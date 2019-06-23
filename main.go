package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dyson/certman"
	"github.com/google/uuid"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	"k8s.io/client-go/rest"
	api "k8s.io/client-go/tools/clientcmd/api/v1"
	csrutils "k8s.io/client-go/util/certificate/csr"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func generateCSR(names []string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to genarate private keys, error: %s", err)
	}

	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: names[0],
		},
		DNSNames:           names,
		SignatureAlgorithm: x509.SHA512WithRSA,
	}, key)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		}), pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
		}), nil
}

func generateKubernetesCSR(name string, csr []byte) (*certificatesv1beta1.CertificateSigningRequest, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	return &certificatesv1beta1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", name, uuid.String()),
		},
		Spec: certificatesv1beta1.CertificateSigningRequestSpec{
			Request: csr,
			Usages: []certificatesv1beta1.KeyUsage{
				certificatesv1beta1.UsageDigitalSignature,
				certificatesv1beta1.UsageKeyEncipherment,
				certificatesv1beta1.UsageClientAuth,
			},
		},
	}, nil
}

func approveKubernetesCSR(csr *certificatesv1beta1.CertificateSigningRequest) {
	csr.Status = certificatesv1beta1.CertificateSigningRequestStatus{
		Conditions: []certificatesv1beta1.CertificateSigningRequestCondition{
			certificatesv1beta1.CertificateSigningRequestCondition{
				Type:           certificatesv1beta1.CertificateApproved,
				Reason:         "CertAuthApprove",
				Message:        "cert-auth automated provisioning",
				LastUpdateTime: metav1.Now(),
			},
		},
	}
}

func getCertificate(csrAPI certificates.CertificateSigningRequestInterface, name string, csr []byte) ([]byte, error) {
	kubernetesCSR, err := generateKubernetesCSR(name, csr)
	if err != nil {
		return nil, err
	}

	createdCSR, err := csrAPI.Create(kubernetesCSR)
	if err != nil {
		return nil, err
	}

	approveKubernetesCSR(createdCSR)

	result, err := csrAPI.UpdateApproval(createdCSR)
	if err != nil {
		return nil, err
	}

	return csrutils.WaitForCertificate(csrAPI, result, time.Second*10)
}

func generateKubernetesConfig(w io.Writer, server string, cert, key, ca []byte) {
	newConfig := &api.Config{
		CurrentContext: "cluster",
		Clusters: []api.NamedCluster{
			api.NamedCluster{
				Name: "cluster",
				Cluster: api.Cluster{
					Server:                   server,
					CertificateAuthorityData: ca,
				},
			},
		},
		Contexts: []api.NamedContext{
			api.NamedContext{
				Name: "cluster",
				Context: api.Context{
					Cluster:  "cluster",
					AuthInfo: "user",
				},
			},
		},
		AuthInfos: []api.NamedAuthInfo{
			api.NamedAuthInfo{
				Name: "user",
				AuthInfo: api.AuthInfo{
					ClientCertificateData: cert,
					ClientKeyData:         key,
				},
			},
		},
	}

	encoder := json.NewYAMLSerializer(json.DefaultMetaFactory, nil, nil)
	if err := encoder.Encode(newConfig, w); err != nil {
		log.Fatal(err)
	}
}

func issueCertificate(csrAPI certificates.CertificateSigningRequestInterface, w io.Writer, subject, server string, ca []byte) error {
	if subject == "" {
		return errors.New("subject is empty")
	}

	if server == "" {
		return errors.New("API server is not set")
	}

	key, csr, err := generateCSR([]string{subject})
	if err != nil {
		return err
	}

	cert, err := getCertificate(csrAPI, subject, csr)
	if err != nil {
		return err
	}

	generateKubernetesConfig(w, server, cert, key, ca)
	return nil
}

func listenAndServe(s *http.Server, tlsCert, tlsKey string) error {
	if tlsCert != "" && tlsKey != "" {
		cm, err := certman.New(tlsCert, tlsKey)
		if err != nil {
			return err
		}

		if err := cm.Watch(); err != nil {
			return err
		}

		s.TLSConfig.GetCertificate = cm.GetCertificate

		return s.ListenAndServeTLS("", "")
	}

	return s.ListenAndServe()
}

func makeTLSConfig(clientCACert string, clientCASubject string) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	if clientCASubject != "" {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return errors.New("client did not present any TLS certificates")
			}

			return verifiedChains[0][0].VerifyHostname(clientCASubject)
		}
	}

	if clientCACert != "" {
		clientCA, err := ioutil.ReadFile(clientCACert)
		if err != nil {
			return nil, fmt.Errorf("could not load client CA: %s", err)
		}

		clientCertPool := x509.NewCertPool()
		clientCertPool.AppendCertsFromPEM(clientCA)

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = clientCertPool

		tlsConfig.BuildNameToCertificate()
	}

	return tlsConfig, nil
}

func main() {
	port := flag.Int("bind-port", 0, "port to bind to.")
	addr := flag.String("bind-addr", "", "address to bind to.")
	server := flag.String("api-server", os.Getenv("API_SERVER"), "API server address.")
	subject := flag.String("subject", "", "subject to issue in cli mode")
	clientCACert := flag.String("client-ca-cert", "", "if set, enables mutual TLS and specifies the path to CA file to use when validating client connections")
	clientCASubject := flag.String("client-ca-subject", "", "if set, requires that the client CA matches the provided subject (requires -client-ca-cert)")
	tlsCert := flag.String("tls-cert", "", "if set, enables TLS and specifies the path to TLS certificate to use for HTTPS server (requires -tls-key)")
	tlsKey := flag.String("tls-key", "", "pth to TLS key to use for HTTPS server (requires -tls-cert)")

	flag.Parse()

	cfg := config.GetConfigOrDie()

	if err := rest.LoadTLSFiles(cfg); err != nil {
		log.Fatal("error loading TLS certificates", err)
	}

	ca := cfg.TLSClientConfig.CAData

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal("error getting kubernetes client", err)
	}

	csrAPI := clientset.Certificates().CertificateSigningRequests()

	if *port == 0 {
		if err := issueCertificate(csrAPI, os.Stdout, *subject, *server, ca); err != nil {
			log.Fatal(err)
		}
	} else {
		tlsConfig, err := makeTLSConfig(*clientCACert, *clientCASubject)
		if err != nil {
			log.Fatal(err)
		}

		s := &http.Server{
			Addr:      fmt.Sprintf("%s:%d", *addr, *port),
			TLSConfig: tlsConfig,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Disposition", "attachment; filename=kubeconfig.yaml")

				user := r.Header.Get("X-Auth-User")

				if err := issueCertificate(csrAPI, w, user, *server, ca); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}

				log.Println("Issued certificate for", user)
			}),
		}

		log.Fatal(listenAndServe(s, *tlsCert, *tlsKey))
	}
}
