package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

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
		return fmt.Errorf("subject is empty")
	}

	if server == "" {
		return fmt.Errorf("API server is not set")
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

func main() {
	port := flag.Int("bind-port", 0, "port to bind to.")
	addr := flag.String("bind-addr", "", "address to bind to.")
	server := flag.String("api-server", os.Getenv("API_SERVER"), "API server address.")
	subject := flag.String("subject", "", "subject to issue in cli mode")

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
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", "attachment; filename=kubeconfig.yaml")

			user := r.Header.Get("X-Auth-User")

			if err := issueCertificate(csrAPI, w, user, *server, ca); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

			log.Println("Issued certificate for", user)
		})

		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *addr, *port), nil))
	}
}
