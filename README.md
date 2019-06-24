cert-auth is a service designed to make it easy to issue signed client certificates for Kubernetes.

It is recommended to use cert-auth with [oauth2-proxy](https://github.com/pusher/oauth2_proxy) for authentication and to use mutual TLS to authenticate oauth2-proxy and cert-auth.

As the Kubernetes API does not allow specifying the expiration of certificates, all certificates are valid for one year - use RBAC to revoke a user's access.

# Usage

There are two ways to use cert-auth.

## CLI

It can be used as a CLI:

```
cert-auth -subject username -api-server https://k8s-api.example.com/ > kubeconfig.yaml
KUBECONFIG=kubeconfig.yaml kubectl get nodes
```

## API

It can also be used as an API:

```
kubectl create configmap cert-auth --from-literal=endpoint=https://k8s-api.example.com/
kubectl apply -f ./deploy.yaml
```

Create an Ingress record for the service and then you can fetch a kubeconfig from it:

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: cert-auth
  annotations:
    certmanager.k8s.io/cluster-issuer: letsencrypt
spec:
  rules:
  - host: kube.example.com
    http:
      paths:
      - path: /
        backend:
          serviceName: cert-auth
          servicePort: cert-auth
  tls:
  - hosts:
    - kube.example.com
    secretName: kube-cert

```

Fetch with curl:

```
curl https://kube.example.com/ -H 'X-Forwarded-User: username' > kubeconfig.yaml
```

See [this documentation](https://github.com/kubernetes/ingress-nginx/tree/master/docs/examples/auth/oauth-external-auth) for details on setup with oauth2-proxy.

## RBAC

The certificates that are issued are issued for the subject or `X-Auth-User` provided, so the permissions can be restricted using Kubernetes RBAC.

For example, to make `username` a cluster-admin:

```
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: username
```

Without an RBAC policy set, a user has no permissions by default.

# Related Projects

* [kubehook](https://github.com/planetlabs/kubehook) is a similar design and inspiration for this project, but uses Kubernetes webhook authentication, which requires setting flags on the Kubernetes API server. In some environments (Digital Ocean managed Kubernetes), this is not possible.
