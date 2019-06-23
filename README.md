cert-auth is a service designed to make it easy to issue signed client certificates for Kubernetes.

It is recommended to use cert-auth with [oauth2-proxy](https://github.com/pusher/oauth2_proxy) for authentication and to use mutual TLS to authenticate oauth2-proxy and cert-auth.

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
cert-auth -bind-port 8080 -api-server https://k8s-api.example.com/
```

In this mode, a Kubernetes configuration can be fetched from the server:

```
curl http://127.0.0.1:8080/ -H 'X-Auth-User: username' > kubeconfig.yaml
```

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
