# ac

Access Control and Group Management service Helm chart.

This chart deploys the OpenCADC ac Tomcat service. Non-secret configuration
from `config/` is rendered into a ConfigMap under `/config`. LDAP credentials
and optional OIDC client configuration and signing keys are projected into the
same directory from an existing Kubernetes Secret.

## Required Secret

Copy `examples/ac-ldap-config.properties.example` to a secure location, remove
the `.example` suffix, and replace every `<FILL_...>` placeholder. The ac 1.5.0
ldap service reads `proxyUser` and `proxyPassword` directly from this file; it
does not use `dbrcHost` or a `.dbrc` file.

Create the runtime configuration Secret:

```shell
kubectl create secret generic ac-runtime-config \
  --from-file=ac-ldap-config.properties=./ac-ldap-config.properties
```

If the ac OIDC endpoints are enabled, add the completed OIDC client file and
the existing signing key pair to the same Secret:

```shell
kubectl create secret generic ac-runtime-config \
  --from-file=ac-ldap-config.properties=./ac-ldap-config.properties \
  --from-file=ac-oidc-clients.properties=./ac-oidc-clients.properties \
  --from-file=oidc-rsa256-pub.key=./oidc-rsa256-pub.key \
  --from-file=oidc-rsa256-priv.key=./oidc-rsa256-priv.key
```

Set the Secret name in the values:

```yaml
application:
  runtimeConfig:
    existingSecret: ac-runtime-config
```

Completed files containing passwords, client secrets, or private keys must not
be stored in Git.

## Example Values

Start from `examples/values.example.yaml` and replace the example hostname,
resource identifier, registry URL, and Secret name.

## Test the Chart

```shell
helm lint ac/helm

helm template ac ac/helm \
  --namespace ac \
  --values ac/helm/examples/values.example.yaml
```

Dry-run against a cluster:

```shell
helm upgrade --install ac ac/helm \
  --namespace ac \
  --create-namespace \
  --values ac/helm/examples/values.example.yaml \
  --dry-run
```

Install after replacing the example values and creating the required Secret:

```shell
helm upgrade --install ac ac/helm \
  --namespace ac \
  --create-namespace \
  --values <your-values.yaml>
```

Check the workload:

```shell
kubectl -n ac get pods
kubectl -n ac logs deploy/ac-tomcat
kubectl -n ac port-forward svc/ac-tomcat-svc 18080:8080
curl http://localhost:18080/ac/availability
```
