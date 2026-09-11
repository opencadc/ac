# ac

Access Control and Group Management service Helm chart.

This chart deploys the OpenCADC ac Tomcat service. LDAP and OIDC settings are
declared as Helm values. Non-secret configuration from `config/` is rendered
into a ConfigMap. An init container copies that configuration, reads password
values from existing Kubernetes Secrets, and creates the final `/config`
directory without putting credentials in the ConfigMap.

## Required Secret

Create a Secret containing the LDAP proxy password:

```shell
kubectl create secret generic ac-ldap-config \
  --from-literal=proxyPassword='<password>'
```

Set the LDAP values and Secret reference. The ac 1.5.0 ldap service receives
`proxyUser` and `proxyPassword` in the generated
`ac-ldap-config.properties`; it does not use `dbrcHost` or a `.dbrc` file.

```yaml
application:
  ldap:
    readOnly:
      servers: ldap-ro.example.org
    readWrite:
      servers: ldap-rw.example.org
    unboundReadOnly:
      servers: ldap-ro.example.org
    port: 636
    proxyUser: uid=webproxy,ou=SpecialUsers,dc=example,dc=org
    proxyPassword:
      existingSecret: ac-ldap-config
      key: proxyPassword
    usersDN: ou=Users,ou=ds,dc=example,dc=org
    groupsDN: ou=Groups,ou=ds,dc=example,dc=org
    adminGroupsDN: ou=adminGroups,ou=ds,dc=example,dc=org
    userRequestsDN: ou=userRequests,ou=ds,dc=example,dc=org
```

Pool tuning, per-pool `port`, and per-pool `secure` values are optional. An
optional property that is not present in the values is omitted from the
generated properties file. LDAP servers, `proxyUser`, and the directory DNs
are environment-specific and must be supplied by the deployer.

## Optional OIDC configuration

Create one Secret per OIDC client:

```shell
kubectl create secret generic ac-oidc-client-1 \
  --from-literal=secret='<client-secret>'
```

Then list the client in the values. `id` is the actual OIDC client ID, not a
list position. `description`, `claims`, and `signDocuments` are required by the
ac parser; only `accessGroup` is optional:

```yaml
application:
  oidc:
    clients:
      - id: client-1
        secret:
          existingSecret: ac-oidc-client-1
          key: secret
        description: Example client
        accessGroup: ivo://example.org/gms?example-group
        claims:
          - name
          - email
          - memberOf
        signDocuments: true
```

When `application.oidc.clients` is not empty, create a Secret containing the
existing signing key pair and reference it in the values. The chart requires
this Secret whenever at least one client is configured:

```shell
kubectl create secret generic ac-oidc-signing-keys \
  --from-file=oidc-rsa256-pub.key=./oidc-rsa256-pub.key \
  --from-file=oidc-rsa256-priv.key=./oidc-rsa256-priv.key
```

```yaml
application:
  oidc:
    signingKeys:
      existingSecret: ac-oidc-signing-keys
```

Passwords, client secrets, and private keys must not be stored in Git.

## Test the Chart

```shell
helm lint ac/helm

helm template ac ac/helm \
  --namespace ac
```

Dry-run against a cluster:

```shell
helm upgrade --install ac ac/helm \
  --namespace ac \
  --create-namespace \
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
