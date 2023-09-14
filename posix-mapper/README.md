# POSIX UID and GID Name Mapper (Name TBD)

This is a mapping service that supports GET, and POST operations.  The GET operations will obtain a mapping
for a given UID or GID, and a POST will add a new entry.

### deployment
The `posix` war file can be renamed at deployment time in order to support an alternate service name, including introducing 
additional path elements (see war-rename.conf).

### configuration
The following runtime configuration must be made available via the `/config` directory.

### catalina.properties
This file contains java system properties to configure the tomcat server and some of the java libraries used in the service.

See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a>
for system properties related to the deployment environment.

See <a href="https://github.com/opencadc/core/tree/master/cadc-util">cadc-util</a>
for common system properties.

`posix` includes multiple IdentityManager implementations to support authenticated access:
- See <a href="https://github.com/opencadc/ac/tree/master/cadc-access-control-identity">cadc-access-control-identity</a> for CADC access-control system support.
- See <a href="https://github.com/opencadc/ac/tree/master/cadc-gms">cadc-gms</a> for OIDC token support.

`posix` requires a connection pool to the local user mapping database:
```
# database connection pools
org.opencadc.science-platform.posix.mapping.maxActive={max connections for mapping pool}
org.opencadc.science-platform.posix.mapping.username={username for mapping pool}
org.opencadc.science-platform.posix.mapping.password={password for mapping pool}
org.opencadc.science-platform.posix.mapping.url=jdbc:postgresql://{server}/{database}
```
The `mapping` account owns and manages (create, alter, drop) database objects and manages
all the content (insert, update, delete). The database is specified in the JDBC URL and the schema name is specified 
in the posix.properties (below). Failure to connect or initialize the database will show up in logs and in the 
VOSI-availability output.

### cadc-registry.properties
See <a href="https://github.com/opencadc/reg/tree/master/cadc-registry">cadc-registry</a>.

### posix.properties
A posix.properties file in /config is required to run this service.  The following keys are required:
```
# service identity
org.opencadc.science-platform.posix=ivo://{authority}/{name}
```
The posix _resourceID_ is the resourceID of _this_ posix service.

### posix-availability.properties (optional)
The posix-availability.properties file specifies which users have the authority to change the availability state of the posix service. Each entry consists of a key=value pair. The key is always "users". The value is the x500 canonical user name.

Example:
```
users = {user identity}
```
`users` specifies the user(s) who are authorized to make calls to the service. The value is a list of user identities (X500 distingushed name), one line per user. Optional: if the `posix-availability.properties` is not found or does not list any `users`, the service will function in the default mode (ReadWrite) and the state will not be changeable.

### cadcproxy.pem (optional)
This client certificate is used to make authenticated server-to-server calls for system-level A&A purposes.

## building it
```
gradle clean build
docker build -t posix -f Dockerfile .
```

## checking it
```
docker run --rm -it posix:latest /bin/bash
```

## running it
```
docker run --rm --user tomcat:tomcat --volume=/path/to/external/config:/config:ro --name posix posix:latest
```

## using it
Using `cURL` is possible with `posix` to POST a user for testing.

**Note:** The `username` field is required.
```bash
$ curl --verbose \
  --data "username=testuser" \
  --header "authorization: bearer <mytoken>" 
  https://myhost.com/posix/uid

1001
```
