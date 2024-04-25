# POSIX UID and GID Name Mapper (Name TBD)

This is a mapping service that supports GET, and POST operations.  The GET operations will obtain a mapping
for a given UID or GID, and a POST will add a new entry.

### deployment
The `posix-mapper.war` WAR file can be renamed at deployment time in order to support an alternate service name, including introducing 
additional path elements (see [war-rename.conf](https://github.com/opencadc/docker-base/tree/master/cadc-tomcat#war-renameconf)).

### configuration
The following runtime configuration must be made available via the `/config` directory.

### Key access (Optional, but required for certain clients)
The POSIX Mapper requires authentication for access, but not all clients will have an authenticated user in hand.  To
facilitate this, the `/config` folder can contain a `keys` folder with a file called `/.api-keys`:

`/config/keys/.api-keys`:
```
MYSECRETKEYVALUE
```

Where Kubernetes is concerned, it's advisable to create a Secret with this value and mount it to the POSIX Mapper, 
as well as any clients that need access to the POSIX Mapper service without an authenticated Subject.

Access for clients will involve setting the `X-Client-API-Key` header to the value in the file:

```shell
$ curl --header "X-Client-API-key: MYSECRETKEYVALUE" https://example.org/posix-mapper/uid
```

### catalina.properties
This file contains java system properties to configure the tomcat server and some of the java libraries used in the service.

See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a>
for system properties related to the deployment environment.

See <a href="https://github.com/opencadc/core/tree/master/cadc-util">cadc-util</a>
for common system properties.

`posix-mapper` includes multiple IdentityManager implementations to support authenticated access:
- See <a href="https://github.com/opencadc/ac/tree/master/cadc-access-control-identity">cadc-access-control-identity</a> for CADC access-control system support.
- See <a href="https://github.com/opencadc/ac/tree/master/cadc-gms">cadc-gms</a> for OIDC token support.

`posix-mapper` requires a connection pool to the local user mapping database:
```
# database connection pools
org.opencadc.posix.mapper.maxActive={max connections for mapping pool}
org.opencadc.posix.mapper.username={username for mapping pool}
org.opencadc.posix.mapper.password={password for mapping pool}
org.opencadc.posix.mapper.url=jdbc:postgresql://{server}/{database}
```
The `mapping` account owns and manages (create, alter, drop) database objects and manages
all the content (insert, update, delete). The database is specified in the JDBC URL and the schema name is specified 
in the [posix-mapper.properties](#posix-mapperproperties) (below). Failure to connect or initialize the database will show up in logs and in the 
VOSI-availability output.

### cadc-registry.properties
See <a href="https://github.com/opencadc/reg/tree/master/cadc-registry">cadc-registry</a>.

### posix-mapper.properties
A posix.properties file in /config is required to run this service.  The following keys are required:
```
# service identity
org.opencadc.posix.mapper.resourceID=ivo://{authority}/{name}

# Database schema
org.opencadc.posix.mapper.schema=mapping

# home dir root
org.opencadc.posix.mapper.homeDirRoot=/storage/home

# ID ranges to allow some customization where administration is necessary
org.opencadc.posix.mapper.uid.start=10000
org.opencadc.posix.mapper.gid.start=90000

# At least one group that are allowed to query the API.  Use multiple org.opencadc.posix.mapper.group entries for
# multiple groups.
org.opencadc.posix.mapper.group=ivo://example.org/gms?mygroup
```
The _resourceID_ is the resourceID of _this_ posix-mapper service.

The _schema_ is the database schema used for interacting with tables in the database.

The _homeDirRoot_ is the path to the root of home folders.  This is used to create entires in the `/etc/passwd` file.

_uid.start_ start of UID range
_gid.start_ start of GID range

## building it
```
gradle clean build
docker build -t posix-mapper -f Dockerfile .
```

## checking it
```
docker run --rm -it posix-mapper:latest /bin/bash
```

## running it
```
docker run --rm --user tomcat:tomcat --volume=/path/to/external/config:/config:ro --name posix-mapper posix-mapper:latest
```

## testing it
Integration tests can be run using Gradle, with a file containing a Token value.  Create (or modify) the `src/intTest/resources/posix-mapper-test.token`
file with the value of a Bearer Token, and it will be used by tests.  Set the Registry location containing the
POSIX Mapper location of your API.

```shell
gradle --info -Dca.nrc.cadc.reg.client.RegistryClient.host=example.com clean build intTest
```

## using it
Using `cURL` is possible with `posix-mapper` to GET a user for testing, which will create the user if it's not found.

**Note:** The `user` field is required to create a new User entry.
```bash
$ curl --verbose \
  --header "authorization: bearer <mytoken>" 
  "https://myhost.com/posix/uid?user=testuser"

1001
```
