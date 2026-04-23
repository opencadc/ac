# Access Control (AC) Service

The ***ac*** service provides the authentication and authorization infrastructure for CADC/CANFAR services.
It consistes of two main components:
- a user service that provides authentication and identity management
- a Group Management Service (GMS) that provides group membership management

## deployment
The `ac` war file can be renamed at deployment time in order to support an alternate service name, including 
introducing additional path elements. 
See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a> (war-rename.conf).

## configuration
The following runtime configuration must be made available via the `/config` directory.

### catalina.properties
This file contains java system properties to configure the tomcat server and some of the java libraries 
used in the service.

See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a> for 
system properties related to the deployment environment.

See <a href="https://github.com/opencadc/core/tree/master/cadc-util">cadc-util</a> for common system properties.

### cadc-registry.properties

See <a href="https://github.com/opencadc/reg/tree/master/cadc-registry">cadc-registry</a>.
Note: this configuration file will soon be deprecated in favour of using the `ac.properties` file.

### cadc-log.properties (optional)
See <a href="https://github.com/opencadc/core/tree/master/cadc-log">cadc-log</a> for common
dynamic logging control.

### ac.properties
An ac.properties file in /config is required to run this service.  The following keys are required:
```
# service identity
org.opencadc.ac.resourceID=ivo://{authority}/{name}
```
The following keys are optional:
```
org.opencadc.ac.readUser = cn={user},ou={org},o={org},c={country}
```
X.509 DNs of privileged users with read access to any group.

## TODO
### technical debt
This service currently uses other configuration files that will be deprecated in future releases:
- ac-oidc-clients.properties
- ac-ldap-config.properties
- ac-domains.properties
- ac-group-names.properties

## building it
```
gradle clean build
docker build -t ac -f Dockerfile .
```

## running it
```
docker run --rm --user tomcat:tomcat --volume=/path/to/external/config:/config:ro --name ac ac:latest
```
