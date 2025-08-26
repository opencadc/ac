# AAI Helper Service for web site (access)

The ***access*** service is a helper service for UI authentication activities. It supports relaying authentication to the **ac** service, setting SSO cookies in the browser, and handling various AAI (Authentication, Authorization, and Identity) related activities such as registration page requests.

This service includes many chard-coded settings and is only usable for CADC/CANFAR deployment. See TODO below for details.

## deployment
The `cavern` war file can be renamed at deployment time in order to support an alternate service name, including 
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

### access.properties
Main configuration file containing runtime properties for SSO server list, cookie domain scope, and token lifetime.
Noter: this file used to be named `AccessControl.properties`.

### RsaSignaturePub.key
This service requires the same RSA public key that other services using the `ACIdentityManager` use to 
validate cookies.

## TODO
### technical debt
- many CADC-specific hard-coded values and behaviours
- missing VOSI-capabilities
- missing API docs
- missing `intTest` code for local testing
- forked code from `cadc-web-util`: only two made sense to _move_, but dependencies

### improve code
- re-write to use `cadc-rest` instead of bare servlets, use IdentityManager instead of custom code

### features
- one endpoint could be a general purpose cookie-issuer that sits in front of the `ac` service; 
other services could advertise this via `www-authenticate` header and `ivoa_cookie` challenge

## building it
```
gradle clean build
docker build -t access -f Dockerfile .
```

## running it
```
docker run --rm --user tomcat:tomcat --volume=/path/to/external/config:/config:ro --name access access:latest
```
