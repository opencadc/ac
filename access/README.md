# Access Control Module
The ***access*** service is a helper service for UI authentication activities. It supports relaying authentication to the **ac** service, setting SSO cookies in the browser, and handling various AAI (Authentication, Authorization, and Identity) related activities such as registration page requests.

## Configuration
### Access.properties
Main configuration file containing runtime properties for SSO server list, cookie domain scope, and token lifetime.

### RSA Public Key
> **Runtime:** RSA public key configuration for validating SSO cookies and tokens is handled by `ACIdentityManager` (this service does not use a private key).  
> **Tests:** Unit tests generate a temporary RSA public key at runtime and set a Java system property so the verifier can locate it. No keys are committed to the repository.

# Running
```bash
gradle clean build
docker build -t access .
docker run -it access
```
# Deployment
A [Dockerfile](Dockerfile) is available to build a container image.