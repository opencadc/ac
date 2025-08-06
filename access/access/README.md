# Access Control Module

This module provides authentication and authorization services for CADC (Canadian Astronomy Data Centre) applications.

## Overview

The access module is responsible for:
- User authentication via SSO (Single Sign-On)
- Cookie-based session management
- Password reset functionality
- User information services

## Build Requirements

- Java 11 or higher
- Gradle 6.8.3 or higher

## Runtime Configuration

### Required Properties Files

The following properties files need to be configured for runtime:

#### 1. AccessControl.properties
Located at: `src/main/resources/AccessControl.properties`

```properties
# SSO server configuration
SSO_SERVERS = jenkinsd.cadc.dao.nrc.ca www.canfar.net www.cadc-ccda.hia-iha.nrc-cnrc.gc.ca

# Cookie domain configuration
COOKIE_DOMAINS = www.cadc-ccda.hia-iha.nrc-cnrc.gc.ca www.canfar.net

# SSO token lifetime (default: 47 hours)
SSO_TOKEN_LIFETIME_SECONDS = 169344
```

#### 2. RSA Key Files
The module requires RSA key pairs for signing SSO cookies:

- **Private Key**: `RsaSignaturePriv.key` (PEM format)
- **Public Key**: `RsaSignaturePub.key` (PEM format)

**Default locations**:
- Production: Classpath root or system property `cadc.rsa.privkey.path`
- Test: `src/test/resources/RsaSignaturePriv.key`

### Key Generation

For testing environments, keys are automatically generated using:
```bash
java -cp "src/test/java:build/classes/java/main" ca.nrc.cadc.accesscontrol.GenerateTestKey
```

For production, generate keys using:
```bash
# Generate 2048-bit RSA key pair
openssl genrsa -out RsaSignaturePriv.key 2048
openssl rsa -in RsaSignaturePriv.key -pubout -out RsaSignaturePub.key
```

## Deployment

### WAR File
Build the WAR file:
```bash
./gradlew :access:build
```

The WAR file will be generated at: `access/build/libs/access.war`

### Docker Deployment
Use the provided Dockerfile for containerized deployment:
```bash
docker build -t cadc-access .
docker run -p 8080:8080 cadc-access
```

## Testing

### Unit Tests
Run unit tests:
```bash
./gradlew :access:test
```

**Note**: Tests automatically generate RSA keys in the test environment. No manual setup required.

### Test Coverage
- 17 test classes covering authentication, SSO, and user management
- All tests are designed to run locally without external dependencies

## Technical Debt

### Legacy Issues
1. **Javadoc Warnings**: Some classes have incomplete Javadoc documentation
2. **Deprecated API Usage**: Some code uses deprecated Java APIs
3. **Hard-coded Paths**: Some legacy code contains hard-coded file paths

### Known Issues
- Javadoc generation may fail due to incomplete documentation
- Some test resources are legacy and may need updates for production

## CI/CD

The module is integrated into the GitHub CI pipeline:
- Automatic build and test on pull requests
- Dynamic RSA key generation for test environment
- Javadoc generation (with warnings ignored)
- Test results and documentation uploaded as artifacts

## Dependencies

### Core Dependencies
- `javax.servlet:javax.servlet-api:4.0.1`
- `ca.nrc.cadc:cadc-util` (for RSA signature utilities)
- `ca.nrc.cadc:cadc-auth` (for authentication)

### Test Dependencies
- `junit:junit:4.13.2`
- `org.easymock:easymock:4.3`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all tests pass
5. Submit a pull request

## License

This module is part of the CADC project and follows the same licensing terms. 