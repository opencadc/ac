# cadcAccessControl-Identity

## Description
When the the cadcAccessControl-Identity jar file is in the classpath of any of the web services offered in opencadc, it will, upon entry into the web service, make a call to the cadcAccessControl-Server service to discover all the identities of the user making the initial web service call.  We call this subject augmentation.  These identities are available for use by downstream code for puposes such as authentication decisions and logging.

## Usage
Without the cadcAccessControl-Identity jar file, web services only know about the identity which the user used to connect to the web service (a cookie value for example).  With the jar file, web service will know about the other identities for the user, such as username, X.509 distinguished name, and potentially various external identity provider information.  Additionally, this information allows services to call other opencadc services *as the user* by making use of the credential delegation service.

## Build and Test Dependencies

### opencadc dependencies:
- opencadc/core/cadcUtil
- opencadc/reg/cadcRegistry
- opencadc/ac/cadcAccessControl

### external build dependencies
- json.jar (json.org-20110818.jar)
- jdom2.jar (jdom-2.0.5.jar)
- log4j.jar (log4j-1.2.17.jar)

### external test dependencies
- xerces.jar (xerces-2_9_1)
- asm.jar (hibernate-3.2.3)
- cglib.jar (hibernate-3.2.3)
- easymock.jar (easymock-3.0.jar)
- junit.jar (junit-4.6.jar)
- objenesis.jar (objenesis-1.2.jar)
- jsonassert.jar (jsonassert-1.2.3.jar)
