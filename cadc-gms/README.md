# cadc-gms

## Description
Group Membership Service client interface.

## Usage
The Group Membership Client Interface provides a static method that will instantiate an implementation of the GMSInterface based on the availability of such a class in the classpath.  If no such implementation is found, a default, no-operation implementation is constructed.  This allows libraries to support group authorization checks but does not require implementors to support GMS. 

## Build and Test Dependencies

### opencadc dependencies:
- opencadc/core/cadcUtil

### external build dependencies
- compile 'log4j:log4j:'

### external test dependencies
- junit.jar