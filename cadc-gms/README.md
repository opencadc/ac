# cadc-gms

## IVOA Group Membership Service

This library provides a client class that supports calls to an IVOA GMS service.

## OIDC Token Support

This library provides an implementation of `ca.nrc.cadc.auth.IdentityManager` for use with
a user/group service that implements OpenID Connect (OIDC). The provided IdentityManager is
configured in services as

```
ca.nrc.cadc.auth.IdentityManager=org.opencadc.auth.StandardIdentityManager
```

The goal is for this IdentityManager implementation to support integration with
non-IVOA standard authentication services. The current implementation is a simple
prototype that is known to work with an Indigo IAM OIDC issuer.

See <a href="https://github.com/opencadc/reg/tree/master/cadc-registry">cadc-registry</a>
for information about configuring an OpenID issuer. In addition, if a service also configures
a "trusted" GMS service in the cadc-registry config file, for example:

```
ivo://ivoa.net/std/GMS#search-1.0 = {my GSM service}
```

then the StandardIdentityManager will ensure that valid access tokens are tagged so they will
be used in calls to that GMS service.
