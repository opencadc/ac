# cadc-access-control-identity

This library provides an implementation of `ca.nrc.cadc.auth.IdentityManager` for use with
a user/group service built with the `cadc-access-control-server` library. The provided
IdentityManager is configured in services as
```
ca.nrc.cadc.auth.IdentityManager=ca.nrc.cadc.ac.ACIdentityManager
```

If a service depends on having a complete PosixPrincipal (including the optional
defaultGroup and username), it should set this additional system property:
```
ca.nrc.cadc.ac.ACIdentityManager.requireCompletePosixPrincipal=true
```
WARNING: This will cause a remote call to obtain the additional info not included
in cookies or bearer tokens, so only use if required.
