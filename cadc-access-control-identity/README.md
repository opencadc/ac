# cadc-access-control-identity

This library provides an implementation of `ca.nrc.cadc.auth.IdentityManager` for use with
a user/group service built with the `cadc-access-control-server` library. The provided
IdentityManager is configured in services as
```
ca.nrc.cadc.auth.IdentityManager=ca.nrc.cadc.ac.ACIdentityManager
```
