# base cadc-ldap-dev image
 
published image: `images.opencadc.org/dev-only/cadc-ldap-dev:{version}`

## expected deployment
This ldap instance is designed for development support of the access control service 
and has a very low level of security. It is based on the `389ds/dirsrv` image (https://hub.docker.com/r/389ds/dirsrv)
and has the `memberOf` plugin turned on.

## accounts 
On startup, the only account available is "Directory Manager":
```
Directory Manager  : pw-dm
```

## Structure
No structure or content is provided. The service is expected to create all the required organizational elements.

## building it 
```
docker build -t cadc-ldap-dev -f Dockerfile .
```

## checking it
```
docker run --rm -it cadc-ldap-dev:latest /bin/bash
```

## running it
```
docker run -d --rm --publish 389:3389 --name cadc-ldap-dev cadc-ldap-dev:latest
```

This runs a default container accessible through port 3389. To make data persistent, mount the `/data` directory
of the container to the persistent location. To test the access, run command:

```
ldapsearch -h ldaps://0.0.0.0 -p 3389 -D "cn=Directory Manager" -w 'pw-dm' -b "" ""
```:


