# sssd container

This sssd container can be used for using an ldap host as authentication source for posix

For other systems to use the functionality of this container, they must share the directory:
```
/var/lib/sss/pipes
```

## building

```
docker build -t cadc-sssd:latest -f Dockerfile .
```

## checking it
```
docker run -it --rm --volume=/path/to/sssd.conf:/etc/sssd/sssd.conf:ro cadc-sssd:latest /bin/bash
```

## running it
```
docker run -d --rm --volume=/path/to/sssd.conf:/etc/sssd/sssd.conf:ro cadc-sssd:latest

## configuration

To apply your configuration settings mount your version of sssd.conf to /etc/sssd/sssd.conf as in the examples above.
