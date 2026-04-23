# cadc-access-control-admin

This module provides a command line tool for managing users. It uses the persistence layer code (rather than the web
service) for the various functions.

## configuration

See the [cadc-java](https://github.com/opencadc/docker-base/tree/master/cadc-java)
image docs for general config requirements.

Runtime configuration must be made available via the `/config` directory.

### ac-ldap-config.properties
This file configures connection to the back end LDAP server.
```
################## Read-only connection pool ##################
# space separated list of hosts
readOnly.servers = {ldap server}
readOnly.port = 389
readOnly.poolInitSize = 1
readOnly.poolMaxSize = 1
# <roundRobin || fewestConnections>
readOnly.poolPolicy = roundRobin
readOnly.maxWait = 30000
readOnly.createIfNeeded = false

################## Read-write connection pool #################
# space separated list of hosts
readWrite.servers = {ldap server}
readWrite.poolInitSize = 1
readWrite.poolMaxSize = 1
# <roundRobin || fewestConnections>
readWrite.poolPolicy = roundRobin
readWrite.maxWait = 30000
readWrite.createIfNeeded = false

############## Unbound-Read-only connection pool ##############
# space separated list of hosts
unboundReadOnly.servers = {ldap server}
unboundReadOnly.poolInitSize = 1
unboundReadOnly.poolMaxSize = 1
# <roundRobin || fewestConnections>
unboundReadOnly.poolPolicy = roundRobin
unboundReadOnly.maxWait = 30000
unboundReadOnly.createIfNeeded = false

########## server configuration -- applies to all servers #####
dbrcHost = devLdap
port = 636
proxyUser = uid=webproxy,ou=SpecialUsers,dc=canfar,dc=net
proxyPassword = {webproxy ldap password}
usersDN = ou=Users,ou=ds,dc=canfar,dc=net
userRequestsDN = ou=userRequests,ou=ds,dc=canfar,dc=net
groupsDN = ou=Groups,ou=ds,dc=canfar,dc=net
adminGroupsDN = ou=adminGroups,ou=ds,dc=canfar,dc=net
```
All three pools need to be configured and have a pool size of at least 1 (even though
`cadc-access-control-admin` does not use the _unboundReadOnly_ pool.

### client certificate
The `cadc-access-control-admin` requires a client certificate that must be specified on the
command line. Since configuration files are generally mounted into `/config` one could include
the certificate file there and use `--cert=/config/cadcproxy.pem`, for example.

The `example-wrapper-script` choses a different approach and mounts a client certificate
separately (from the `/config`) and appends the correct `--cert` command line argument.

### ac-admin-email.properties
This file is used by the cadc-access-control-admin tool for sending
email messages for account approval to newly approved users, and
mass emails to all users.

If this file is not present the admin tool will continue to function
but will be unable to send email messages.
```
# required fields for all messages:
#
#  SMTP host for bulk email
#    smtp.host=<host>                   The SMTP host name.
#    smtp.port=<port>                   The SMTP host port number.
#
#  SMTP host for account approval
#    smtp.auth.host=<host>              The SMTP auth host name.
#    smtp.auth.port=<port>              The SMTP auth host port number.
#    smtp.auth.account=<account>        The SMTP host account name.
#    smtp.auth.password=<password>      The SMTP host password.
#
# required fields for account approval messages:
#    mail.from=<email addr>             The from address.
#    mail.reply-to=<reply to addr>      The reply to address.
#    mail.subject                       The subject of the email.
#    mail.body=body                     The email body. The %s character in the
#                                       body will be replaced with the user's
#                                       userid (if present).
#
# optional field for account approval messages:
#
#    mail.bcc=<bcc addr>               A single bcc email address

smtp.host=example.host
smtp.port=25
smtp.auth.host=example-auth.host
smtp.auth.port=587
smtp.auth.account=account@example.host
smtp.auth.password=changeme

mail.from=id@example.com
mail.reply-to=id@example.com
mail.subject=New Account
mail.body=<p>Dear User</p> \
          <p>Your new account is %s </p>\
          <p>Thank you</p>

mail.bcc=id@example.com
```

## building it
```
gradle clean build
docker build -t cadc-access-control-admin -f Dockerfile .
```

## checking it
```
docker run -it cadc-access-control-admin:latest /bin/bash
```

## running it to display command-line help
```
docker run --rm --user opencadc:opencadc -v /path/to/external/config:/config:ro \
    cadc-access-control-admin:latest /cadc-access-control-admin/bin/cadc-access-control-admin --help
```
Important: in the above usage, the args **replace** the CMD from the Dockerfile so you have to include it here.
This could be improved, but the ENTRYPOINT is provided by the base image and does some setup before executing
the CMD.... TBD.
