# cadcAccessControl-Server

## Description

Building cadcAccessControl-Server produces a jar file that can be deployed within a war file in a servlet container (
servlet api 3.0).

cadcAccessControl server is a RESTful interface to authentication, authorization and user and group management. There
are three software layers:

1. The action classes - these coordinate the functions of the REST API
2. The persistence layer - Authorization and connection management
3. The DAO layer - interface to persistent storage

cadcAccessControl-Server has a default persistence layer built-in: LDAP. However, by implementating the Persistence and
DAO interfaces one can easily configure this service to communicate with a different storage mechanism (such as a
relational database).

## REST API

| operation                                    | 	HTTP Method                                                                                | description                                                                                                                                                                                                                                 | faults                                                                                                                                                      |
|----------------------------------------------|---------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Group Management - List all groups           | GET                                                                                         | Lists the names of all the groups in the service                                                                                                                                                                                            |                                                                                                                                                             |
| Group Management - Create group              | PUT                                                                                         | Create the group according to the group XML document in the HTTP PUT.                                                                                                                                                                       | 404 Not Found - If a member is not recognized.<br/>409 Conflict - If a group with the same name already exists.                                             |
| Group Management - Get group                 | GET                                                                                         | Get the group with name {groupID}.                                                                                                                                                                                                          | 404 Not Found - If the group {groupID} could not be found.                                                                                                  | 
| Group Management - Delete group              | DELETE                                                                                      | DELETE the group with name {groupID}.                                                                                                                                                                                                       | 404 Not Found - If the group {groupID} could not be found.                                                                                                  |
| Group Management - Modify group              | POST                                                                                        | Modify the group with name {groupID} according to the group XML document in the HTTP POST.                                                                                                                                                  | 404 Not Found - If the group {groupID} could not be found or if a member is not recognized<br/>409 Conflict - If a group with the same name already exists. |
| Group Management - Add user member           | PUT                                                                                         | Add user {userID} as a member of group {groupID}.                                                                                                                                                                                           | 404 Not Found - If the group {groupID} could not be found or if the member {userID} is not recognized                                                       |
| Group Management - Remove user member        | DELETE                                                                                      | Remove user {userID} as a member of group {groupID}.                                                                                                                                                                                        | 404 Not Found - If the group {groupID} could not be found or if the member {userID} is not recognized                                                       |
| Group Management - Add group member          | PUT                                                                                         | Add group {groupID2} as a member of group {groupID}.	                                                                                                                                                                                       | 404 Not Found - If the group {groupID} or {groupID2} could not be found.                                                                                    |
| Group Management - Remove group member       | DELETE                                                                                      | Remove group {groupID2} as a member of group {groupID}.                                                                                                                                                                                     | 404 Not Found - If the group {groupID} or {groupID2} could not be found.                                                                                    |
| Group Searching - Search by role             | GET                                                                                         | Find the groups in which the user (specified by param {userID}) has the role {role}.                                                                                                                                                        |                                                                                                                                                             |
| Group Searching - Search specific membership | POST	                                                                                       | If a user has the specified role in the specified group the group is returned. Otherwise returns an empty list of groups.	                                                                                                                  |                                                                                                                                                             |
| User management - List all users             | GET                                                                                         | Lists basic information of all the users in the service                                                                                                                                                                                     |                                                                                                                                                             |
| User Management - Request account            | PUT	                                                                                        | Request the user account in the user XML document in the HTTP PUT. This can take an arbitrary amount of time. If the account existed before but was deleted, this operation will reenable the account.                                      | 404 Not Found - If a member is not recognized.<br/>409 Conflict - If a group with the same name already exists.                                             |
| User Management - Get user                   | GET                                                                                         | Get the user with userid {userID} of type {idType}. This operation supports an optional parameter: detail, which can have values of display or identity. The detail parameter adjusts the amount type of user information that is returned. | 404 Not Found - If the user {userID} could not be found.                                                                                                    |
| User Management - Disable account            | DELETE                                                                                      | Disable the account for user with userid {userID} of type {idType}.                                                                                                                                                                         | 404 Not Found - If the group {userID} could not be found.                                                                                                   |
| User Management - Modify user	               | POST                                                                                        | Modify the user with name {userID} and type {idType} according to the user XML document in the HTTP POST.                                                                                                                                  | 404 Not Found - If the user {userID} could not be found.                                                                                                    |
| User Login                                   | POST	                                                                                       | 	Validate the userID and password combination. If the combination is valid this operation will return a cookie that can be used to enter any of these endpoints over HTTP.                                                                  | 403 Permission Denied - If the userID / password validation failed.                                                                                         |
| Password Changes                             | POST	                                                                                       | Change password from {old_password} to {new_password}.                                                                                                                                                                                      | 403 Permission Denied - If the old password is incorrect.                                                                                                   |
| Who Am I - Logged-in user information        | GET	                                                                                        | Returns information about the authenticated user.                                                                                                                                                                                           |                                                                                                                                                             |
| Service availability                         | GET                                                                                         |                                                                                                                                                                                                                                             |                                                                                                                                                             |	

## CONFIGURATION

See the [cadc-java](https://github.com/opencadc/docker-base/tree/master/cadc-java)
image docs for general config requirements.

Runtime configuration must be made available via the `/config` directory.

### ac-ldap-config.properties

This file configures connection to the back-end LDAP server. A template is provided in
[this module](ac-ldap-config.properties).

All three connection pools must be configured. Setting a pool's `poolMaxSize` to `0` affects
service availability:

- `readOnly.poolMaxSize = 0` or `unboundReadOnly.poolMaxSize = 0` puts the service in **offline** mode
- `readWrite.poolMaxSize = 0` puts the service in **read-only** mode

```
################## Read-only connection pool ##################
# space-separated list of hosts
readOnly.servers = {ldap server}
readOnly.port = 389
readOnly.secure = false
readOnly.poolInitSize = 1
readOnly.poolMaxSize = 1
# roundRobin || fewestConnections || fastestConnect
readOnly.poolPolicy = roundRobin
readOnly.maxWait = 30000
readOnly.createIfNeeded = false

################## Read-write connection pool #################
# space-separated list of hosts
readWrite.servers = {ldap server}
readWrite.port = 636
readWrite.secure = true
readWrite.poolInitSize = 1
readWrite.poolMaxSize = 1
# roundRobin || fewestConnections
readWrite.poolPolicy = roundRobin
readWrite.maxWait = 30000
readWrite.createIfNeeded = false

############## Unbound-read-only connection pool ##############
# space-separated list of hosts
unboundReadOnly.servers = {ldap server}
unboundReadOnly.port = 636
unboundReadOnly.secure = true
unboundReadOnly.poolInitSize = 1
unboundReadOnly.poolMaxSize = 1
# roundRobin || fewestConnections
unboundReadOnly.poolPolicy = roundRobin
unboundReadOnly.maxWait = 30000
unboundReadOnly.createIfNeeded = false

########## server configuration -- applies to all pools #######
port = 636
proxyUser = uid=webproxy,ou=SpecialUsers,dc=canfar,dc=net
proxyPassword = {webproxy ldap password}
usersDN = ou=Users,ou=ds,dc=canfar,dc=net
userRequestsDN = ou=userRequests,ou=ds,dc=canfar,dc=net
groupsDN = ou=Groups,ou=ds,dc=canfar,dc=net
adminGroupsDN = ou=adminGroups,ou=ds,dc=canfar,dc=net
```

Each pool may specify its own `port`. If omitted, the default `port` at the bottom of the file is used.

Each pool may also specify `secure` to indicate whether connections use TLS. When omitted,
`secure` defaults to `true` when the pool port is 636 and `false` otherwise. Set `secure = true`
explicitly when using a non-standard port for LDAPS (for example, `readOnly.port = 10636` with
`readOnly.secure = true`). Pools that share the same port must use the same `secure` setting.

Property summary:

| property | required | description |
|----------|----------|-------------|
| `{pool}.servers` | yes | Space-separated list of LDAP host names |
| `{pool}.poolInitSize` | yes | Initial number of connections in the pool |
| `{pool}.poolMaxSize` | yes | Maximum number of connections in the pool |
| `{pool}.poolPolicy` | yes | Load-balancing policy for the pool |
| `{pool}.maxWait` | yes | Connection wait timeout in milliseconds |
| `{pool}.createIfNeeded` | yes | Whether to create connections beyond `poolMaxSize` |
| `{pool}.port` | no | LDAP port for this pool; defaults to `port` |
| `{pool}.secure` | no | Whether the pool uses TLS; defaults from the pool port |
| `port` | yes* | Default LDAP port (389 or 636) when a pool port is omitted |
| `proxyUser` | yes | DN of the LDAP proxy user |
| `proxyPassword` | yes | Password for the LDAP proxy user |
| `usersDN` | yes | DN of the users branch |
| `userRequestsDN` | yes | DN of the new-user-requests branch |
| `groupsDN` | yes | DN of the groups branch |
| `adminGroupsDN` | yes | DN of the admin-groups branch |

\* Required unless every pool specifies its own `{pool}.port`.

The `fastestConnect` pool policy is supported for the read-only pool only.

