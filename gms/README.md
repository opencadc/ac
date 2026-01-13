# Groups Management Service (gms)

The ***gms*** service provides RESTful web service interface for group management operations. It handles creation, modification, deletion, and querying of user groups, as well as managing group memberships and permissions.

This service works with a user service that provides user identity information. TBD

## deployment
The `gms` war file can be renamed at deployment time in order to support an alternate service name, including
introducing additional path elements.
See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a> (war-rename.conf).

## configuration
The following runtime configuration must be made available via the `/config` directory.

### catalina.properties
This file contains java system properties to configure the tomcat server and some of the java libraries
used in the service.

See <a href="https://github.com/opencadc/docker-base/tree/master/cadc-tomcat">cadc-tomcat</a> for
system properties related to the deployment environment.

See <a href="https://github.com/opencadc/core/tree/master/cadc-util">cadc-util</a> for common system properties.

### cadc-registry.properties

See <a href="https://github.com/opencadc/reg/tree/master/cadc-registry">cadc-registry</a>.

### gms.properties
TBD. At minimum, the following properties are required:
- Corresponding user service base URL and the name of the user identity attribute.

## API Overview

The GMS service provides the following operations:

### Group Management
- **List all groups** - GET /groups
- **Create group** - PUT /groups
- **Get group** - GET /groups/{groupID}
- **Delete group** - DELETE /groups/{groupID}
- **Modify group** - POST /groups/{groupID}
- **Add/Remove user members** - POST/DELETE /groups/{groupID}/userMembers
- **Add/Remove group members** - POST/DELETE /groups/{groupID}/groupMembers  (Is it required to distinguish between user and group members?)

### Group Searching
- **Search by role** - GET /search?id={userID}&idType={idType}&role={role}
- **Search specific membership** - GET /search?id={userID}&idType={idType}&role={role}&groupID={groupID}

### Authentication Methods
The service supports multiple authentication methods:
- **Client certificates** (CC) over HTTPS - `/groups/*` endpoints
- **Anonymous** (AN) access for listing operations

## Group Structure

Groups have the following key components:
- **Owner** - Can modify administrator/member lists and delete the group
- **Administrators** - Can modify administrator and member lists
- **Members** - Are granted access to resources the group is associated with

Both users and other groups can be members or administrators of a group.

## building it
```
gradle clean build
docker build -t gms -f Dockerfile .
```

## running it
```
docker run --rm --user tomcat:tomcat --volume=/path/to/external/config:/config:ro --name gms gms:latest
```

## testing it

### Unit tests
```
gradle clean test
```

### Integration tests
```
gradle clean intTest
```

For local testing against a running instance:
```
~/bin/int-test-localhost.sh
```

## API Documentation

For detailed API specifications including request/response formats, authentication requirements, and error codes, see the OpenAPI specification or the service capabilities endpoint at `/capabilities`.
