# cadcAccessControl-Server

## Description

Building cadcAccessControl-Server produces a jar file that can be deployed within a war file in a servlet container (servlet api 3.0).

cadcAccessControl server is a RESTful interface to authentication, authorization and user and group management.  There are three software layers:

1. The action classes - these coordinate the functions of the REST API
2. The persistence layer - Authorization and connection management
3. The DAO layer - interface to persistent storage

cadcAccessControl-Server has a default persistence layer built-in: LDAP.  However, by implementating the Persistence and DAO interfaces one can easily configure this service to communicate with a different storage mechanism (such as a relational database).

## REST API

| operation |	HTTP Method | description | faults |
| --------- | ----------- | ----------- | ------ |
| Group Management - List all groups | GET | Lists the names of all the groups in the service | |
| Group Management - Create group | PUT | Ceate the group according to the group XML document in the HTTP PUT. | 404 Not Found - If a member is not recognized. | 409 Conflict - If a group with the same name already exists. |
| Group Management - Get group | GET | Get the group with name {groupID}. | 404 Not Found - If the group {groupID} could not be found. | 
| Group Management - Delete group | DELETE | DELETE the group with name {groupID}. | 404 Not Found - If the group {groupID} could not be found. |
| Group Management - Modify group | POST | Modify the group with name {groupID} according to the group XML document in the HTTP POST. | 404 Not Found - If the group {groupID} could not be found or if a member is not recognized<br/>409 Conflict - If a group with the same name already exists. |
| Group Management - Add user member | PUT | Add user {userID} as a member of group {groupID}. | 404 Not Found - If the group {groupID} could not be found or if the member {userID} is not recognized |
| Group Management - Remove user member | DELETE | Remove user {userID} as a member of group {groupID}. | 404 Not Found - If the group {groupID} could not be found or if the member {userID} is not recognized |
| Group Management - Add group member | PUT | Add group {groupID2} as a member of group {groupID}.	| 404 Not Found - If the group {groupID} or {groupID2} could not be found. |
| Group Management - Remove group member | DELETE | Remove group {groupID2} as a member of group {groupID}. | 404 Not Found - If the group {groupID} or {groupID2} could not be found. |
| Group Searching - Search by role | DELETE Find the groups in which the user (specified by param {userID}) has the role {role}. | |
| Group Searching - Search specific membership | POST	| If a user has the specified role in the specified group the group is returned. Otherwise returns an empty list of groups.	| |
| User management - List all users | GET | Lists basic information of all the users in the service | |
| User Management - Request account | PUT	| Request the user account in the user XML document in the HTTP PUT. This can take an arbitrary amount of time. If the account existed before but was deleted, this operation will reenable the account. | 404 Not Found - If a member is not recognized.<br/>409 Conflict - If a group with the same name already exists. |
| User Management - Get user | GET | Get the user with userid {userID} of type {idType}. This operation supports an optional parameter: detail, which can have values of display or identity. The detail parameter adjusts the amount type of user information that is returned. | 404 Not Found - If the user {userID} could not be found. |
| User Management - Disable account | DELETE | Disable the account for user with userid {userID} of type {idType}. | 404 Not Found - If the group {userID} could not be found. |
| User Management - Modify user	| POST |  Modify the user with name {userID} and type {idType{ according to the user XML document in the HTTP POST. | 404 Not Found - If the user {userID} could not be found. |
| User Login | POST	|	Validate the userID and password combination. If the combination is valid this operation will return a cookie that can be used to enter any of these endpoints over HTTP. | 403 Permission Denied - If the userID / pasword validation failed. |
| Password Changes | POST	| Change password from {old_password} to {new_password}. | 403 Permission Denied - If the old pasword is incorrect. |
| Who Am I - Logged-in user information | GET	| Returns information about the authentication user. | |
| Service availability | GET | | |	

## CONFIGURATION
The service requires the following configuration files:
.dbrc: stores data source configuration for the LDAP server
ldap.properties: stores LDAP connection configuration


