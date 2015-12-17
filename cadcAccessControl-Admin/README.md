# cadcAccessControl-Admin

This module provides a command line tool for managing users.  It uses the persistence layer code (rather than the web service) for the various functions.

## Usage

```
Usage: userAdmin <command> [-v|--verbose|-d|--debug] [-h|--help]
Where command is:

--list                       : List users in the Users tree
--list-pending               : List users in the UserRequests tree
--view=<userid>              : Print the entire details of <user> (pending or not)
--approve=<userid> --dn=<dn> : Approve user with userid=<userid> and set the
                             : distinguished name to <dn>
--reject=<userid>            : Delete this user request

-v|--verbose                 : Verbose mode print progress and error messages
-d|--debug                   : Debug mode print all the logging messages
-h|--help                    : Print this message and exit
```

## Depdencies

### opencadc dependencies

- opencadc/ac/cadcUtil
- opencadc/ac/cadcLog
- opencadc/ac/cadcAccessControl
- opencadc/ac/cadcAccessControl-Server

### external build dependencies
- log4j.jar (log4j-1.2.17.jar)
- commons-logging.jar
- unboundid.jar
- servlet-api
- mail

### external test dependencies
- asm.jar (hibernate-3.2.3)
- cglib.jar (hibernate-3.2.3)
- easymock.jar (easymock-3.0.jar)
- junit.jar (junit-4.6.jar)
- objenesis.jar (objenesis-1.2.jar)
