# cadcAccessControl-Admin

This module provides a command line tool for managing users. It uses the persistence layer code (rather than the web
service) for the various functions.

## Usage

```
Usage: userAdmin <command> [-v|--verbose|-d|--debug] [-h|--help]
Where command is:

--list                       : List approved users
--list-pending               : List users waiting for approval
--view=<userid>              : Print the entire details of <user> (pending or not)
--approve=<userid> --dn=<dn> : Approve user with userid=<userid> and set the
                             : distinguished name to <dn>
--reject=<userid>            : Delete this user request
--disable=<userid>           : Lock this user account
--enable=<userid>            : Unlock this user account

--send-email                                   : Send an email to selected users
    --file=<email-properties-file>             : Config file with email details
    --outfile=<list-of-successful-sends>       : Log file
    --batch-size=<num-of-emails-in-bcc>        : Number of emails in the bcc list
    --to=<group> | --to-all                    : --to send - to all members of a group
                                               : --to-all - send to all users
    [--resume=<last-successful-send-address>]  : Resume sending after this email address
    [--dry-run]     
        
-v|--verbose                 : Verbose mode print progress and error messages
-d|--debug                   : Debug mode print all the logging messages
-h|--help                    : Print this message and exit
```
