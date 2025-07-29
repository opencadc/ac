FROM 389ds/dirsrv:3.1

ENV DS_DM_PASSWORD=pw-dm
COPY src/schema/* /etc/dirsrv/schema/

COPY src/cadc-ldap-dev-start /usr/bin
CMD ["cadc-ldap-dev-start"]

