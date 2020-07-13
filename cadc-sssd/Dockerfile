FROM centos:7

RUN \
  yum -y install sssd-client sssd-ldap && \
  yum -y clean all && \
  touch /run/utmp && \
  chmod u+s /usr/bin/ping

COPY src/cadc-sssd-start /usr/bin/cadc-sssd-start
CMD ["/usr/bin/cadc-sssd-start"]
