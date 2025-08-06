#FROM opencadc/tomcat:8.5-alpine
FROM ghcr.io/opencadc/cadc-tomcat:9

#COPY AccessControl.properties /root/config/
#COPY LocalAuthority.properties /root/config/
#COPY build/libs/*.war webapps/
COPY build/libs/access.war /usr/local/tomcat/webapps/access.war

EXPOSE 5555

