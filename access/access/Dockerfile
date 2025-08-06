# Dockerfile for CADC Access Control Module
# Based on cadc-tomcat as mentioned by Patrick

FROM cadc/tomcat:latest

# Set working directory
WORKDIR /usr/local/tomcat

# Copy the built WAR file
COPY build/libs/access.war webapps/

# Create directory for configuration files
RUN mkdir -p /usr/local/tomcat/conf/cadc

# Copy configuration files (if available)
COPY src/main/resources/AccessControl.properties /usr/local/tomcat/conf/cadc/
COPY src/main/resources/DelegationToken.properties /usr/local/tomcat/conf/cadc/

# Set environment variables
ENV CATALINA_OPTS="-Xmx2g -Xms1g"
ENV JAVA_OPTS="-Djava.security.egd=file:/dev/./urandom"

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/access/ || exit 1

# Default command
CMD ["catalina.sh", "run"] 