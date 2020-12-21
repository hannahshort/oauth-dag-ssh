FROM ubuntu:bionic

# Install OpenJDK-8 and Maven
RUN apt-get update && \
    apt-get install -y openjdk-8-jdk maven && \
    apt-get install -y ant && \
    apt-get clean;

# Install git
RUN apt-get install -y git

# Fix certificate issues
RUN apt-get update && \
    apt-get install ca-certificates-java && \
    apt-get clean && \
    update-ca-certificates -f;

# Setup JAVA_HOME -- useful for docker commandline
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/
RUN export JAVA_HOME

# Clone Keycloak Code
RUN git clone --single-branch --branch oauth2-device-authorization-grant https://github.com/openstandia/keycloak

# Copy files to change discovery url
COPY OIDCWellKnownProvider.java /keycloak/services/src/main/java/org/keycloak/protocol/oidc/OIDCWellKnownProvider.java
COPY OIDCConfigurationRepresentation.java /keycloak/services/src/main/java/org/keycloak/protocol/oidc/representations/OIDCConfigurationRepresentation.java

# Create server distribution
RUN cd keycloak && \
	mvn -Pdistribution -pl distribution/server-dist -am -Dmaven.test.skip -DskipTests clean install

# Unzip server distribution
RUN mkdir server-keycloak && \
	mv /keycloak/distribution/server-dist/target/keycloak-7.0.0-SNAPSHOT.tar.gz /server-keycloak/keycloak-7.0.0-SNAPSHOT.tar.gz && \
	cd server-keycloak && \
	tar xvzf keycloak-7.0.0-SNAPSHOT.tar.gz

EXPOSE 8080
EXPOSE 8443

COPY docker-entrypoint.sh docker-entrypoint.sh

RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["-b", "0.0.0.0"]