FROM vault:1.6.0

ENV VAULT_ADDR="http://127.0.0.1:8200"

# Install jq to extract keys from a JSON file
RUN apk add --no-cache jq

# The "vault-plugin-secrets-oauthapp" go binary is a dynamic executable and needs system libraries
# that does not exist in Alpine. We install glibc in order to be able to run it
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
	wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.32-r0/glibc-2.32-r0.apk && \
	apk add glibc-2.32-r0.apk

# Create folders needed
RUN mkdir /etc/vault && \
    mkdir /var/lib/vault && \
	chown vault:vault /var/lib/vault

# Copy configuration files and plugins
COPY config /etc/vault/config
COPY plugins /etc/vault/config/plugins
RUN chmod 777 /etc/vault/config/reconfig.sh /etc/vault/config/unseal.sh /etc/vault/config/initialize_vault.sh

# Copy vault server configuration 
COPY vault.json /vault/config/vault.json

WORKDIR /etc/vault/config