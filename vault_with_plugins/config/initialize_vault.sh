#!/bin/sh

while true; do
  echo "Checking the current vault status..."
  vault status -address=${VAULT_ADDR} > /dev/null 2>&1
  STATUS=$?
  if [ ${STATUS} = 2 ]; then
    break
  else
    echo "Vault unavailable. Retrying in 5s..."
  fi
  sleep 5
done

while true; do
  echo "Checking the Keycloak is up and running..."
  CODE=$(wget --spider -S ${KEYCLOAK_ADDR} 2>&1 | grep "HTTP/" | awk '{print $2}')
  if [ ${CODE} = 200 ]; then
  	echo "Keycloak up!"
    break
  else
    echo "Keycloak unavailable. Retrying in 5s..."
  fi
  sleep 5
done

# Init vault servers
vault operator init -key-shares=1 -key-threshold=1 -format=json >keys.json

# Parse keys and root token in files
# The root token could be used to access vault through a browser (http://localhost:8200)
jq -r ".unseal_keys_b64[0]" keys.json >vaultseal.txt
jq -r ".root_token" keys.json >~/.vault-token
chmod 600 vaultseal.txt ~/.vault-token
rm -rf keys.json

# Unseal (access to the encrypted master key)
./unseal.sh

# Reconfig to enable oidc and oauth secrets storage. Create OIDC client with Oauth2.0 Id, Secret, Redirect Uri, etc
./reconfig.sh