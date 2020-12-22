# Command line authentication by outsourcing token storage

This repository provides a proof of concept of retrieving an OAuth2.0 token from the command line by the use of SSH. The architecture relies on Keycloak playing the role of Identity Provider and Harshicop Vault to externally store OAuth 2.0 tokens. The architecture also relies on the [OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628) to obtain user authorization as the command line lacks a browser to perform a user-agent-based authorization.

## Architecture
The overall architecture consists of the following elements:
- SSH Server. Listen for incoming requests and acts as a proxy between the client and Vault along with Keycloak. The server relies on a custom PAM (Pluggable Authentication Module) which defines the authentication process
- [Keycloak](https://www.keycloak.org/). It provides Identity and Access Management
- [Harshicop Vault](https://www.vaultproject.io/) for token storage. It also needs two plugins:
    - [JWT Auth Backend](https://github.com/hashicorp/vault-plugin-auth-jwt). It allows OIDC to authenticate with Vault.
    - [Secrets OAuth App](https://github.com/puppetlabs/vault-plugin-secrets-oauthapp). It provides a secure wrapper around OAuth 2 authorization code grant flows

![Architecture](https://raw.githubusercontent.com/apozohue10/oauth-dag-ssh/master/doc/architecture.png)

### Flow

![Flow](https://raw.githubusercontent.com/apozohue10/oauth-dag-ssh/master/doc/flow.png)

## Prerequisites
### Docker
To keep it simple, all components will be run using Docker and Docker Compose. All docker images are available in Docker Hub, but, in case are needed, the Dockerfiles are provided too. The solution has been developed with the followings versions (In any case it should work in later versions):
- Docker 19.03
- Docker Compose 1.25

## Start up
1.  Clone Proxy repository:

```console
git clone https://github.com/apozohue10/oauth-dag-ssh
```

2. Deploy docker containers

```console
make up
```

3. Initialize Harshicop Vault

```console
make initialize_vault_server
```

4. Run ssh client script

```console
./client_ssh
```

Once you have run the ssh client, you will retrieve in the command line a QR code and also a url. Open a browser and navigate to the url mentioned. You will be redirected to a Keycloak authentication form. You can authenticate using:
- Username: user
- Password: user
Once that you have authenticated and accepted an authorization, you have to return to the command line and press Enter. If everything goes well, the command line will display a Bearer Token.

ScreenCast

## Code structure
The code is structured as follows:
- */keycloak-dag* contains all necessary files to build a Keycloak Docker Image that supports Device Code Flow. The official repository of Keycloak does not support this flow but there is a pending [PR](https://github.com/keycloak/keycloak/pull/6992) that enables it. However, in this case, it is used directly the keycloak repository forked from which the PR was made. The folder also contains two java files that modify the OIDC discovery url needed. In the sub-folder data, there is a default realm to provide some values when running Keycloak.
- */ssh-server* contains all necessary files to build a SSH Server Image. It contains the configuration files to enable ssh to use a python PAM Module. The python PAM modules is named pam_get_oauth2_token.py which is based in [pam_python](http://pam-python.sourceforge.net/).
- */vault_with_plugins* contains all necessary files to build a Vault Image supporting the two plugins mentioned. The plugins subfolder contains the binaries of the plugins. These plugins were compiled with go as described in this [link](https://learn.hashicorp.com/tutorials/vault/plugin-backends). The config folder and vault.json are needed to initialice and configure Vault with Keycloak values.
- Makefile. Enables running, configuring and stopping the scenario.
- client_ssh allows to stablish a ssh communication to retrieve a token.
- docker-compose.yml defines all the docker containers involved in the solution.

The Keycloak version used is 7.0.0
The Vault version used is 1.6.0
