#!/bin/bash
set -eou pipefail

# usage: file_env VAR [DEFAULT]
#    ie: file_env 'XYZ_DB_PASSWORD' 'example'
# (will allow for "$XYZ_DB_PASSWORD_FILE" to fill in the value of
#  "$XYZ_DB_PASSWORD" from a file, especially for Docker's secrets feature)
file_env() {
    local var="$1"
    local fileVar="${var}_FILE"
    local def="${2:-}"
    if [[ ${!var:-} && ${!fileVar:-} ]]; then
        echo >&2 "error: both $var and $fileVar are set (but are exclusive)"
        exit 1
    fi
    local val="$def"
    if [[ ${!var:-} ]]; then
        val="${!var}"
    elif [[ ${!fileVar:-} ]]; then
        val="$(< "${!fileVar}")"
    fi

    if [[ -n $val ]]; then
        export "$var"="$val"
    fi

    unset "$fileVar"
}

SYS_PROPS=""

##################
# Add admin user #
##################

file_env 'KEYCLOAK_USER'
file_env 'KEYCLOAK_PASSWORD'

if [[ -n ${KEYCLOAK_USER:-} && -n ${KEYCLOAK_PASSWORD:-} ]]; then
    /server-keycloak/keycloak-7.0.0-SNAPSHOT/bin/add-user-keycloak.sh --user "$KEYCLOAK_USER" --password "$KEYCLOAK_PASSWORD"
fi


################
# Realm import #
################

if [[ -n ${KEYCLOAK_IMPORT:-} ]]; then
    SYS_PROPS+=" -Dkeycloak.import=$KEYCLOAK_IMPORT"
fi

##################
# Start Keycloak #
##################

exec /server-keycloak/keycloak-7.0.0-SNAPSHOT/bin/standalone.sh $SYS_PROPS $@
exit $?