#!/bin/sh
export VAULT_ADDR=http://localhost:8200
export VAULT_LOG_LEVEL=debug
#(echo "$@"; env|sort) >/tmp/`basename $0`.out
exec `dirname $0`/`basename $0 .sh` "$@"
