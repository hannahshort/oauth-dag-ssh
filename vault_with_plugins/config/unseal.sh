#!/bin/sh
#
# In order to use gpg for the unseal key:
#  1. gpg --gen-key
#     where a 4096-bit key was created with name "vault seal", email
#     vault@seal, and given a passphrase.
#  2. gpg -a --export vault >vaultseal.pub
#  3. vault operator init -key-shares=1 -key-threshold=1 -pgp-keys=vaultseal.pub
# The pgp-encrypted and base64-encoded key is printed to stdout; save it
#  in vaultseal.gpg.b64.
#
# This will prompt for passphrase the first time the seal is used, and
#  otherwise the passphrase is in gpg-agent for up to 5 minutes (by default).
#
# Alternatively the gpg key can be stored unencrypted in a Yubikey:
#  https://support.yubico.com/support/solutions/articles/15000006420-using-your-yubikey-with-openpgp
# Verified with Yubikey 4, encrypt-only gpg key and this command:
#  echo 123456|gpg --passphrase-fd=0 --pinentry-mode=loopback --decrypt <(base64 --decode </etc/vault/vaultseal.gpg.b64)
# Disadvantage is that someone who broke in could still get the unseal key
#  by doing the same command.

set -x
#vault operator unseal `gpg --decrypt <(base64 --decode </etc/vault/vaultseal.gpg.b64)`
vault operator unseal `cat /etc/vault/config/vaultseal.txt`
