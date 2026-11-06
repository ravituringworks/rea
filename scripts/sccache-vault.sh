#!/usr/bin/env bash

# Run a command with sccache configured from the local HashiCorp Vault.
# Secret values are captured only in this process and its children.
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-secret/symphony/sccache}"
SCCACHE_BUCKET="${SCCACHE_BUCKET:-vibecody-sccache}"
SCCACHE_ENDPOINT="${SCCACHE_ENDPOINT:-https://729b7dfc20ff853a20b46ed4bcbcacd3.r2.cloudflarestorage.com}"
SCCACHE_REGION="${SCCACHE_REGION:-auto}"
export VAULT_ADDR

die() {
  echo "sccache-vault: $*" >&2
  exit 1
}

command -v vault >/dev/null 2>&1 || die "vault is not installed or not on PATH"
command -v sccache >/dev/null 2>&1 || die "sccache is not installed or not on PATH"

if ! vault token lookup >/dev/null 2>&1; then
  die "no usable Vault token at ${VAULT_ADDR}"
fi

access_key=$(vault kv get -field=access_key_id "$VAULT_SECRET_PATH") || {
  die "could not read access_key_id from ${VAULT_SECRET_PATH}"
}
secret_key=$(vault kv get -field=secret_access_key "$VAULT_SECRET_PATH") || {
  die "could not read secret_access_key from ${VAULT_SECRET_PATH}"
}

if [ "${#access_key}" -ne 32 ]; then
  die "Vault access_key_id must be 32 characters; refusing to send it to R2"
fi
if [ "${#secret_key}" -ne 64 ]; then
  die "Vault secret_access_key must be 64 characters; refusing to send it to R2"
fi

if [ "$#" -lt 1 ]; then
  die "usage: $0 <command> [args...]"
fi

# A running daemon retains the environment from its first startup. Stop it so
# the Vault-loaded credentials are guaranteed to be the credentials it uses.
sccache --stop-server >/dev/null 2>&1 || true

exec env \
  AWS_ACCESS_KEY_ID="$access_key" \
  AWS_SECRET_ACCESS_KEY="$secret_key" \
  SCCACHE_BUCKET="$SCCACHE_BUCKET" \
  SCCACHE_ENDPOINT="$SCCACHE_ENDPOINT" \
  SCCACHE_REGION="$SCCACHE_REGION" \
  # Do not inherit a stale wrapper path (for example /opt/homebrew/bin/sccache)
  # after loading credentials; the server must be started by this sccache.
  RUSTC_WRAPPER="sccache" \
  "$@"
