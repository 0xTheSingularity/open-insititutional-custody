#!/usr/bin/env bash
set -euo pipefail
base=$(realpath "${1:?Usage: request.sh INSTALL_DIRECTORY console|reader|approval|operator METHOD /path [JSON_FILE]}")
credential=${2:?credential required}; method=${3:?method required}; path=${4:?path required}
case "$credential" in console|reader|approval|operator) ;; *) echo 'Unknown credential' >&2; exit 1 ;; esac
[[ $path == /* && $path != //* && $path != *$'\n'* ]] || { echo 'Expected a local absolute API path' >&2; exit 1; }
token=$(jq -er .token "$base/handoff/$credential.json")
args=(--silent --show-error --fail-with-body --request "$method" --header "Authorization: Bearer $token" --header 'Content-Type: application/json')
if [[ $method == POST && $path == /v1/intents ]]; then
  : "${OIC_IDEMPOTENCY_KEY:?Set OIC_IDEMPOTENCY_KEY to the stable, unique payment request ID}"
  args+=(--header "Idempotency-Key: $OIC_IDEMPOTENCY_KEY")
fi
if [[ $# -ge 5 ]]; then args+=(--data-binary "@$5"); fi
exec curl "${args[@]}" "http://127.0.0.1:8787$path"
