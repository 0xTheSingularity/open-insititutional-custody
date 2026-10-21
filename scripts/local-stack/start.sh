#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
base=$(realpath "${1:?Usage: start.sh PRIVATE_INSTALL_DIRECTORY [development fault options]}")
shift
exec "$root/target/debug/oic-local-stack" start --state "$base/state" --listen 127.0.0.1:8787 --ready-file "$base/server.json" "$@"
