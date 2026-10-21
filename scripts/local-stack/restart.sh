#!/usr/bin/env bash
set -euo pipefail
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
base=${1:?Usage: restart.sh PRIVATE_INSTALL_DIRECTORY}
bash "$root/scripts/local-stack/stop.sh" "$base"
exec bash "$root/scripts/local-stack/start.sh" "$base"
