#!/usr/bin/env bash
set -euo pipefail
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
base=$(realpath "${1:?Usage: stop.sh PRIVATE_INSTALL_DIRECTORY}")
[[ -f "$base/server.json" ]] || { echo 'No server readiness record' >&2; exit 1; }
pid=$(jq -er '.pid | select(type == "number" and . > 1 and floor == .)' "$base/server.json")
[[ -d "/proc/$pid" ]] || { echo 'Recorded server is already stopped'; exit 0; }
[[ $(readlink "/proc/$pid/exe") == "$root/target/debug/oic-local-stack" ]] || { echo 'PID belongs to another executable; refusing to signal' >&2; exit 1; }
mapfile -d '' -t argv < "/proc/$pid/cmdline"
matches=false
for ((i=0; i+1<${#argv[@]}; i++)); do
  if [[ ${argv[i]} == --state && ${argv[i+1]} == "$base/state" ]]; then matches=true; fi
done
[[ $matches == true ]] || { echo 'PID has another state directory; refusing to signal' >&2; exit 1; }
kill -TERM "$pid"
for _ in {1..300}; do
  [[ -d "/proc/$pid" ]] || exit 0
  state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
  [[ $state == Z || -z $state ]] && exit 0
  sleep .1
done
echo 'Shutdown still draining. Inspect operations; do not start a second writer or retry an uncertain payment.' >&2
exit 1
