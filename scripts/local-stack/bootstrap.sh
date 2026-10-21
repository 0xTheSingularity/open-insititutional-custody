#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
base=${1:?Usage: bootstrap.sh PRIVATE_INSTALL_DIRECTORY}
command -v jq >/dev/null
bash "$root/scripts/local-stack/build.sh"
mkdir -p "$base/independent"
base=$(realpath "$base")
if [[ -e "$base/state/provisioned.json" || -e "$base/independent/approver.json" ]]; then
  echo 'Installation already exists. Bootstrap never replaces keys or resets stores; use start/restart.' >&2
  exit 1
fi
read -r -s -p 'New independent approval passphrase (at least 12 bytes): ' OIC_LOCAL_APPROVAL_PASSPHRASE; echo
read -r -s -p 'Confirm passphrase: ' confirmation; echo
[[ "$OIC_LOCAL_APPROVAL_PASSPHRASE" == "$confirmation" ]] || { echo 'Passphrases differ' >&2; exit 1; }
unset confirmation
export OIC_LOCAL_APPROVAL_PASSPHRASE
"$root/target/debug/oic-approve" keygen --out "$base/independent/approver.json" --credential-id independent-approver --role treasury_approver --passphrase-env OIC_LOCAL_APPROVAL_PASSPHRASE
unset OIC_LOCAL_APPROVAL_PASSPHRASE
public_key=$(jq -er .public_key_hex "$base/independent/approver.json")
"$root/target/debug/oic-local-stack" bootstrap --state "$base/state" --handoff "$base/handoff" --approver-public-key "$public_key"
printf '\nStart: bash %q/scripts/local-stack/start.sh %q\n' "$root" "$base"
echo 'Only handoff/console.env belongs in the local console server environment. Keep independent/ and other handoff credentials outside the browser and Vercel.'
