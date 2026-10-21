#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
base=$(realpath "${1:?Usage: approve.sh INSTALL_DIRECTORY INTENT_ID}")
id=${2:?intent ID required}
[[ $id =~ ^[a-zA-Z0-9._:-]{1,100}$ ]] || { echo 'Invalid local intent filename' >&2; exit 1; }
package="$base/independent/$id.package.json"
grant="$base/independent/$id.grant.json"
[[ ! -e $package && ! -e $grant ]] || { echo 'Review/grant file already exists. Inspect it; never silently replace an approval.' >&2; exit 1; }
bash "$root/scripts/local-stack/request.sh" "$base" approval GET "/v1/intents/$id/preview" > "$package"
read -r -s -p 'Independent approval key passphrase: ' OIC_LOCAL_APPROVAL_PASSPHRASE; echo
export OIC_LOCAL_APPROVAL_PASSPHRASE
"$root/target/debug/oic-approve" approve --trust "$base/handoff/trust.json" --package "$package" --key "$base/independent/approver.json" --passphrase-env OIC_LOCAL_APPROVAL_PASSPHRASE --grant-id "grant-$id" --ttl-seconds 300 --out "$grant"
unset OIC_LOCAL_APPROVAL_PASSPHRASE
bash "$root/scripts/local-stack/request.sh" "$base" approval POST "/v1/intents/$id/approvals" "$grant"
