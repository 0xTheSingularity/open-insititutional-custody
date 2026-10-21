#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 ]]; then
  echo "usage: $0 /absolute/provision.json independently-published-sha256 /absolute/output-directory" >&2
  exit 2
fi
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
provision=$(realpath "$1")
expected=$2
out=$(realpath -m "$3")
[[ $(wasm-bindgen --version) == 'wasm-bindgen 0.2.117' ]] || { echo 'wasm-bindgen-cli 0.2.117 required' >&2; exit 1; }
[[ $(sha256sum "$provision" | cut -d' ' -f1) == "$expected" ]] || { echo 'Independent provision digest mismatch' >&2; exit 1; }
mkdir -p "$out/pkg"
# No mold flag for wasm-ld. BETA gate is mandatory, not a test-only setting.
wrapper=()
if command -v eto-build >/dev/null 2>&1; then
  wrapper=(eto-build)
else
  export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
fi
"${wrapper[@]}" env OIC_APPROVER_PROVISION="$provision" OIC_APPROVER_PROVISION_SHA256="$expected" \
  RUSTFLAGS="--cfg commonware_stability_BETA --remap-path-prefix=$root=/workspace" \
  cargo +1.95.0 build --manifest-path "$root/Cargo.toml" -p oic-approver-client \
  --lib --release --target wasm32-unknown-unknown --target-dir "$root/target" --locked --offline
wasm-bindgen "$root/target/wasm32-unknown-unknown/release/oic_approver_client.wasm" --target web --out-dir "$out/pkg" --out-name oic_approver_client
cp "$root/apps/approver-client/web/"{index.html,app.js,style.css} "$out/"
(
  cd "$out"
  sha256sum index.html app.js style.css pkg/oic_approver_client.js pkg/oic_approver_client_bg.wasm > SHA256SUMS
)
echo "Built $out. Publish/sign SHA256SUMS through an independent channel; this script does not establish distribution trust."
