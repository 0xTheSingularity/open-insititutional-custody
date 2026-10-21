#!/usr/bin/env bash
# Development evidence only: real TCP/WASM, simulated chain inputs, virtual UV.
set -euo pipefail
umask 077
usage() {
  echo 'Usage: bash scripts/local-stack/check-d2.sh NEW_PRIVATE_RUN_DIRECTORY [both|evm|solana]'
  echo 'Requires cached Cargo dependencies, Rust 1.95.0 + wasm32 target, mold, wasm-bindgen 0.2.117, Node and Playwright Chromium.'
}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
if (( $# < 1 || $# > 2 )); then usage >&2; exit 2; fi
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
base=$(realpath -m -- "$1")
mode=${2:-both}
case "$mode" in both) chains=(evm solana);; evm|solana) chains=("$mode");; *) usage >&2; exit 2;; esac
[[ ! -e "$base" && ! -L "$base" ]] || { echo 'Run directory already exists; refusing to replace keys, journals or evidence.' >&2; exit 1; }
for tool in cargo rustup mold wasm-bindgen node sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
rustup run 1.95.0 rustc --version >/dev/null
rustup target list --toolchain 1.95.0 --installed | grep -qx wasm32-unknown-unknown || {
  echo 'Install the target first: rustup target add --toolchain 1.95.0 wasm32-unknown-unknown' >&2; exit 1;
}
[[ $(wasm-bindgen --version) == 'wasm-bindgen 0.2.117' ]] || { echo 'wasm-bindgen-cli 0.2.117 required; no global tool changes were made.' >&2; exit 1; }
# The browser harness resolves its fixture binary relative to the repository.
cd "$root"
node --input-type=module <<'JS'
try {
  const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
  const browser = await chromium.launch({ headless: true });
  await browser.close();
} catch (error) {
  console.error(`Playwright Chromium prerequisite failed: ${error.message}`);
  console.error('Install Playwright/Chromium first; set PLAYWRIGHT_MODULE to its absolute module path if it is outside this repository.');
  process.exitCode = 1;
}
JS
mkdir -p -- "$(dirname "$base")"
mkdir -- "$base"
native_pid=
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$native_pid" ]]; then
    # Signal only this shell's still-running child, never a saved/reused PID.
    if jobs -pr | grep -qx "$native_pid"; then kill -TERM "$native_pid" || true; fi
    wait "$native_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then echo "D2 check failed; complete logs and private run state retained at $base" >&2; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
wrapper=()
if command -v eto-build >/dev/null; then wrapper=(eto-build); else export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}; fi
echo 'Building the native development network (locked, offline)...'
"${wrapper[@]}" env RUSTFLAGS='-C link-arg=-fuse-ld=mold' CARGO_INCREMENTAL=0 \
  cargo +1.95.0 build --manifest-path "$root/Cargo.toml" --target-dir "$root/target" \
  -p oic-service-signer-net --example approver_network --locked --offline > "$base/native-build.log" 2>&1
wait_for() {
  local file=$1
  for _ in {1..600}; do
    [[ ! -s "$file" ]] || return 0
    kill -0 "$native_pid" 2>/dev/null || { echo "Native network exited before $(basename "$file"); inspect native.log" >&2; return 1; }
    sleep .5
  done
  echo "Timed out waiting for $(basename "$file"); inspect native.log" >&2
  return 1
}
for chain in "${chains[@]}"; do
  dir="$base/$chain"
  mkdir -- "$dir"
  echo "Running $chain: four TCP replicas, two HTTP nodes and real browser verification..."
  "$root/target/debug/examples/approver_network" "$dir/native" "$chain" > "$dir/native.log" 2>&1 &
  native_pid=$!
  wait_for "$dir/native/provision.json"
  "$root/apps/approver-client/build-web.sh" "$dir/native/provision.json" \
    "$(sha256sum "$dir/native/provision.json" | cut -d' ' -f1)" "$dir/web" > "$dir/web-build.log" 2>&1
  wait_for "$dir/native/endpoints.json"
  node "$root/apps/approver-client/tests/browser.mjs" "$dir/native" "$dir/web" "$dir/evidence" "$chain" --live > "$dir/browser.log" 2>&1
  native_status=0
  wait "$native_pid" || native_status=$?
  native_pid=
  if (( native_status != 0 )); then echo 'Native journal/shutdown verification failed; inspect native.log' >&2; exit "$native_status"; fi
  cp "$dir/native/approval-observed.json" "$dir/native/journal-replay.json" "$dir/web/SHA256SUMS" "$dir/evidence/"
  "$root/apps/approver-client/verify-install.sh" "$dir/evidence/SHA256SUMS" "$dir/web" > "$dir/install-check.log" 2>&1
  cat "$dir/browser.log"
done
echo "D2 development E2E passed; private runs, logs and evidence: $base"
echo 'No production installation, independently authenticated distribution, physical attestation or live-chain transfer is claimed.'
