#!/usr/bin/env bash
set -euo pipefail
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
build=(env RUSTFLAGS='-C link-arg=-fuse-ld=mold' CARGO_INCREMENTAL=0 cargo +1.95.0 build --manifest-path "$root/Cargo.toml" --target-dir "$root/target" --locked --offline -p oic-service-local-stack -p oic-approval-client)
if command -v eto-build >/dev/null; then
  exec eto-build "${build[@]}"
fi
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
exec "${build[@]}"
