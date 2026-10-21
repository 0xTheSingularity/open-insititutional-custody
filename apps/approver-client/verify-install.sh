#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: $0 independently-obtained-SHA256SUMS /absolute/installed-build-directory" >&2
  exit 2
fi
manifest=$(realpath "$1")
installed=$(realpath "$2")
# Do not accept a downloaded manifest alongside the build as independent proof.
cd "$installed"
sha256sum --check --strict "$manifest"
