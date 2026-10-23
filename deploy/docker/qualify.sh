#!/usr/bin/env sh
# Multi-address qualification: provision and start the reference topology
# with one IP per node, prove convergence from the gateway's view, and tear
# everything down. Exits 0 only if the topology converged.
set -eu

compose="docker compose -f $(dirname "$0")/compose.yaml"

cleanup() {
    $compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

$compose build
$compose up -d signer-0 signer-1 signer-2 authority

started=$(date +%s)
$compose run --rm qualify
echo "qualification converged in $(( $(date +%s) - started ))s"
