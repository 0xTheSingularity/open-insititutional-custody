#!/usr/bin/env sh
# install.sh — download, VERIFY, then run the `oic` custody demo.
#
# Headline flow (what this script does): download the prebuilt `oic` binary for
# your platform, verify its SHA-256 checksum BEFORE running anything (fail closed
# on mismatch), optionally verify the cosign signature, then run `oic demo`.
#
# This is the "download, verify the signature, then run" path the README leads
# with. Piping this script straight into a shell
#   curl -fsSL https://raw.githubusercontent.com/0xTheSingularity/open-insititutional-custody/main/install.sh | sh
# is offered only as a CONVENIENCE FALLBACK. The security-researcher audience is
# right to distrust `curl | sh`; the recommended path is to download this script,
# read it, verify, then run it. The SHA-256 check is ALWAYS enforced regardless.
#
# Usage:
#   ./install.sh [--help]
#
# Environment:
#   OIC_VERSION   Release version to install (e.g. 0.1.0 or v0.1.0).
#                 Defaults to the latest published release.
#   OIC_INSTALL_DIR
#                 Directory to extract the binary into. Defaults to a temp dir.
#   OIC_NO_RUN    If set to 1, install the binary but do not run `oic demo`.

set -eu

REPO="0xTheSingularity/open-insititutional-custody"
GITHUB="https://github.com"
API="https://api.github.com"
# cosign keyless identity: the release workflow of this repo, signed via the
# GitHub Actions OIDC issuer.
COSIGN_ISSUER="https://token.actions.githubusercontent.com"
COSIGN_IDENTITY_REGEXP="^https://github.com/0xTheSingularity/open-insititutional-custody/\.github/workflows/release\.yml@refs/tags/"

usage() {
  cat <<'EOF'
oic installer — download, verify, then run.

RECOMMENDED (verify-first) flow:
  1. Download this script and read it.
       curl -fsSLO https://raw.githubusercontent.com/0xTheSingularity/open-insititutional-custody/main/install.sh
  2. Run it. It downloads the binary + .sha256, verifies the checksum BEFORE
     running, verifies the cosign signature when cosign is installed, then runs
     `oic demo`.
       sh ./install.sh

CONVENIENCE fallback (not the headline — the checksum is still enforced):
  curl -fsSL https://raw.githubusercontent.com/0xTheSingularity/open-insititutional-custody/main/install.sh | sh

Environment:
  OIC_VERSION       release version (e.g. 0.1.0); default: latest
  OIC_INSTALL_DIR   extract directory; default: a temp dir
  OIC_NO_RUN=1      install but do not run `oic demo`
EOF
}

log() { printf '%s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") : ;;
  *) die "unknown argument: $1 (try --help)" ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
need uname
need tar
need mktemp

# A downloader: prefer curl, fall back to wget.
download() {
  # download <url> <dest>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    die "need curl or wget to download $1"
  fi
}

# Map the host OS/arch to a release target triple.
detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin) os_part="apple-darwin" ;;
    Linux)  os_part="unknown-linux-gnu" ;;
    *) die "unsupported OS: $os (supported: macOS, Linux)" ;;
  esac
  case "$arch" in
    arm64|aarch64) arch_part="aarch64" ;;
    x86_64|amd64)  arch_part="x86_64" ;;
    *) die "unsupported architecture: $arch (supported: x86_64, aarch64)" ;;
  esac
  # Phase 1 ships: aarch64-apple-darwin, x86_64-apple-darwin, x86_64-unknown-linux-gnu.
  if [ "$os_part" = "unknown-linux-gnu" ] && [ "$arch_part" = "aarch64" ]; then
    die "no Phase 1 prebuilt binary for linux/aarch64; build from source or use the Docker image"
  fi
  printf '%s-%s' "$arch_part" "$os_part"
}

# Resolve the release tag (vX.Y.Z) to install.
resolve_tag() {
  if [ -n "${OIC_VERSION:-}" ]; then
    case "$OIC_VERSION" in
      v*) printf '%s' "$OIC_VERSION" ;;
      *)  printf 'v%s' "$OIC_VERSION" ;;
    esac
    return
  fi
  # Latest release tag, without jq: scrape the first tag_name from the API.
  tmp_json="$(mktemp)"
  download "${API}/repos/${REPO}/releases/latest" "$tmp_json"
  tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp_json" | head -n1)"
  rm -f "$tmp_json"
  [ -n "$tag" ] || die "could not resolve the latest release tag for $REPO"
  printf '%s' "$tag"
}

# Compute the SHA-256 of a file as a bare hex string.
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "need sha256sum or shasum to verify the checksum"
  fi
}

main() {
  target="$(detect_target)"
  tag="$(resolve_tag)"
  version="${tag#v}"

  tarball="oic-${version}-${target}.tar.gz"
  base="${GITHUB}/${REPO}/releases/download/${tag}"

  workdir="$(mktemp -d)"
  # Clean up the download workdir on exit.
  trap 'rm -rf "$workdir"' EXIT INT TERM

  log "==> oic ${version} (${target})"
  log "    downloading ${tarball}"
  download "${base}/${tarball}" "${workdir}/${tarball}"
  download "${base}/${tarball}.sha256" "${workdir}/${tarball}.sha256"

  # --- VERIFY THE CHECKSUM BEFORE DOING ANYTHING ELSE (fail closed) ---
  expected="$(awk '{print $1}' "${workdir}/${tarball}.sha256" | head -n1)"
  [ -n "$expected" ] || die "empty checksum file; refusing to continue"
  actual="$(sha256_hex "${workdir}/${tarball}")"
  if [ "$expected" != "$actual" ]; then
    die "SHA-256 mismatch for ${tarball}
  expected: ${expected}
  actual:   ${actual}
Refusing to extract or run. The download may be corrupt or tampered with."
  fi
  log "    sha256 OK: ${actual}"

  # --- OPTIONAL: cosign signature verification ---
  if command -v cosign >/dev/null 2>&1; then
    log "    cosign found; verifying signature"
    download "${base}/${tarball}.sha256.sig" "${workdir}/${tarball}.sha256.sig"
    download "${base}/${tarball}.sha256.pem" "${workdir}/${tarball}.sha256.pem"
    if cosign verify-blob \
      --certificate "${workdir}/${tarball}.sha256.pem" \
      --signature "${workdir}/${tarball}.sha256.sig" \
      --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
      --certificate-oidc-issuer "$COSIGN_ISSUER" \
      "${workdir}/${tarball}.sha256" >/dev/null 2>&1; then
      log "    cosign signature OK"
    else
      die "cosign signature verification FAILED for ${tarball}.sha256; refusing to continue"
    fi
  else
    log "    cosign not found; skipping signature verification (checksum already enforced)."
    log "    To verify the signature manually, install cosign and run:"
    log "      cosign verify-blob \\"
    log "        --certificate ${tarball}.sha256.pem \\"
    log "        --signature ${tarball}.sha256.sig \\"
    log "        --certificate-identity-regexp '${COSIGN_IDENTITY_REGEXP}' \\"
    log "        --certificate-oidc-issuer '${COSIGN_ISSUER}' \\"
    log "        ${tarball}.sha256"
    log "      (download the .sha256, .sha256.sig and .sha256.pem from ${base})"
  fi

  # --- EXTRACT (only after verification passed) ---
  install_dir="${OIC_INSTALL_DIR:-${workdir}/oic}"
  mkdir -p "$install_dir"
  tar -C "$install_dir" --strip-components=1 -xzf "${workdir}/${tarball}"
  bin="${install_dir}/oic"
  [ -x "$bin" ] || die "extracted archive did not contain an executable oic at ${bin}"
  chmod +x "$bin"
  log "==> installed oic to ${bin}"

  # --- RUN THE DEMO (the headline payoff) ---
  if [ "${OIC_NO_RUN:-}" = "1" ]; then
    log "==> OIC_NO_RUN=1 set; skipping \`oic demo\`. Run it yourself:"
    log "      ${bin} demo"
    # Keep the install dir if the caller chose an explicit location.
    [ -n "${OIC_INSTALL_DIR:-}" ] && trap - EXIT INT TERM
    exit 0
  fi

  log "==> running: oic demo"
  # If the caller picked a persistent install dir, keep it after the run.
  [ -n "${OIC_INSTALL_DIR:-}" ] && trap 'rm -rf "$workdir"' EXIT INT TERM
  "$bin" demo
}

main
