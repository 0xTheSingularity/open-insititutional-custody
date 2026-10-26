#!/usr/bin/env sh
# record-demo.sh — record the <=20s `oic demo` terminal GIF for the README.
#
# Re-run this locally to refresh docs/assets/oic-demo.gif after the demo output
# changes. Do NOT install tools blindly in CI.
#
# Prerequisites (install whichever pair you have):
#   - asciinema + agg   (preferred)   https://asciinema.org  /  https://github.com/asciinema/agg
#   - OR vhs                          https://github.com/charmbracelet/vhs
#
# The demo already builds: `cargo build -p oic-cli` produces ./target/debug/oic.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ASSETS="${ROOT}/docs/assets"
CAST="${ASSETS}/oic-demo.cast"
GIF="${ASSETS}/oic-demo.gif"
BIN="${ROOT}/target/debug/oic"

# Build the demo binary if it is not present.
if [ ! -x "$BIN" ]; then
  echo "==> building oic (debug)"
  ( cd "$ROOT" && cargo build -p oic-cli )
fi

if command -v asciinema >/dev/null 2>&1 && command -v agg >/dev/null 2>&1; then
  echo "==> recording with asciinema -> ${CAST}"
  # --cols/--rows keep the frame compact; the demo runs in well under 20s.
  asciinema rec --overwrite \
    --cols 100 --rows 30 \
    --command "${BIN} demo" \
    "$CAST"
  echo "==> converting to GIF -> ${GIF}"
  agg --cols 100 --rows 30 "$CAST" "$GIF"
  echo "done: ${GIF}"
elif command -v vhs >/dev/null 2>&1; then
  echo "==> recording with vhs -> ${GIF}"
  tape="$(mktemp)"
  cat > "$tape" <<EOF
Output ${GIF}
Set Width 1000
Set Height 600
Set FontSize 16
Type "${BIN} demo"
Enter
Sleep 20s
EOF
  vhs "$tape"
  rm -f "$tape"
  echo "done: ${GIF}"
else
  echo "error: no recorder found. Install asciinema + agg, or vhs, then re-run." >&2
  exit 1
fi
