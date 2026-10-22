#!/bin/sh
# Test double for .github/workflows/custody-check.yml. It stands in for the
# `oic` binary so CI can check how the custody-check action (action.yml) reports
# each outcome of `oic demo --check`. OIC_STUB_EXIT selects the outcome:
#   3         oic reports a security regression
#   1         oic did not complete the check
#   no-check  an oic release without `demo --check`
set -eu

outcome="${OIC_STUB_EXIT:?set OIC_STUB_EXIT}"

case "$*" in
  "demo --help")
    echo "Usage: oic demo [OPTIONS]"
    [ "$outcome" = no-check ] || echo "      --check  CI mode"
    ;;
  "demo --check")
    echo "oic stub: exit $outcome"
    exit "$outcome"
    ;;
  *)
    echo "oic stub: unexpected arguments: $*" >&2
    exit 2
    ;;
esac
