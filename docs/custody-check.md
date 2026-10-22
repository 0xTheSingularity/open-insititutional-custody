# Custody check in CI

`oic demo --check` runs the quickstart demo as a test. The custody-check GitHub
Action runs that test in your workflow, against an `oic` release or your own
build of it. The step fails if that build's verifier signs a changed approval
package.

## Add the check to a workflow

```yaml
jobs:
  custody:
    runs-on: ubuntu-latest
    steps:
      - uses: 0xTheSingularity/open-insititutional-custody@v0.1.3
```

The action needs no inputs. It does three things:

1. It installs the `oic` release that matches the action's tag (`v0.1.3` in this
   example).
2. It verifies the download before it runs anything: the SHA-256 checksum, the
   cosign signature, and the build provenance attestation from this
   repository's release workflow.
3. It runs `oic demo --check` and adds the output to the job summary.

Use a Linux x86_64 or macOS runner. The action needs the GitHub CLI (`gh`),
which GitHub-hosted runners include. If you pin the action to a commit SHA, also
set `version`. Otherwise, the action installs the latest release.

## What the check asserts

The check runs the full custody flow against throwaway local simulators. No real
funds move. It prints one line for each assertion:

```text
oic demo --check: DEVELOPMENT profile, local simulators, no real funds
PASS  dev-only guard: environment dev
PASS  EVM transfer settled: DEVELOPMENT single-key secp256k1, 1-of-1 (tx 0x6da7…)
PASS  Solana transfer settled: FROST ed25519 2-of-3 (tx 4TcM…)
PASS  theft blocked: the verifier refused amount_base_units 1234567 -> 1234568 [UnverifiableTransaction]
PASS  audit export verified: 8 journal entries, 51 events, 28 checkpoints
RESULT: PASS
```

The theft line is the security assertion. The check copies an approved EVM
package, changes the amount, and asks the independent verifier to sign it. The
verifier decodes the amount from the transaction bytes, so it must refuse.

| Exit code | `result` output | Meaning |
| --- | --- | --- |
| `0` | `pass` | Every assertion held. |
| `3` | `regression` | The verifier signed the changed package. The custody guard failed. |
| `1` | `error` | The flow stopped before the check could decide. |

## Scope

The check tests the `oic` release that it installs. It does not read your own
code, policy configuration, or deployment. It shows that the verifier in that
release refuses a changed package on your runner. To test your own build of this
repository, pass it as `binary`:

```yaml
      - run: cargo build -p oic-cli --locked
      - uses: 0xTheSingularity/open-insititutional-custody@v0.1.3
        with:
          binary: target/debug/oic
```

With `binary`, the action skips the download and its verification.

## Inputs and outputs

| Input | Default | Description |
| --- | --- | --- |
| `version` | The action's tag, else the latest release | The `oic` release tag to install, for example `v0.1.3`. |
| `binary` | None | The path to an `oic` binary to check instead of a release. |

| Output | Description |
| --- | --- |
| `result` | `pass`, `regression`, or `error`. |
| `version` | The release tag that the action checked, or `local` for `binary`. |

## How this repository tests the action

The [custody check workflow](../.github/workflows/custody-check.yml) runs the
action on each change to it. One job builds `oic` from the commit and requires
`pass`. Other jobs replace `oic` with a [stub](../.github/custody-check/oic-stub.sh)
that exits `3`, exits `1`, or has no `--check` mode. Each job requires a failed
step with the matching `result`.

Each release also runs the action with no `binary` input on Linux and macOS.
See the `release-smoke` job in the [release workflow](../.github/workflows/release.yml).
