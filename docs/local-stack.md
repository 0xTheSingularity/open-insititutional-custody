# Development-only local custody stack

This Linux recipe runs actual D1 authorization, independent verification,
signing, broadcast and reconciliation libraries against the EVM and Solana
simulators. It cannot move real funds. It is not a production installation,
RFC003 D2 deployment, institutional SSO, or the whole RFC004 product.

EVM uses development **1-of-1 secp256k1**. Solana uses actual **2-of-3 FROST
Ed25519**, but all shares and the D1 authority run under one local OS account.
The profile's institution is `local-institution`, environment is `dev`, vault
is `operating`, proposer is `local-proposer`, and independent approver is
`independent-approver`. No production roots should be reused here.

## Build, bootstrap and start

Prerequisites: Linux, Rust 1.95.0, mold, Bash, curl, jq, a native C/C++ toolchain
with CMake, and the workspace's locked native dependencies in the Cargo cache.
For the first dependency download, run `cargo +1.95.0 fetch --locked` with network
access. The build script uses `eto-build` when available; otherwise it defaults
to two build jobs (`CARGO_BUILD_JOBS` overrides this). Binaries always go under
this checkout's `target/debug`, regardless of `CARGO_TARGET_DIR`.
Build/download time is separate from setup time.
Run commands from the repository root:

```bash
bash scripts/local-stack/build.sh
export INSTALL="$HOME/.local/share/oic-local-trial"
bash scripts/local-stack/bootstrap.sh "$INSTALL"
bash scripts/local-stack/start.sh "$INSTALL"
```

Bootstrap builds both binaries, prompts for a new approval-key passphrase
(at least 12 bytes), and calls the existing `oic-approve keygen` CLI. Only the
public approval key reaches the server. The encrypted key remains in
`$INSTALL/independent/approver.json`. Bootstrap refuses an existing installation;
never delete stores or bootstrap again to resolve payment uncertainty.

Start stays in the foreground, binds **127.0.0.1:8787**, and writes
`$INSTALL/server.json` with its PID/address after reopening all stores. In another
terminal, `bash scripts/local-stack/stop.sh "$INSTALL"` checks that PID's actual
executable and state path before sending SIGTERM. `restart.sh` performs that
stop and starts in the foreground again. A per-state process lock prevents a
second writer. SIGTERM drains HTTP requests; the tests also exercise abrupt
process death, not only graceful shutdown.

## Keep credentials separate

Bootstrap creates private mode-0600 handoff files in `$INSTALL/handoff`:

| File | Authority |
| --- | --- |
| `console.json`, `console.env` | Read, Propose, Submit for the local vault; no approval |
| `reader.json` | Read only |
| `approval.json` | Read and ingest signed approval grants; not a signing key |
| `operator.json` | Local simulator mutation only; not an API approval/admin vote |
| `trust.json`, `catalog.json` | Public trust configuration and enrolled catalog |

For the separately owned local Next console bridge, load **only** `console.env`
into the local server's environment. It contains exactly:

```text
OIC_CONSOLE_CUSTODY_ORIGIN=http://127.0.0.1:8787
OIC_CONSOLE_CUSTODY_TOKEN=<local Read/Propose/Submit bearer>
```

Do not copy the installation, approval/operator credentials, or approval keys
into browser storage, the console repository, Vercel, or a hosted demo.
The console bridge disables this integration under `VERCEL` or
`OIC_CONSOLE_DEMO=1`. Its `/console-api/v1` setup/watch-only behavior is separate.
Local bearer authorization is not institutional identity federation.

## Receive, fund fees, independently approve, send and export

The following is one EVM transfer. All amounts are **integer base-unit strings**:
DEV-ETH has 18 decimals; DEV-SOL has 9. Simulator `receive` and `fund_fees`
are separately labelled native faucets, not external deposits or approved
treasury funding workflows. Each control requires a unique stable command ID;
repeating that ID with the same contents is idempotent, different contents fail.

```bash
umask 077
req() { bash scripts/local-stack/request.sh "$INSTALL" "$@"; }
req reader GET /local/v1/catalog > "$INSTALL/catalog-live.json"
printf '%s\n' '{"id":"evm-receive-1","chain":"evm","action":"receive","amount":"100000000000000000"}' > "$INSTALL/control.json"
req operator POST /local/v1/controls "$INSTALL/control.json"
printf '%s\n' '{"id":"evm-fees-1","chain":"evm","action":"fund_fees","amount":"10000000000000000"}' > "$INSTALL/control.json"
req operator POST /local/v1/controls "$INSTALL/control.json"
printf '%s\n' '{"id":"evm-funding-finality","chain":"evm","action":"advance","blocks":8}' > "$INSTALL/control.json"
req operator POST /local/v1/controls "$INSTALL/control.json"

target/debug/oic-local-stack intent --catalog "$INSTALL/catalog-live.json" \
  --chain evm --id trial-evm-1 --amount 1234567 --max-fee 10000000000000000 \
  --out "$INSTALL/intent-evm.json"
OIC_IDEMPOTENCY_KEY=trial-evm-1 req console POST /v1/intents "$INSTALL/intent-evm.json"
bash scripts/local-stack/approve.sh "$INSTALL" trial-evm-1
req console POST /v1/intents/trial-evm-1/submit
printf '%s\n' '{"id":"evm-payment-finality","chain":"evm","action":"advance","blocks":8}' > "$INSTALL/control.json"
req operator POST /local/v1/controls "$INSTALL/control.json"
req reader GET /local/v1/status
req reader GET /v1/intents/trial-evm-1
req reader GET /v1/export > "$INSTALL/export.json"
```

`approve.sh` fetches the actual package using the separate approval bearer,
prompts for the encrypted key passphrase, runs `oic-approve approve`, displays
the independently decoded recipient/amount/fee/policy, requires confirmation,
then ingests the signed grant. The console bearer cannot ingest approvals.
The script refuses to overwrite saved packages/grants. If interrupted, inspect
the saved grant and server state before manually posting it; do not silently
create another approval. Evidence expires quickly; prepare and approve promptly.

For Solana repeat the same sequence with `chain:solana`, new stable IDs,
`--chain solana --id trial-solana-1 --amount 1234567 --max-fee 20000`, receive
`10000000`, and fee funding `1000000`. Advance 8 slots for funding and payment
finality. Inclusion alone does not release reserved exposure: the simulator's
finality depth must also pass. Use a new `--out` filename for each intent.

Restart after approval or after submit **before** advancing blocks: stop/start
the same installation, discover the intent with `/local/v1/intents`, then inspect
`/v1/intents/{id}`. Repeating submit for an already signed record rebroadcasts
only its stored transaction bytes. It must not create a new payment intent.

## HTTP contract

Requests use `Authorization: Bearer …`. Existing `/v1` routes retain their
actual typed JSON contracts. `POST /v1/intents` requires the caller's stable
`Idempotency-Key`; the request script passes it unchanged. Preserve JSON bytes,
integer strings and u64 values in proxies; do not round-trip through JavaScript
floating-point values. Bodies are bounded at 1 MiB. No CORS/browser-key endpoint
is added.

| Extension | Scope and response |
| --- | --- |
| `GET /local/v1/catalog` | Read: schema_version, profile, institution/environment/proposer/approver IDs; enrolled vaults, wallets, assets, versioned destinations, profiles, public keys, signed policy, event/authority verifying keys and backend_limits |
| `GET /local/v1/intents` | Read: array of persisted IntentId strings from authority state |
| `GET /local/v1/status` | Read: poll broadcaster, reconcile, return `balances` and signed `checkpoints`; balances include chain, head, wallet_balance, beneficiary_balance, holdings |
| `POST /local/v1/controls` | Separate operator bearer: `{id,chain,action,amount}` for `receive`/`fund_fees`, or `{id,chain,action:"advance",blocks:1..64}`; returns `{outcome,status}` |

Catalog and intent discovery do not fabricate console-local custody truth.
`/local/v1/status` is an explicit reconciliation refresh, not a passive health
probe. `/v1/export` contains actual reconciler events/journal/checkpoints and
the D1 authority checkpoint. The event verifying key is public in catalog.

## Durable state and failure behavior

Keep the **entire state directory** together: authority/fence, signer one-time
ledgers and generations, sealed shares, coordinator operation log, broadcaster
submission log, reconciler store/event key, API SQLite/WAL, simulator seeds,
genesis, journal and floor. Reopening SQLite alone is not recovery. Missing
required state fails closed. Starting signers advances their generations.

The local simulator adapter journals real public simulator calls, including
unmined signed submissions. Before an effect, it scratch-replays prior calls,
validates the next call, fsyncs its hash-linked command/outcome and local floor,
then applies it. Reopen replays original seeds/times and checks outcomes/head
hashes. A partial final record is truncated; complete mismatches or rollback
below the retained local floor are rejected. An ambiguous write poisons that
process until restart. This is local crash durability, **not an independent
anti-rollback witness**, power-loss laboratory proof, or safe live backup tool.

Development fault options require explicit `start.sh "$INSTALL" --enable-faults`:

- Operator action `lose_next_submission_ack` loses the next RPC acknowledgement
  **after** its signed transaction is durably submitted. Inspect submission
  uncertainty; recovery may rebroadcast identical bytes only.
- Add `--fail-after-release` to lose a signer response after actual release/share
  output. On restart `ISSUANCE_UNCERTAIN` stays visible, exposure stays reserved,
  and submit refuses fresh signing. There is no automatic reset/retry button.

## Validation and remaining limits

```bash
eto-build env RUSTFLAGS='-C link-arg=-fuse-ld=mold' cargo +1.95.0 test \
  -p oic-service-local-stack --locked --offline --test money_loop -- --nocapture
eto-build env RUSTFLAGS='-C link-arg=-fuse-ld=mold' cargo +1.95.0 clippy \
  -p oic-service-local-stack --all-targets --no-deps --locked --offline -- -D warnings
shellcheck scripts/local-stack/*.sh
```

The public TCP tests cover both chains, independent signed grants, native
signature verification, full process death/reopen while approval and submission
are pending, economic balances/fees, signed export verification, lost RPC ack
recovery, and no signing retry after ambiguous release. They assert one payment
and no duplicate journal entries. They are not D2 consensus/runtime tests.

Supported scope is fixed native transfers to bootstrapped beneficiaries on two
simulators. No real RPC, tokens, arbitrary enrollment, production threshold ECDSA,
distributed signer administration, supported FROST recovery ceremony, SSO,
release packaging or complete RFC004 setup/migration UI is claimed. Simulator
journal limits are 20,000 commands and approximately 60 MiB; each new mutation
replays prior commands, so this is a bounded trial, not a scalable chain store.

Continue with the [independent approval client](approval-client.md),
[network integration contracts](signer-network.md), or
[development checks](development.md).
