# Run the D1 signer-network tests

Exercise a Solana transfer with three separate signer-core processes, private
Unix sockets, and authenticated Commonware TCP connections. The chain is a local
simulator; these tests do not contact Solana devnet or spend funds.

This guide is for developers integrating the RFC003 D1 libraries. It is not a
production installation procedure or a claim that all RFC003 phases are complete.

## Prerequisites and command

Use Linux, a native C/C++ build toolchain including CMake, and Rust 1.95 or newer.
The network packages use edition 2024 and Commonware `=2026.9.0`. Other packages
retain their existing edition. Cargo needs registry access for the initial locked
dependency download. Tests bind ephemeral loopback TCP ports and create disposable
private files; no credentials, external RPC service, or environment file is needed.

From the repository root:

```sh
cargo test -p oic-service-signer-net --test network --locked
```

Three scenarios run. A fourth test is an ignored child-process entrypoint that
the scenarios invoke explicitly, not an unimplemented acceptance test.

Loopback startup can take several minutes under Commonware's production per-IP
handshake limits and retry cooldowns. Read-only readiness probes share a five-minute
budget. Mutation RPCs keep their ten-second deadline and are never retried.

| Scenario | Assertions |
| --- | --- |
| Native SOL transfer | Two selected child cores each produce one share after release; the third produces none. The simulator verifies the assembled transaction and credits the recipient. Durable ledgers bind consumption to the native payload; signed core audit chains verify. |
| Signer control unavailable | An actual network request times out before release. The reservation aborts, exposure clears, and no signer produces a share. |
| Release reply lost after commit | The real authority commits release but its response is withheld. The coordinator records `IssuanceUnknown`, retains exposure, and neither retries release nor aborts. No receipt reaches the cores, so they produce no shares. |

DKG is offline fixture provisioning. The parent drops fixture signers before
starting any network reactor. During the network run, only the child processes
load shares and participant private keys. Private fixture files contain sealed
share ciphertext, not plaintext shares. Fixture keys and sealing seeds are
development constants; they must never be used for real assets.

## Embedding responsibilities

The implementation is split across these libraries:

| Package | Interface and responsibility |
| --- | --- |
| `oic-membership` | `validate_roster` checks admin signatures, scope, linked epochs, activation anchors, key purposes, topology, trust-domain placement, and ACL ceilings. `SignedRoster::namespace()` derives the network namespace. |
| `oic-peer-wire` | Bounded canonical frames, participant-signed MPC messages, and typed session/authority RPC controls. Backend MPC types cannot use general serde or public/confidential encoders; Debug output is redacted. |
| `oic-node` | `Transport::start` runs Commonware lookup with roster admission, IP checks, per-channel sizes/quotas, and epoch/hash convergence. `sender()` returns a cloneable handle; sends always name one recipient. |
| `oic-service-signer-core` | `SignerCore::open`, `control`, `deliver`, `outbound_at`, and signed `halt`; private Unix IPC; local envelope verification, participant authentication, FROST package reconstruction, one-time state, and release gating. |
| `oic-service-authority-rpc` | `AuthorityEndpoint` supports local or networked D1 authority access. The server accepts authenticated gateways only on channel 12. No administration endpoint or mutation retry is added. |
| `oic-service-signer-net` | `Bridge` routes authenticated transport events to IPC or the authority handler. `Gateway` supplies remote authority and signer clients to `SigningCoordinator`. |

Supply Commonware's production Tokio `Runner` context and supervise its tasks and
socket binding. Run blocking coordinator/client calls outside the bridge reactor.
`Bridge::run` is a spawnable Tokio future. Stop it explicitly and await shutdown.
Transport submission acknowledges local acceptance, not delivery. Only directed,
idempotent MPC frames are retransmitted; Open, Reserve, and Release are not retried.

Provision and retain trust outside the network:

- Compare the genesis roster hash independently. For later epochs, supply the
  trusted active predecessor, authority-committed hash, and activation time.
  Lookup methods and quorum collectors assume the roster was validated first.
- Keep transport, participant, attestation, authority receipt, operator, audit,
  administrator, approval, and share keys purpose-distinct. Constructors reject
  observable aliases; provisioning must compare keys not carried in their inputs.
- Open signer ledgers, generation stores, authority stores, and audit logs against
  their independently retained rollback floors/checkpoints. Local disk alone
  cannot detect whole-host rollback.
- Put IPC sockets in private mode-0700 directories. The server creates mode-0600
  sockets, bounds requests, and refuses to replace an existing endpoint.
- Supply a dedicated-key `FileAuditLog` to each core. Release output is withheld
  if its evidence cannot be fsynced. A signed local halt remains effective across
  restart; its monotone sequence also needs an independent floor.
- Restart transports, bridges, and RPC endpoints on roster activation. This
  implementation does not order or automatically apply roster updates. A removed
  participant still holds its share; removal alone is not cryptographic revocation.
- Reopening `Signer` advances its durable generation. The core refuses to start
  unless that generation matches the validated roster. Generation enrollment and
  ordered fencing are operator integration work, not an automatic restart path.

Attestations are available through `AttestationQuorum`. Its expected inputs must
come from trusted candidate, evidence, roster, and policy state. Only
`require_allow(now)` is an allowing gate; a reached Deny/RequireApprovals quorum
does not authorize anything. Disagreement is sticky within a collector and retains
both signed bodies. The caller must persist quarantine, alert, and conflict evidence.
This remains opt-in and never replaces signer-local evaluation.

## Checks and current limits

```sh
cargo test --workspace --locked
RUSTFLAGS='--cfg commonware_stability_BETA' \
  cargo check -p oic-service-signer-net --lib --locked
```

CI uses Rust 1.95 and the Commonware BETA gate. The workspace's inherited Rust
1.85 declaration is not a verified workspace minimum: the existing locked `uuid`
dependency requires a newer compiler. Use 1.95 or newer for this composition.

| RFC003 area | Current boundary |
| --- | --- |
| N0/N1: pinning, admission, wire, transport | Implemented libraries and real-socket tests. No seeded Commonware deterministic simulation suite. |
| N2: D1 signing | Separate-process FROST/Solana simulator E2E plus core tamper/replay/forgery/halt checks. Not the complete A01–A12 matrix over a live chain. No production node launcher, network DKG, automatic roster activation, or ordered generation-fence integration. |
| N3: attestations and audit | Signed attestations/quorums and fsynced signer evidence. No network witness/checkpoint follower, Commonware-journal migration, or complete independent export/reconstruction. |
| N4: D2 authority | Roster count/placement checks only. No Simplex engine, replicated transition, marshal follower, or D2 release evidence. D1 remains a trusted single authority. |
| N5: hardening/extensions | Channel ACLs, quotas and BETA gate exist. No extension subscription service, TEE profile, padding, or upgrade/rollback qualification. |
| N6: browser approver | Not implemented. The existing independent approval CLI is not a WebAuthn browser light client. |

No security audit, consensus-safety result, production performance claim, or
production deployment follows from these tests. Production threshold ECDSA and
live-chain clients also remain outside the current implementation.

Continue with the [RFC003 acceptance matrix](../spec/rfc-0003-institution-operated-signer-network.md#17-acceptance-tests),
[development checks](development.md), and the [payment walkthrough](payment-flow.md).
