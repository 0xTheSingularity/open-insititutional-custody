# Run the signer-network tests

Exercise a Solana transfer with three separate signer-core processes, private
Unix sockets, and authenticated Commonware TCP connections. The chain is a local
simulator; these tests do not contact Solana devnet or spend funds.

This guide is for developers integrating the RFC003 D1 and D2 libraries. It is not a
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

Loopback startup retains Commonware's production per-IP handshake limits.
Read-only readiness probes share a five-minute budget. Mutation RPCs keep their
ten-second deadline and are never retried.

The D1 process tests, D2 consensus/signing tests and live browser example use
`Transport::start_loopback(context, config, PaddingProfile::Disabled)`. It rejects
any roster containing a non-loopback address and lowers only the peer connection
cooldown, to two seconds. Authentication, IP checks, handshake/channel quotas and
all deadlines stay unchanged. The loopback profile is not production startup
qualification: `start` and `start_with_padding` retain Commonware's recommended
production cooldown.

The loopback cooldown must stay longer than Commonware's one-second dial
interval. When idle, the dialer wakes at the next jittered dial time, clamped
between the dial interval and the cooldown. A one-second cooldown closed that
range, so nodes started together dialed on one shared one-second grid. Two peers
that dialed each other on the same tick then refused each other's handshake on
every retry, until the readiness budget ran out.

Startup is still slow. Every loopback peer shares 127.0.0.1, so each listener
admits one handshake per five seconds from all peers combined. In local runs on
four CPUs, the five-node D1 fixture converged in 8 to 56 seconds.

Shutdown probes bind through `commonware_runtime::Network`, matching the actual
Tokio listener's address-reuse behavior. They also reject a second bind while
the listener is live. On Linux a plain `std::net::TcpListener::bind` can fail
because of TCP `TIME_WAIT` even after clean shutdown; that alone is not evidence
that a listener leaked.

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

## Verify replicated authorization locally

Run authenticated finalization, native re-execution, and signing-boundary tests
without a D1 receipt-signing key:

```sh
cargo +1.95.0 test -p oic-replicated-authority --test contracts --locked
cargo +1.95.0 test -p oic-replicated-authority --test runtime --locked
cargo +1.95.0 test -p oic-replicated-authority --test signing --locked
cargo +1.95.0 test -p oic-service-signer-core --test finalized --locked
cargo +1.95.0 test -p oic-service-signer-net --test consensus --locked
cargo +1.95.0 test -p oic-service-signer-net --test finalized --locked
```

`runtime` runs four genuine Simplex engines with marshal delivery on Commonware's
deterministic simulated network. A two-plus-two partition prevents release;
healing three replicas permits finalization. It also checks retained-floor restart,
keyless catch-up using an existing committee identity, and actor shutdown.

The signer-net `consensus` test uses four genuine engines over authenticated
Commonware TCP, with vote keys distinct from transport keys. A separately admitted
Signer starts after Release and catches up from genesis without a vote key or
committee impersonation. The signed ACL admits certificate channel 2 and
confidential block/backfill channels 4/5 to that Signer, and only backfill channel
5 in the reverse direction. Vote and consensus-resolver channels 1/3 remain
committee-only. `ConsensusHost::start_follower` requires this complete path.

The signer-net `finalized` test connects two independent keyless Signer followers
directly to private IPC cores through clones of their runtimes' `verified_log`
receivers. A reservation alone cannot start either core. After real finalization
of Release, participant-signed MPC messages traverse the same hosts' TCP channel
20; two cores produce a native FROST 2-of-3 Solana signature. The test independently
verifies Ed25519 and the assembled transaction, and reopens each audit floor's
certificate-backed history. IPC cores run in test threads here; the separate D1
test above supplies the multi-process isolation evidence.

`contracts` assembles real three-of-four certificates and rejects tampered blocks,
false execution roots, stale/gapped histories, and lost or rolled-back journals.
`signing` takes capabilities from a synced follower through native EVM and Solana
signature verification. Those two native keys are development one-of-one fixtures,
not a threshold-signing claim.

For embedding, provision the genesis and roster independently, construct
`FollowerConfig` with an independently retained `FinalizedFloor`, and consume only
`Follower::verified_log()` or `Running::verified_log`. The latter publishes `None`
at genesis and a process-local `VerifiedLog` after authenticated re-execution and
sync. `Running::progress` is unsigned status and cannot authorize signing.

Commonware may finalize an ancestor through a descendant certificate without
ever producing a certificate at the ancestor's own height. The follower checks
the real descendant certificate, every parent hash/height and each native state
transition, then syncs the entire checkpoint before publishing its certified tip.
The journal retains that ancestry for replay and checks independent floors even
inside a checkpoint. Marshal redelivery must match its synced block digests.
Checkpoints are bounded to 256 blocks and 4 MiB of canonical journal bytes;
larger uncertified gaps fail closed rather than skipping execution. No fabricated
per-height certificate or peer-supplied state snapshot is used.

Configure a signer with `with_finalized_authority` before loading keys or opening
sessions. Pin its `LogAnchor`, minimum floor, and maximum view age. D2 mode rejects
D1 envelope/receipt entrypoints. `open_finalized_session` requires the exact
finalized Release, not merely a reservation or notarization; `release_finalized`
rechecks the current ordered approver enrollment and freshness before output.
Signer-core receives the local watch source through `with_finalized_log`; gateways
send `OpenFinalized`/`ReleaseFinalized`, never a claimed verified snapshot. Retain
each accepted floor outside the signer's rollback domain.

The current runtime pins one committee and execution registry. It refuses raw D1
reservation and observation commands; a proposer's claimed Allow or settlement is
not chain evidence. Ordered roster activation, committee handoff, verified chain
observations, encrypted deployment storage, and production qualification remain
unfinished. Commonware journals contain confidential candidates and grants; these
libraries do not encrypt those journals themselves.

## Public extensions are bounded host capabilities

`ExtensionHost` binds extensions to the host's actual transport identity and
signed roster. Extensions reserve exclusive channels at or above 1024, use only
reviewed public witness messages, and have bounded nonblocking mailboxes, frame
limits, narrower role checks, and per-peer rolling quotas. Cloned send handles
share their quota. Shareholding nodes cannot host extensions.

`Bridge::with_extensions` retains and stops extension tasks. The host may explicitly
publish an already-verified, ordered D1 receipt through
`Gateway::publish_extension_record`; RPC replies are never implicitly published.
Acknowledgment means queued publication, not consumption or durable monitoring.
`ReceiptMonitor` is the reference read-only consumer. Run its real-socket and
flood-versus-authority-RPC contracts with:

```sh
cargo +1.95.0 test -p oic-node --test extensions --locked
cargo +1.95.0 test -p oic-service-signer-net --test extensions --locked
```

This public profile has no proposer, custom signing, or confidential-data grant
API. Native extension code is cooperative code, not a CPU, memory, filesystem,
or process sandbox. A TEE, durable extension replay, and an independent composition
review are not supplied by this API. The separate padding profile below does not
pad extension channels or grant extensions access to confidential/MPC data.

## Optional fixed-bucket transport padding

`Transport::start(context, config)` remains unpadded. Explicitly enable the local
profile on both endpoints with:

```rust
use oic_node::{PaddingProfile, Transport};
let transport = Transport::start_with_padding(
    context, config, PaddingProfile::FixedBucketsV1,
)?;
```

This wraps **only channels 10, 20 and 21**. Callers still send the original
`PeerFrameV1`/participant-signed point-to-point bytes. `Event.bytes` contains those
exact original bytes after transport unpadding. The inner frame version, roster
epoch, kind and length are checked structurally; signer-core still verifies
participant signatures, scope, generation, replay expectations and release gates.
No canonical CBOR, signature input, payload hash, Class S trait boundary, ACL,
quota, or native `ConsensusFrame` codec is changed. Channels 0–5, 11, 12, 30 and
extensions remain unpadded. Only named-recipient transport sends are available.

The V1 envelope is `OIC/PAD` plus version byte `0x01`, original frame length as
big-endian u32, original encoded frame, then zero padding. Its complete size is
the smallest fitting bucket: **1024, 4096, 16384 or 65552 bytes**. These lengths
exclude the node's fixed 43-byte routing prefix and Commonware's encrypted stream
overhead. The original length field is inside that encrypted stream.

The **padded** length must fit the existing signed channel ACL and absolute
65552-byte application limit on both send and receive. No cap grows implicitly.
An ACL below 1024 cannot send padded traffic. A 1012-byte inner frame fits the
1024-byte bucket; 1013 bytes needs 4096. The largest accepted inner frame is 65540
bytes (65524-byte body), because the padding header consumes 12 bytes of the
existing cap. An oversized declared length is rejected before allocation; decode
borrows the bounded original bytes. Nonminimal buckets, trailing bytes, nonzero
padding and wrong inner version/epoch/kind are rejected before event delivery.

This is **local configuration**, not peer-supplied trust or negotiated fallback.
Mixed padded/unpadded settings reject data before event delivery in either
direction, even if roster convergence succeeds. `send` still acknowledges local
submission only. Restart both endpoints with `FixedBucketsV1` to enable it, or
use `start`/`PaddingProfile::Disabled` on both to roll it back. Do not downgrade
automatically after a delivery timeout.

Run the wire boundaries and actual encrypted TCP contracts with:

```sh
eto-build env RUSTFLAGS='-C link-arg=-fuse-ld=mold' cargo +1.95.0 test -p oic-peer-wire --locked --offline
eto-build env RUSTFLAGS='-C link-arg=-fuse-ld=mold' cargo +1.95.0 test -p oic-node --test sockets padding --locked --offline -- --nocapture --test-threads=1
```

Tests compare unequal-sized native legacy/v0 Solana transaction vectors in equal
wire buckets, preserve exact canonical/signed frames, and reverify participant and
native signatures after real sockets. They also reject malformed, mixed-profile,
oversized and unauthorized traffic while valid traffic continues. These vectors
are not a threshold-protocol or live-chain execution test. Padding reveals bucket
membership and does not hide timing, count, direction, peers, sessions or traffic
correlation. No anonymity, traffic-analysis resistance, measured bandwidth budget,
TEE assumption, independent security review, or complete D3 qualification follows.

## Independent browser approval

`apps/approver-client` builds a separate provisioned Rust/WASM client. It verifies
real fixed-committee certificates, re-executes native blocks, decodes EVM/Solana
candidates, constructs the grant challenge and checks the WebAuthn assertion.
It confirms approval only after the exact grant appears in verified ordered
state, not after a gateway acknowledgement. See its [build, trust and HTTP
contracts](../apps/approver-client/README.md).

### Embed the authenticated node HTTP API

`oic_service_signer_net::http::NodeApi` exposes a running D2 node's synced
history and approval-only proposal intake. Construct it with the node's `Running`
handle, the same independently pinned `Executor`, provisioned `NodeCredential`s,
the exact installed approver origin, and an `oic_authorization_state::Clock`
(`SystemClock` for wall time). Its `router()` returns an Axum router; it does not
start a listener, terminate TLS, enroll users, or issue sessions.

| Request | Contract |
| --- | --- |
| `GET /v1/node/log?after_height=H&after_digest=D` | Authenticated read of one synced journal checkpoint after an exact cursor. Returns `{entries, tip, more}`. Each entry contains hex `block`, hex `finalization`, and optional oldest-first `ancestors`. |
| `POST /v1/node/approvals` | JSON encoding of the existing `Command::Authority(Approve)` only. Requires the session's bound credential, a valid native grant, current local ordered state, and the exact installed `Origin`. `202 {"accepted":true}` means local proposal-queue acceptance, not ordering or approval confirmation. |

Advance the cursor only after authenticating the certificate and replaying every
linked block locally. `tip` certifies the returned page, not an unsigned remote
head. Continue from that verified floor while `more` is true; paginate the second
source as well before comparing rollback floors. A checkpoint holds at most 256
blocks and 4 MiB of canonical journal data. Reads borrow at most two journal
records and never consume replay or mint a signing capability. The offset index
is rebuilt from authenticated replay and grows with the retained journal.

Each session grants access to the **entire confidential institutional log**.
Do not reuse a vault-scoped console token. Provision an unpredictable ASCII token
of 32–512 characters outside the router and give it only the SHA-256 token hash.
`NodeCredential::approver = None` permits reads only; `Some(credential_id)` also
permits submission of that enrolled credential's signed approvals. Enrollment,
signature, policy, freeze and freshness checks still run in native execution and
again during consensus execution. The router cannot Reserve, Release, sign a
transaction, or accept an unsigned state snapshot.

Send one `Authorization: Bearer` token or one `oic_node_session` cookie, never
both. The host owns session issuance, expiry and revocation; configure cookies as
HttpOnly, Secure and SameSite=Strict with a narrow path. Put production listeners
behind operator-managed mTLS/HTTPS. HTTP origins are accepted only for localhost
development. The router sends no-store and anti-framing headers and permits
credentialed CORS only for the configured exact origin. It bounds request bodies,
history queues and concurrent native preflights; a stopped runtime fails closed.
On an ambiguous POST response, reconcile verified history instead of retrying
the mutation automatically.

The default Chromium harness uses a native fixture bridge; it does not run
Simplex. The [opt-in live harness](../apps/approver-client/README.md#live-simplex--native-http--wasm--webauthn)
instead runs four real TCP consensus hosts and two independently replaying HTTP
nodes. Both EVM and Solana journeys verify actual endpoint checkpoints in WASM,
submit a virtual-WebAuthn approval once, and confirm only after its genuine
certificate is published. A barrier in the test proxy proves HTTP 202 and four
durable replica approvals alone cannot confirm the browser view. The native
example then reopens two actual journals against retained floors and verifies
the exact browser grant, state hash and genuine 3-of-4 certificates.

Browser refreshes stop after 64 pages. Cold installations can require repeated
explicit Verify actions, each continuing from the already-verified floor;
non-advancing pagination fails closed. These are development tests with virtual
authenticators and simulator evidence, not live-chain transfers or production
deployment. Independently authenticated installation, retained-floor provisioning,
physical authenticator validation and committee transitions remain required.

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
| N0/N1: pinning, admission, wire, transport | Implemented libraries, seeded Commonware simulation, and real-socket admission tests. |
| N2: D1 signing | Separate-process FROST/Solana simulator E2E plus core tamper/replay/forgery/halt checks. Not the complete A01–A12 matrix over a live chain. No production node launcher, network DKG, automatic roster activation, or ordered generation-fence integration. |
| N3: attestations and audit | Signed attestations/quorums, fsynced signer evidence, Commonware witness journal, authenticated TCP checkpoint following, and offline export reconstruction. D1 checkpoint comparisons detect attributable conflicts, not consensus safety. |
| N4: D2 authority | Pure native re-execution, Simplex/marshal simulation and authenticated TCP, independent keyless followers, synced capabilities, IPC/FROST signing, and bounded Stateright composition. Fixed committee only; committee handoff and independently verified chain observations remain unfinished. |
| N5: hardening/extensions | Bounded public extension API, reference receipt consumer, real TCP flood/RPC tests, and opt-in fixed-bucket content/MPC padding. No TEE profile, traffic-analysis safety result, generic confidential extension grants, or upgrade/rollback qualification. |
| N6: browser approver | Provisioned Rust/WASM client, ordered enrollment, native candidate verification, authenticated D2 history/approval HTTP adapter, and live TCP Simplex-to-Chromium virtual-WebAuthn EVM/Solana journeys with actual journal replay. Signed installation, session/TLS provisioning and physical-device qualification remain outside these libraries. |

No security audit, consensus-safety result, production performance claim, or
production deployment follows from these tests. Production threshold ECDSA and
live-chain clients also remain outside the current implementation.

Continue with the [RFC003 acceptance matrix](../spec/rfc-0003-institution-operated-signer-network.md#17-acceptance-tests),
[development checks](development.md), and the [payment walkthrough](payment-flow.md).
