# Independent D2 approver

This is a provisioned Rust/WASM light client, separate from `apps/console`.
It verifies Commonware `2026.9.0` ed25519 Finalizations and reexecutes complete,
contiguous authority blocks using the native `oic-replicated-authority::Executor`.
It starts from the installed empty genesis, not a serialized state snapshot.
The browser is neither a consensus voter nor a chain signer.

## What is implemented

- Institution, environment, genesis, fixed roster, admin quorum, registry,
  adapter builds, origin/RP and a minimum finalized floor are installed inputs.
- Untrusted artifacts cannot replace these inputs. Invalid certificates, epochs,
  bodies, state roots, parent links, rollback and stale views fail closed.
- `IndependentVerifier` decodes actual EVM/Solana transfer bytes and computes
  the preview hash. The UI displays full addresses, asset/network, registry
  version, amount/base units/decimals, maximum fee, purpose, policy, warnings
  and recorded approval count. It does not display a console-supplied summary.
- WASM constructs an exact-candidate grant and its challenge. JavaScript calls
  `navigator.credentials.get` with the installed raw credential ID, RP ID and
  `userVerification: 'required'`. WASM verifies the returned assertion and
  executes the native ordered `Approve` transition before submission.
- A gateway acknowledgement is not confirmation. Only the exact submitted
  grant, found in reexecuted certificate-verified state under the same ordered
  credential enrollment, produces **Approval recorded**.
- The bounded WebAuthn parser accepts Chromium's optional
  `other_keys_can_be_added_here` marker only with its exact emitted string.
  Other unknown/duplicate fields remain unsupported; the signature still covers
  the original complete JSON bytes. This is stricter than WebAuthn's general
  forward-compatible client-data parsing and needs qualification per platform.
- Commonware batch verification uses a CSPRNG seeded with real browser
  `crypto.getRandomValues` through `getrandom 0.2.17/js`. Artifact hashes are
  never RNG seeds. Native callers must supply an unpredictable seed themselves.

## Supported profile and limits

This initial profile supports a **fixed committee and exact-candidate intents**.
It rejects bounded-transfer intents, epoch changes and uninstalled adapters.
Changing the committee, registry or trust configuration requires independently
approving and installing a new build. It does not follow roster transitions,
implement D1 receipts, import checkpoints, or implement Exoware/QMDB proofs.
It retains no `VerifiedLog` and offers no snapshot import.

The floor cannot decrease during a running client. The build embeds a minimum
height/digest; replay must reach that exact point before approval. A restart
replays from genesis again. **Cross-restart protection extends only to the
independently provisioned floor**, not the last height observed by a previous
tab. Institutions must retain/reprovision newer floors externally when needed.
Browser storage is not trusted and cannot advance or reset the installed floor.
The local clock is assumed trustworthy; age limits cannot detect a newer block
withheld by both witnesses within the allowed age. The authority must still
enforce current freeze/policy/credential state when ordering approval.

Use an independently installed distribution with a trustworthy origin, HTTPS,
WASM, `BigInt`, WebAuthn/ES256, streaming fetch and modern abort APIs. The exact
installed origin must be admin-enrolled for the dedicated approval credential;
login credentials must be separate. The RP/platform combination needs testing
on each deployed browser/OS. The harness covers Chromium's **virtual**
authenticator, not physical user verification or hardware attestation. No
attested-device/AAGUID enrollment or signed extension/desktop installer is
implemented here.

Build hashes are an external installation gate. The page cannot prove its own
integrity: malicious JavaScript could lie about any self-check. Institutions
must independently authenticate the source, provision digest, installed build
manifest and origin, and prevent the console/server from rewriting installed
files. The scripts emit/check hashes; **they neither sign a release nor make an
ordinary remotely served page an independently trusted installed application**.
Reproducibility here means repeatable release output with the same source,
provision, toolchain and dependencies; cross-machine reproduction is untested.

Complete blocks contain confidential business data, potentially for multiple
vaults. Institution access control must authorize those reads. Fetch uses a
separate session (`credentials: 'include'`); the passkey is approval-only.
There is no vault projection or authentication/session service in this unit.

## Build and independently check an installation

Use Rust `1.95.0`, target `wasm32-unknown-unknown`, and
`wasm-bindgen-cli 0.2.117`. Install those through the normal user toolchain.
The optional runner wrapper `eto-build` limits build resources when available;
otherwise the script uses `CARGO_BUILD_JOBS` (default 2). It derives the root
from its own location and explicitly builds into the root `target/` directory.
It preserves the Commonware `commonware_stability_BETA` gate and does not pass
native mold flags to the WASM linker.

`Provision` in `src/lib.rs` is the authoritative JSON schema. It contains public
trust material only: authority/admin configuration, registry, approved adapter
manifest hashes, admin-signed roster and roster genesis, encoded empty block
genesis and digest, minimum floor, exact origin/RP, view/grant lifetimes, mode
and identity-to-raw-WebAuthn-credential-ID mapping. Ordered credential changes,
including public keys, roles and people, still have to be replayed. No network
or browser API can supply a provision to the WASM constructor.

Obtain the following digest independently; computing it from a downloaded
untrusted provision is not authentication:

```sh
apps/approver-client/build-web.sh /absolute/provision.json \
  "$INDEPENDENTLY_PUBLISHED_PROVISION_SHA256" /absolute/installed-build
apps/approver-client/verify-install.sh /trusted/independent/SHA256SUMS \
  /absolute/installed-build
```

The build script checks the provision digest, compiles a release WASM module,
runs the matching bindings generator and emits `SHA256SUMS`. Authenticate and
publish/sign that manifest outside the console's control. Verify the installed
files **before serving/opening them**, using the independent manifest. A
manifest downloaded beside the application is not an independent trust anchor.
Unprovisioned WASM builds compile but refuse to construct a browser client.

## HTTP integration contract

The form accepts two distinct witness URLs, an approval-package URL, an approval
gateway URL and the ordered approval identity. Endpoints require HTTPS except
for the explicit localhost development profile. The UI uses no redirects,
requests uncached reads, bounds response sizes and does not retry a submission
after an ambiguous failure. Configure access controls/CORS for the installed
origin; avoid storing credentials in URLs. The installation's serving channel
must prevent framing (for example `X-Frame-Options: DENY` and an HTTP CSP
`frame-ancestors 'none'`); a meta CSP cannot enforce `frame-ancestors`. The
browser harness serves `X-Frame-Options: DENY`.

For each witness, the client sends:

```text
GET <witness-url>?after_height=<locally-verified-height>&after_digest=<0x-digest>
```

The JSON response is:

```json
{
  "entries": [{
    "ancestors": ["0x<encoded-parent-1>", "0x<encoded-parent-2>"],
    "block": "0x<Commonware-encoded-certified-tip>",
    "finalization": "0x<Commonware-encoded-Finalization-of-tip>"
  }],
  "tip": {"block": "0x<Commonware-encoded-AuthorityBlock>", "finalization": "0x<Commonware-encoded-Finalization>"},
  "more": false
}
```

`entries` must be a contiguous suffix page after the requested floor, with at most
256 checkpoint entries per response. `ancestors` is optional and omitted when
empty, preserving the single-block encoding. A checkpoint contains at most 256
blocks including its certified tip, and its canonical encoding must be at most
4 MiB (the native follower's limit). Each block is bounded to 128 KiB and the
certificate to 64 KiB. The tip's certificate authenticates the full ancestry
through linked parent hashes; ancestors need not have their own certificates.
WASM authenticates the actual tip, reexecutes every block against private cloned
state, checks any retained floor inside the ancestry, and publishes the new
state/floor only when the **entire checkpoint** passes.

The mandatory response `tip` marks the **certified page tip**, not an unsigned
claim about the latest remote head. It contains a certified block and its
certificate. After applying checkpoint entries, the client authenticates
that marker as an exact repeat of its verified tip. An ahead marker without its
ancestry or an older marker fails; an empty suffix with the current marker is
valid. HTTP responses are bounded to 10 MiB and WASM checkpoint JSON to 9 MiB
to allow hex-encoded transport of the 4 MiB canonical record. Missing/reordered/
altered ancestors, wrong digests or an over-limit response block approval. There
is no skip-to-tip or trusted-state checkpoint import. `more` must be a boolean;
when true, the client continues from its WASM-verified height/digest. Each refresh
is limited to 64 pages. A non-advancing page with `more: true` fails closed.
After the limit, explicit verification continues from the retained verified floor.

Both sources are checked through the same verifier. The second may advance the
client, but cannot roll it back. Distinct URLs do not prove independent hosting;
institutions must choose independent witnesses. Neither source can inject a
verified snapshot or a trusted `verified` flag.

The package endpoint returns the existing `ApprovalPackage` JSON including
native candidate/evidence bytes. The gateway receives `POST` of the existing
serialized `Command::Authority(AuthorityCommand::Approve { intent, grant })`
with `Content-Type: application/json`. A successful HTTP response means only
accepted for processing. The UI polls witnesses and confirms only after
verified ordering; timeout means reconcile the log before retrying.

`oic-service-signer-net::http::NodeApi` implements these log/approval routes at
`/v1/node/log` and `/v1/node/approvals`. The host embeds the router and provisions
unpredictable full-institution-log sessions externally. Bearer and
`oic_node_session` cookie are alternatives, never simultaneous. An approval
session binds one ordered credential; read-only sessions cannot submit. Exact
installed Origin is required on POST. HTTP 202 is local enqueue only. This is
not a login service, TLS terminator, package server, or general proposer API.

## Validation

From the repository root:

```sh
eto-build env RUSTFLAGS='-C link-arg=-fuse-ld=mold' \
  cargo +1.95.0 test -p oic-approver-client --all-targets --locked --offline

# Development fixtures only. Never install this test provision for real funds.
eto-build env RUSTFLAGS='-C link-arg=-fuse-ld=mold' \
  cargo +1.95.0 run -p oic-approver-client --example browser-fixture \
  --locked --offline -- generate evm .amp/in/approver-evm
apps/approver-client/build-web.sh "$PWD/.amp/in/approver-evm/provision.json" \
  "$(sha256sum .amp/in/approver-evm/provision.json | cut -d' ' -f1)" \
  "$PWD/.amp/in/approver-evm-web"
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
  node apps/approver-client/tests/browser.mjs \
  .amp/in/approver-evm .amp/in/approver-evm-web .amp/in/artifacts/approver evm
```

Repeat with `solana` and matching directories. Use an installed Playwright and
Chromium; the harness starts a temporary localhost server on port 4317, fixes
the clock to the fixture epoch and imports an explicitly insecure fixture ES256
key into a virtual authenticator. It captures desktop/mobile, pending, recorded
and blocked states and writes JSON evidence. Its gateway executes the real
native authority transition and creates real 3-of-4 Commonware Finalizations.
The approval is an ancestor at height 2, delivered without its own certificate;
only a height-4 descendant certificate is published. The harness withholds that
checkpoint to prove a gateway acknowledgement cannot confirm, then publishes it
to exercise atomic browser replay and confirmation. Missing, reordered and
altered ancestors are rejected without advancing the floor in native and WASM
checks.

**This default fixture bridge is not a live Simplex network.** Native tests exercise
non-roster/epoch/body/state/rollback rejection, pinned configuration, native
addresses/amounts, WebAuthn scope/UV, stale/frozen/removed/self/duplicate approval
and changed policy/destination rejection. These checks are not a claim that all
RFC003 deployment requirements are complete.

### Live Simplex → native HTTP → WASM → WebAuthn

For the automated both-chain entry point, see
[the D2 development check](../../docs/local-stack.md#check-the-d2-development-path):

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
  bash scripts/local-stack/check-d2.sh "$HOME/.local/share/oic-d2-check-1" both
```

It requires a fresh private directory, checks prerequisites without installing
global tools, preserves complete failure logs, and stops its native child on
failure/interruption. It checks the local build manifest for consistency, not
independent distribution trust. The following commands expose its individual
stages for diagnosis.

The opt-in harness uses four actual `ConsensusHost`s over TCP with distinct
transport and vote keys. Bootstrap, credential enrollment and the browser grant
are proposed once to an actual engine; Simplex produces all certificates.
Two independently replaying nodes serve the real `NodeApi` routers. No
`Committee::certify` call occurs on this path. Current-clock fixture inputs have
a bounded 900-second evidence window; freshness checks remain enabled.

The example explicitly selects `Transport::start_loopback`: every admitted address
must be loopback, and only the connection retry cooldown is shortened, to two seconds.
Identity/IP checks and handshake/channel quotas remain enabled. This local startup
profile does not qualify production connection timing or change normal defaults.

Use a **new directory per run**. In one terminal start:

```sh
eto-build env RUSTFLAGS='-C link-arg=-fuse-ld=mold' \
  cargo +1.95.0 run -p oic-service-signer-net --example approver_network \
  --locked --offline -- "$PWD/.amp/in/approver-live-evm" evm
```

As soon as `provision.json` exists, build the matching WASM installation:

```sh
apps/approver-client/build-web.sh "$PWD/.amp/in/approver-live-evm/provision.json" \
  "$(sha256sum .amp/in/approver-live-evm/provision.json | cut -d' ' -f1)" \
  "$PWD/.amp/in/approver-live-evm-web"
# Wait for endpoints.json (all four replicas have synced enrollment).
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
  node apps/approver-client/tests/browser.mjs .amp/in/approver-live-evm \
  .amp/in/approver-live-evm-web .amp/in/artifacts/approver-live/evm evm --live
```

Repeat using `solana` and fresh directories. The proxy forwards actual native
HTTP responses and records them without the session token. Its test-only
publication barrier retains the last genuine certified tip after POST: even
after HTTP 202 and four native replicas durably order the exact grant, the
browser must stay pending. Releasing the barrier exposes actual endpoint
checkpoints and permits confirmation. No publication barrier exists in NodeApi.
Live mode uses the real browser clock, not the fixed fixture clock.

The browser writes a `stop` file on exit. The native example then shuts down
all hosts, reopens two actual retained follower journals, verifies their genuine
3-of-4 certificates and confirms approval survives disk replay. Keep
`approval-observed.json`, `journal-replay.json`, the recorded HTTP responses,
browser JSON evidence and inspected screenshots together. Test keys, local HTTP,
virtual user verification and provision generation are **development evidence**,
not production deployment, independently trusted distribution, or physical
authenticator attestation. These sessions authorize the full confidential log;
the local test proxy does not implement a production authentication service.
