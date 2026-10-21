# Institution console

RFC004's setup, watch-only discovery, local simulator workflow and read-only sample, built with
Next.js App Router, React, Tailwind CSS and generated shadcn/ui components. The
default is a local source-build application, not a production custody control plane.

## Run locally

Requires Node.js 22.18 or newer within the Node 22 release line, and npm. Node 22 emits an experimental warning
for its built-in SQLite API.

From `apps/console`:

```sh
npm ci
npm run build
OIC_CONSOLE_STATE_DIR="$HOME/.local/state/oic-console" npm start
```

Open `http://127.0.0.1:4174/setup` **on the machine running the server**. For a
remote machine, forward port 4174 over SSH rather than exposing the service on
a public interface. `npm run dev` runs the same app in development mode; it also
requires `OIC_CONSOLE_STATE_DIR`.

The listener binds only to IPv4 loopback. Host, origin and mutation-header checks
reject browser cross-site requests. These checks are not institution
authentication; local processes can access the service. Do not expose it through
a reverse proxy or use it for production custody. `OIC_CONSOLE_ORIGIN` can set
the expected local port when explicitly overriding Next's port; it does not
authorize remote hosts.

## Hosted sample

Set the server-side environment variable `OIC_CONSOLE_DEMO=1` for a Vercel sample
deployment. Use `apps/console` as the project root, the Next.js framework preset,
Node.js 22.x, `npm ci` and `npm run build`. Do not set `OIC_CONSOLE_STATE_DIR`,
configure custody credentials or connect a production backend to this project.

Demo mode serves fixed, labeled public examples instead of opening SQLite.
Same-origin CSV previews remain available, but both workspace and inventory
writes return 403 even if a state directory is configured. The UI disables
saving and identifies the sample on every page. Filters and theme preferences
work; exports contain only sample fixtures and identify that provenance.
Previews are not persisted. Use public test addresses only, never private data,
keys or credentials. This does not supply institution authentication or custody
integration. Without `OIC_CONSOLE_DEMO=1`, the loopback-only boundary still
applies.

The hosted sample includes `/overview`, `/vaults`, `/transfers`, `/approvals`,
`/destinations`, `/operations` and `/activity`. Vaults, transfers and operational
cases have stable detail URLs. These show historical illustrative holdings
and four transfers, not simulator runs or live API observations. The fixture
snapshot supplies a fixed as-of time and an unverified sample sequence; reload
does not advance it. No signed grants, transaction bytes, policy epoch, expiry
or verified checkpoints are supplied. Approval and custody controls stay disabled.

The examples distinguish awaiting approvals, uncertain submission, chain
finality and journal reconciliation. Uncertain submission retains principal and
maximum fee exposure without a blind retry or cancellation. Native ETH/SOL
quantities stay decimal base-unit strings and render without floating-point
conversion. Search/status filters survive detail navigation and Back through
non-secret URL parameters. The watch-only inventory export deliberately excludes
treasury illustrations; it is not an audit export. In local mode, these operator
screens use the local custody bridge below or show an unavailable connection.

In the hosted sample, `/transfers/new` explores source/destination selection, exact decimal input and
review without creating a request. It rejects zero amounts, excess precision,
duplicate sample references and amount-plus-fee exposure above the sample
available balance. Switching networks clears amount and fee. Review displays
full addresses, registry version, network/asset identity, base units and the fee
ceiling. It is not policy evaluation or transaction simulation. Input stays in
component memory; no draft, idempotency key, grant or reservation is created.
Do not enter private business data. Creation remains disabled.

`/administration` links to people/access, policies, signers, recovery,
integrations and migration. These are public capability-requirement previews,
not authorized administrative read models. They invent no active users,
policies, grants, signer health or recovery results. Mutations and verifier
handoffs remain disabled with their prerequisites visible. Migration links to
the existing watch-only inventory; no canary is claimed.

Searches use non-secret URL parameters; vault/case details and transfer review
preserve the applicable list filters on Back. Activity downloads include the
current filter, fixture provenance and explicit unsigned/incomplete markers.
They are scenario notes, not sequenced events or audit proof. The mobile shell
uses a shadcn Sheet with keyboard dismissal and the same navigation as desktop.

## Local simulator operator workflow

`/custody-api/v1/*` connects the local operator screens to the runnable D1
development stack described in [local-stack.md](../../docs/local-stack.md).
It uses actual persisted intents, enrolled wallets/destinations, reconciled
holdings and operation lifecycles. There are no fallback sample balances.

Bootstrap and start that stack separately, then, from `apps/console`, load
**only** its console handoff into the Next server:

```bash
set -a
. "$INSTALL/handoff/console.env"
set +a
OIC_CONSOLE_STATE_DIR="$HOME/.local/state/oic-console" npm start
```

The local flow is:

1. Inspect enrolled receiving addresses and settled/reserved/available holdings
   in Overview or Vaults. Receive test funds and fund native fees through the
   stack's separate operator terminal, then refresh custody state.
2. Create a native EVM/Solana request with a business reference, exact amount,
   versioned beneficiary and fee ceiling. Review full addresses and base units.
3. Download the approval package from the transfer detail. Use the separately
   trusted `oic-approve` client and approval capability outside Next/browser.
4. Refresh to observe the signed grant. Request local submission, then use the
   operator terminal to advance simulator finality. Submission is not finality.
5. Refresh holdings/checkpoints and download operation evidence or the custody
   export. Restart the same stack stores without creating replacement intents.

Before creation, the console retains the immutable intent and idempotency key
under versioned browser storage, scoped to the installation's public event key.
Web Locks coordinate tabs on the same origin; fresh intent discovery checks for
an existing business reference. An unknown create outcome retains its identity
through reload and provides inspection, not retry/replacement. Only an acknowledged
or subsequently discovered exact record lets the operator explicitly prepare a
new request. This browser aid is not an atomic global reference registry: other
API clients, browsers or origins must coordinate their own requests.

The retained request contains public test payment details, not a credential.
Do not clear browser storage to bypass an unknown outcome. Signed/uncertain
operations have no new-signing retry or cancellation control. Cancellation is
confirmed explicitly and is only available before dispatch.

Configure `OIC_CONSOLE_CUSTODY_TOKEN` on the Next server only, using the stack's
scoped Read/Propose/Submit credential. `OIC_CONSOLE_CUSTODY_ORIGIN` defaults to
`http://127.0.0.1:8787`; only an IPv4 loopback HTTP origin without a path, query,
or embedded credentials is accepted. Never use a `NEXT_PUBLIC_` variable or
configure these values in the Vercel project. All bridge routes return 403 when
`OIC_CONSOLE_DEMO=1` or `VERCEL` is set, even if a token is configured.

The route allowlist covers catalog/intents/status reads, immutable intent creation,
preview, pre-dispatch cancellation, submission, operation/evidence reads,
refresh, balances, event replay, and export. It deliberately excludes approval
grant ingestion, simulator operator controls, and administrative updates. The
independent verifier, encrypted approval key, and approval bearer remain outside
Next and the browser. The bridge provides no institution login: local processes
can access the development operator capability through the loopback console.

Intent creation requires a caller-retained `Idempotency-Key`; the bridge never
generates one or retries a request. Any failed mutation response marks the
outcome unknown and instructs the operator to inspect existing records first.
Redirects are not followed. JSON is forwarded without reserialization so u64
sequences and signed material do not lose precision. Display models reject unsafe
JavaScript integers, malformed quantities and mismatched identity bindings.
The browser does not verify signatures. Use independently pinned trust for
approval/evidence verification. Event download is limited to the first 1,000
events; the UI does not claim a complete verified event stream. The service export
is not a cross-store atomic backup.

Browser validation exercised both chains through creation, independent CLI
approval, submission, full-stack restart while pending, finality, fee/payment
accounting and evidence download. A lost browser create acknowledgment recovered
the original Solana intent on reload without another create. This is a D1/local
test-money trial, not production or complete RFC004 acceptance.

## Supported now

- Name a test workspace and resume it after navigation or process restart.
- Preview a `network,address,label` CSV, then explicitly save valid public
  addresses. Duplicate, malformed and unsupported rows stay excluded.
- Validate EVM address syntax and mixed-case EIP-55 checksums, or 32-byte Solana
  base58 addresses. Network selection and ownership remain operator assertions.
- Filter saved inventory and export public metadata, provenance and blockers as
  unsigned JSON.
- Inspect explicit production blockers with no override.
- Choose Light, Dark or System from the header's Appearance menu. System is the
  default; explicit choices persist in this browser, independently of workspace
  state. System follows changes to the operating system's color preference.

## Appearance

Components remain shadcn/ui. The visual reference is the live
[Singularity product UI](https://the-singularity-ui-kappa.vercel.app/): an open
canvas, quiet dividers, rounded panels, 8px button corners and neutral actions.
Light mode uses white surfaces; dark mode uses warm charcoal with off-white
text. Separate success/warning text, surface and border tokens retain status
meaning. Selected navigation uses a filled background and `aria-current`;
status labels and icons do not rely on color alone.

Clash Grotesk headings and the star mark are self-hosted under `public/`, from
the Singularity design repository (`brand/dist/brand/fonts/clash-grotesk-var.woff2`
and `brand/dist/brand/logo/mark.svg`). Body text uses system sans-serif;
identifiers and exact quantities use system monospace. No Atlaskit components,
external font requests or additional UI library are used.

`next-themes` sets the class before hydration using the request's CSP nonce.
Theme choice is stored under `oic-color-theme` in browser local storage. It never
changes permissions, readiness or the local metadata API.

## Inventory and storage

Supported network identifiers: `ethereum-mainnet`, `ethereum-sepolia`,
`solana-mainnet`, `solana-devnet`. Each import accepts 1–500 rows and an HTTP JSON
body up to 128 KiB. The file picker limits files to 120 KB to leave room for JSON
encoding. Quote CSV labels containing commas. Labels and workspace names must
fit 80 UTF-8 bytes without control characters.

State lives in `console.sqlite` in the configured directory, with private
directory/file permissions. Only public setup metadata is stored, never browser
keys or credentials. Revision checks reject stale writes; an ambiguous failure
pauses writes until saved state reloads. Back up the state directory while the
console is stopped. Corrupt storage reports an error rather than replacing it.

## Not implemented

There is no real-RPC chain discovery, ownership verification, institution login,
production transfer workflow, browser approval, signer provisioning, migration
canary or production readiness certification. The native EVM simulator uses a
development 1-of-1 key; Solana uses co-resident 2-of-3 FROST. Watch-only imports
neither enroll authority nor activate receiving addresses. The watch-only export
is unsigned metadata, distinct from local-stack operation/journal evidence.

`/console-api/v1/*` owns this local metadata only. The separate local custody
bridge supplies local simulator records but is not an independent verifier.
Never add private-key collection, an approval vote or a generic Sign control
to either API.

## Check

```sh
npm run check
npm test
npm run build
npm audit --omit=dev
```

The tests exercise the route-handler boundary using disposable SQLite state:
preview/save/resume/export, duplicate rejection, checksum and size boundaries,
stale revisions, cross-site rejection and corrupt-storage failure. Demo coverage
checks fixture provenance, temporary previews, blocked writes and isolation
from a configured local store. Exact-decimal tests cover ETH/SOL base units
beyond JavaScript Number precision and rejection rather than rounding.

UI primitives live in `src/components/ui`; `components.json` records the shadcn
registry configuration. Add primitives with `npx shadcn add <component>` rather
than introducing another UI library. The shadcn CLI is a build/development
dependency, not part of the console's server request path. At implementation,
the full development audit reports a transitive `braces` advisory through the
CLI with no compatible patched release; do not force-downgrade shadcn to silence
it. The production dependency audit is clean.
