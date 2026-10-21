# Institution console

RFC004's setup, watch-only discovery and read-only operator sample, built with
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
screens show a service-unavailable explanation rather than sample balances.

`/transfers/new` explores source/destination selection, exact decimal input and
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

There is no chain discovery, observed balance, ownership verification,
institution login, live transfer workflow, approval, signer provisioning, migration
canary or production readiness certification. Watch-only imports neither enroll
authority nor activate receiving addresses. The export is not a signed audit or
reconciliation checkpoint.

`/console-api/v1/*` owns this local metadata only. The RFC002/RFC003 custody API
and independently distributed verifier remain separate integration work. Never
add private-key collection, an approval vote or a generic Sign control here.

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
