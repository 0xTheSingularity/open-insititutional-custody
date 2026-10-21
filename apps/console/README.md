# Institution console

RFC004's initial setup and watch-only discovery slice, built with Next.js App
Router, React, Tailwind CSS and generated shadcn/ui components. This is a local
source-build application, not a production custody control plane.

## Run locally

Requires Node.js 22.18 or newer and npm. Node 22 emits an experimental warning
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

## Supported now

- Name a test workspace and resume it after navigation or process restart.
- Preview a `network,address,label` CSV, then explicitly save valid public
  addresses. Duplicate, malformed and unsupported rows stay excluded.
- Validate EVM address syntax and mixed-case EIP-55 checksums, or 32-byte Solana
  base58 addresses. Network selection and ownership remain operator assertions.
- Filter saved inventory and export public metadata, provenance and blockers as
  unsigned JSON.
- Inspect explicit production blockers with no override.

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
institution login, transfer workflow, approval, signer provisioning, migration
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
stale revisions, cross-site rejection and corrupt-storage failure.

UI primitives live in `src/components/ui`; `components.json` records the shadcn
registry configuration. Add primitives with `npx shadcn add <component>` rather
than introducing another UI library. The shadcn CLI is a build/development
dependency, not part of the console's server request path. At implementation,
the full development audit reports a transitive `braces` advisory through the
CLI with no compatible patched release; do not force-downgrade shadcn to silence
it. The production dependency audit is clean.
