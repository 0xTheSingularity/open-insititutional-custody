# Security policy

Open Institutional Custody is a **development preview** (see
[THREAT_MODEL.md](THREAT_MODEL.md)). We take the custody protocol's security
claims seriously, and we want researchers to hold us to them. If a security
claim in [THREAT_MODEL.md](THREAT_MODEL.md) is not actually enforced by the code,
that is a finding we want to hear about.

## Supported versions

This project is pre-release. Only the latest `0.1.x` line and the current `main`
branch receive security fixes.

| Version | Supported |
| --- | --- |
| `0.1.x` (latest) | Yes |
| `main` (unreleased) | Yes |
| anything older | No |

## Reporting a vulnerability

Please report security issues **privately**, not as a public GitHub issue.

Use **GitHub private vulnerability reporting** (Security Advisories) for this
repository:

> **https://github.com/0xTheSingularity/open-insititutional-custody/security/advisories/new**

<!--
  MAINTAINER ACTION REQUIRED before this policy is live:
  1. Enable private vulnerability reporting for the repo:
     Settings -> Code security and analysis -> Private vulnerability reporting -> Enable.
     Until this is enabled, the "Report a vulnerability" button / advisory link
     above will not work.
  2. Add a real monitored security contact below (email or form). The address
     here is a PLACEHOLDER and must be replaced with one the maintainer watches.
-->

If private advisories are not yet enabled, or you cannot use GitHub, contact the
maintainer directly:

> **Security contact: `<REPLACE-WITH-A-REAL-MONITORED-ADDRESS>`**
> *(Maintainer: replace this placeholder with a real, monitored email or form
> before publishing. Do not leave a placeholder address in a live security
> policy.)*

In your report, please include:

- The affected component and, where possible, the exact `file:line` in this repo.
- A description of the issue and its impact: what an attacker can do, and how.
- Steps to reproduce — ideally a failing test, an `oic demo` variation, or a
  minimal command sequence.
- The commit, toolchain, and platform you tested on.

Keep keys, shares, passphrases, and secret files out of your report (this mirrors
the contribution guidance in the README).

### What to expect

This is a volunteer-maintained preview, so these are aspirations, not contractual
guarantees:

- **Acknowledgement:** we aim to acknowledge a report within 5 business days.
- **Assessment:** we aim to give an initial assessment (valid / needs-info /
  out-of-scope) within 10 business days.
- **Fix and disclosure:** we will work with you on a fix and coordinate public
  disclosure once a fix is available or a decision is made. Please give us a
  reasonable window before disclosing publicly.

### Recognition, not cash

Because this is a development preview where **no real funds move** (the chains are
simulators), there is **no paid bug bounty** at this time. We offer recognition
instead: valid, good-faith reports are credited in the [Hall of fame](#hall-of-fame)
below, with your consent. A paid bounty is deferred to a future deployment that
holds real value at stake. *(This matches the project plan:
`docs/designs/five-minute-self-host-quickstart.md:126-128`.)*

## Safe harbor

We support good-faith security research. If you make a good-faith effort to
comply with this policy, we will consider your research authorized, we will not
pursue or support legal action against you for it, and we will work with you to
understand and resolve the issue quickly.

Good faith means:

- You only test against your own local instance (the `oic demo`, local-stack, or
  your own build). This software runs entirely on your own machine; there is no
  hosted service to test against.
- You do not access, modify, or exfiltrate data that is not yours.
- You avoid privacy violations, data destruction, and service disruption.
- You give us a reasonable time to fix an issue before public disclosure.

## Scope

**In scope** — the custody protocol and the properties asserted in
[THREAT_MODEL.md](THREAT_MODEL.md):

- The protocol crates: policy kernel, signer, approval verifier, crypto
  providers (dev single-key and FROST ed25519), domain types and canonical
  encoding, authorization state, audit, one-time-state ledger, and the reconciler
  store (`crates/*`, `services/reconciler`).
- The `oic` demo and its guarantees (`cli/oic`), including the blocked-theft
  proof and the signed audit export.

**Out of scope** — not accepted as security findings for this preview:

- The deterministic chain simulators (`crates/chain-simulator`) as an attack
  target. They are test doubles standing in for real chains.
- Denial of service, resource exhaustion, and traffic-volume attacks.
- The sample console application (`apps/console`). It is a demonstration UI; its
  security relies on the downstream re-verification in the protocol crates.
- Issues that require an already-compromised host, a stolen key share, or a
  privileged local attacker.
- Behavior that only appears when the software is run outside the `dev`
  environment it currently targets. Production deployment is not yet supported.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full out-of-scope list and the
preview's known limitations.

## Hall of fame

We credit researchers who report valid, in-scope issues in good faith. With your
permission, we will add you here.

<!--
  Format (newest first). Keep one row per acknowledged report.

  | Date (YYYY-MM-DD) | Researcher (name or handle) | Summary | Advisory / commit |
  | --- | --- | --- | --- |
-->

_No entries yet — be the first._
