# Approval client

`oic-approve` independently decodes a builder-produced package, shows the verified
operation, and signs an approval grant. It does not sign or broadcast the chain
transaction. Approval credentials are separate from administrative keys and signer
shares.

## Build and prepare inputs

```sh
cargo build -p oic-approval-client --locked
./target/debug/oic-approve --help
./target/debug/oic-approve approve --help
```

Run the examples from the repository root. Replace `/path/to/...` and public-key
placeholders with your enrolled input files; they are not bundled demo filenames.

| Input | Where it comes from |
| --- | --- |
| `profile.json` | Independently enrolled `ChainProfile` for the intended network |
| Administrator public keys | Institution's independent administrative roster |
| `package.json` | Serialized `ApprovalPackage` returned by the builder |
| `approver.key.json` | Local `keygen` output; encrypted credential |
| `envelope.json` | Coordinator's authorization envelope, when inspecting |

The application exporting a package should serialize `built.package`; a raw
transaction or golden-vector file is not an `ApprovalPackage`. Working package
construction is shown in the [approval test fixtures](../apps/independent-approval-client/tests/common/mod.rs).
The repository does not currently ship a package-export server or enrollment UI.

## Pin trust roots

```sh
./target/debug/oic-approve init-trust \
  --out /path/to/trust.json \
  --admin-key "admin-a=<ADMIN_A_ED25519_PUBLIC_KEY_HEX>" \
  --admin-key "admin-b=<ADMIN_B_ED25519_PUBLIC_KEY_HEX>" \
  --admin-quorum 2 --profile /path/to/profile.json
```

The example quorum is two distinct administrators. Use the actual institution's
enrolled quorum and public keys. Repeat `--profile` for each enrolled profile.
The command pins this binary's adapter verifier builds; a foreign/unaccepted build
is refused when used. Obtain roots independently of the console supplying packages.

## Generate an approver credential

Supply a passphrase of at least 12 bytes in `OIC_APPROVER_PASSPHRASE` through your
operator-controlled secret mechanism, then run:

```sh
./target/debug/oic-approve keygen \
  --out /path/to/approver.key.json \
  --credential-id treasury-1 --role treasury_approver \
  --passphrase-env OIC_APPROVER_PASSPHRASE
```

The command creates an encrypted mode-`0600` Ed25519 key file and prints its
**public** enrollment information. Separately enroll the credential id, public key
and role in the approver roster used by builder/signers. Creating the file does not
activate the credential in the custody system. Use an existing parent directory
and a new output path.

## Review and approve

```sh
./target/debug/oic-approve show \
  --trust /path/to/trust.json --package /path/to/package.json

./target/debug/oic-approve approve \
  --trust /path/to/trust.json --package /path/to/package.json \
  --key /path/to/approver.key.json \
  --passphrase-env OIC_APPROVER_PASSPHRASE \
  --grant-id grant-1 --ttl-seconds 300 --out /path/to/grant.json
```

Check full recipient, network, concrete asset/mint/contract identity, base-unit
amount, maximum fee, policy epoch, evidence age, and approval scope. The displayed
address is derived from native bytes, not editable console text.

The default confirmation accepts `y` or `yes`; a declined confirmation writes no
grant. `--yes` skips that interaction while retaining verification. TTL must be
positive. A wrong passphrase, stale evidence, wrong recipient, missing quorum, or
other verification failure writes no grant. Existing output files are not overwritten.

The intent selects exact-candidate or bounded-direct-transfer mode. A bounded
approval fixes the transfer meaning and permits only adapter-defined fields to be
filled; it does not remove global budget or replacement checks.

## Verify and hand off the grant

```sh
./target/debug/oic-approve verify-grant \
  --trust /path/to/trust.json --package /path/to/package.json \
  --grant /path/to/grant.json \
  --approver "treasury-1=<APPROVER_ED25519_PUBLIC_KEY_HEX>=treasury_approver"
```

Pass the grant back to the builder/coordinator for policy evaluation and signing.
A locally created grant does not reserve exposure or create a transaction.

## Inspect an envelope

```sh
./target/debug/oic-approve inspect-envelope \
  --trust /path/to/trust.json --package /path/to/package.json \
  --envelope /path/to/envelope.json
```

This compares envelope/package commitments field by field. It explicitly does
**not** verify the authority receipt signature: the authority key is not an
approval-client trust root. Every signer performs that separate check.

`show`, `approve`, `verify-grant` and `inspect-envelope` accept `--now <unix-seconds>`
for reproducible fixture checks. They otherwise use system time.

| Exit code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Invalid command/argument |
| 3 | Verification or confirmation refused |
| 4 | Native recipient differs from registry destination |
| 5 | File read, parse or write failure |

For a self-contained executable example, run
`cargo test -p oic-approval-client --locked --test approval_client`.
The tests construct temporary inputs and cover the CLI flow, compromised-console
cases, encrypted key behavior and exact/bounded grants. See the
[independent approval reference](../openwiki/workflows/independent-approval.md)
for the verifier mechanisms and [getting started](getting-started.md) for transfer examples.
