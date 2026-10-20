# Documentation

Start with [getting started](getting-started.md) to build the workspace and run the
implemented EVM and Solana transfer examples. Use the [approval client guide](approval-client.md)
to review packages and sign grants, then the [development guide](development.md)
when changing or integrating components.

## Guides

| Task | Guide |
| --- | --- |
| Install prerequisites and run the current code | [Getting started](getting-started.md) |
| Set up local approval trust and credentials | [Approval client](approval-client.md) |
| Choose tests, check vectors and run the authority model | [Development](development.md) |
| Find a subsystem or trace its behavior | [OpenWiki quickstart](../openwiki/quickstart.md) |

## Reference by system

| System | Reference |
| --- | --- |
| Architecture and ownership | [System overview](../openwiki/architecture/system-overview.md) |
| Objects and signed formats | [Security objects and encoding](../openwiki/concepts/security-objects-and-encoding.md) |
| Policy rules and approvals | [Policy evaluation](../openwiki/concepts/policy-evaluation.md) |
| Global state and budgets | [Authorization authority](../openwiki/architecture/authorization-authority.md) |
| Candidate preparation and signing orchestration | [Build and coordinate](../openwiki/workflows/build-and-coordinate.md) |
| Independent approver verification | [Approval workflow](../openwiki/workflows/independent-approval.md) |
| Key-share boundary | [Signer verification](../openwiki/architecture/signer-boundary.md) |
| Chain semantics | [EVM](../openwiki/integrations/evm-adapter.md), [Solana](../openwiki/integrations/solana-adapter.md) |
| Cryptographic backends | [Crypto providers](../openwiki/integrations/crypto-providers.md) |
| Crash/rollback handling | [Durable state and recovery](../openwiki/operations/durable-state-and-recovery.md) |
| Signed history | [Audit log](../openwiki/operations/audit-log.md) |
| Delivery and settlement | [Broadcast and finality](../openwiki/workflows/broadcast-and-finality.md) |
| Test chains | [Simulators](../openwiki/testing/chain-simulators.md) |
| Test and conformance details | [Verification guide](../openwiki/testing/verification-guide.md) |
| Roadmap and readiness limits | [Implementation boundaries](../openwiki/concepts/implementation-boundaries.md) |

## Documentation ownership

`README.md` and `docs/` are the human-facing usage guides. `openwiki/` is the deeper
reference, authored by Codex from repository source and tests through OpenWiki's
resumable page/Claims lifecycle. OpenWiki manages its indexes, provenance and
claim metadata. The documents under `spec/` contain proposed requirements and
designs; they are not a list of completed features.

When the two disagree, verify the current source and focused tests, then update the
affected documentation. See [updating documentation](development.md#updating-documentation).
