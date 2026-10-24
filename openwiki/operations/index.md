# Files

- [Audit log and checkpoints](audit-log.md) - Signed append-only audit chains, crash-safe file recovery, independent checkpoint witnesses, and authority-event projection with explicit sink-failure monitoring.
- [Durable state and recovery](durable-state-and-recovery.md) - Maps the independent persistence domains that protect authorization, one-time signing state, workflow uncertainty, chain simulation, reconciliation, and audit history, with their rollback floors and restart behavior.
- [Reconciliation and treasury workflows](reconciliation-and-treasury-workflows.md) - Explains how the reconciler indexes finalized chain effects into a signed journal, compares holdings with chain balances, and plans controlled deposit-triggered funding and sweep intents without bypassing custody authorization.
