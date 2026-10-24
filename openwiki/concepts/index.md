# Files

- [Implementation and deployment boundaries](implementation-boundaries.md) - Supported development direct-transfer capabilities and the boundary between executable repository behavior and unimplemented production deployment claims.
- [Policy evaluation](policy-evaluation.md) - Deterministic policy decisions bind a candidate to the active policy, apply non-overridable safety checks, select one ordered rule, enforce limits, and count scoped approvals. This page also explains the caller authentication boundary and authority-supplied exposure input.
- [Security objects and canonical encoding](security-objects-and-encoding.md) - Security objects describe custody authorization, while a restricted deterministic CBOR profile supplies the bytes for commitments and signatures. REST JSON is a typed transport representation and is never the signed byte format.
