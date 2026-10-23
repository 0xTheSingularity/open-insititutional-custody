# Deploying the reference topology

`oic-node` (in `services/node-runner`) runs any role of the reference
topology — three signers, one authority, one gateway — from a provisioned
node directory. This directory holds the deployment artifacts around it.

**This is a development-profile deployment.** It qualifies the production
transport across real processes and real per-node addresses, but shares
are sealed in software, the roster is signed by locally generated admin
keys, and nothing here is an audited production setup. See
`docs/multi-host-transport.md` and `THREAT_MODEL.md` before promoting any
of it.

## Provision

```sh
oic-node provision --out /var/lib/oic \
  --address 10.0.0.10:7420 --address 10.0.0.11:7420 --address 10.0.0.12:7420 \
  --address 10.0.0.13:7420 --address 10.0.0.14:7420
```

Five directories result: `node-0..2` (signers), `node-3` (gateway),
`node-4` (authority). Each holds the signed roster, the admin set, and
that node's secrets (0600, directory 0700). Move each directory to its
host; nothing outside it is needed. The DKG runs inside `provision`, so
the machine that runs it briefly holds all shares — acceptable for
development, not for production ceremonies.

## Run

- **Docker (one host, one IP per node):** `deploy/docker/qualify.sh`
  provisions, starts the topology with distinct container IPs, proves
  convergence from the gateway's view, and tears down. `compose.yaml` is
  the long-running variant of the same topology.
- **systemd (one or more hosts):** install `deploy/systemd/oic-node@.service`
  and start `oic-node@<node-dir>` per host, one instance per provisioned
  directory.
- **Health:** `oic-node run --check --dir <gateway dir>` exits 0 once every
  signer answers a status probe and the authority answers RPC. Budget for
  the cold-start cooldown cycle either way: measured convergence was 109
  seconds with one IP per container and 98 to 216 seconds across runs
  with a shared IP.

## Recovery

Gateways restart freely, and the authority reopens its durable store on
restart. A signer does not: `Signer::open` bumps the persisted instance
generation on every open (`crates/signer/src/lib.rs:91`), and the roster
pins each signer's generation, so a restarted signer-core is refused with
`StaleGeneration` (`services/signer-core/src/lib.rs:131`) until an admin
quorum commits a roster that approves the new instance. That refusal is
the anti-clone defense working, not a defect.

Readmission is an administrative act, and `oic-node readmit --base
<topology>` runs its development ceremony: it pins every signer's next
instance generation from its durable store, advances the roster epoch,
signs the update with two of the three provisioned admin keys, and
stages it in every node directory. Restart the fleet onto it and the
refused signer is a member again. The ceremony keys sit in
`admin-ceremony/` only because this is a one-machine development
topology, and the authority commit reference self-attests with the
prior roster hash; production admins are people, and the reference
would name an authority log commit.

Readmission is planned downtime. Nodes read the roster only at start,
and nodes on different epochs refuse each other, so the fleet restarts
together and nothing signs during the roll. Live roster propagation
through the authority is the production follow-up that removes the
outage.

`services/node-runner/tests/topology.rs` drills the full sequence: the
unauthorized restart fails fast, the surviving two signers plus a
restarted authority pass `run --check --check-require 2`, and after the
ceremony and a rolling restart the topology reaches full three-signer
convergence on the new epoch.
