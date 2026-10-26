import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CHECKPOINT_STALE_SECONDS,
  checkpointView,
  readCatalog,
  readIntentRecord,
  readOperation,
  lifecycleDisplay,
  lifecycles,
  liveApprovals,
  matchesQuery,
  needsApproval,
  readStatus,
  requiredApprovals,
} from "../src/lib/custody-model";
import {
  prepareIntent,
  readPending,
  sameIntent,
} from "../src/lib/custody-draft";

function fixture() {
  const catalog = readCatalog({
    schema_version: 1,
    profile: "DEVELOPMENT-ONLY test fixture",
    institution_id: "institution",
    environment_id: "dev",
    proposer_credential_id: "proposer",
    event_verifying_key: "ab".repeat(32),
    vaults: [
      { vault_id: "vault", display_name: "Local vault", policy_id: "policy" },
    ],
    wallets: [
      {
        chain_wallet_id: "evm-wallet",
        vault_id: "vault",
        chain_profile_id: "evm",
        network_id: "evm-test",
        address_display: "source-evm",
        key_id: "evm-key",
        active: true,
      },
      {
        chain_wallet_id: "sol-wallet",
        vault_id: "vault",
        chain_profile_id: "sol",
        network_id: "sol-test",
        address_display: "source-sol",
        key_id: "sol-key",
        active: true,
      },
    ],
    assets: [
      {
        asset_id: "eth",
        network_id: "evm-test",
        asset: "native",
        behavior: "standard",
        decimals: 18,
        symbol: "DEV-ETH",
      },
      {
        asset_id: "sol",
        network_id: "sol-test",
        asset: "native",
        behavior: "standard",
        decimals: 9,
        symbol: "DEV-SOL",
      },
    ],
    destinations: [
      {
        destination_id: "evm-payee",
        version: 7,
        network_id: "evm-test",
        address_display: "payee-evm",
        display_name: "EVM payee",
        allowed_assets: ["eth"],
      },
      {
        destination_id: "sol-payee",
        version: 2,
        network_id: "sol-test",
        address_display: "payee-sol",
        display_name: "Solana payee",
        allowed_assets: ["sol"],
      },
    ],
    profiles: [
      {
        chain_profile_id: "evm",
        adapter_id: "evm",
        network_id: "evm-test",
        display_name: "EVM simulator",
        network_binding: "31337",
      },
      {
        chain_profile_id: "sol",
        adapter_id: "solana",
        network_id: "sol-test",
        display_name: "Solana simulator",
        network_binding: "genesis",
      },
    ],
    policy: { policy_id: "policy", policy_epoch: 3, rules: [] },
    backend_limits: { recovery: "local only" },
  });
  const status = readStatus({
    balances: [
      {
        chain: "evm",
        head: { height: 9, hash: "evm-block", commitment: "latest" },
        holdings: {
          chain_wallet_id: "evm-wallet",
          asset_id: "eth",
          settled: "2000000000000000000",
          reserved: "500000000000000000",
          available: "1500000000000000000",
          pending_inbound: "9000000000000000000",
          as_of_sequence: 12,
        },
      },
      {
        chain: "solana",
        head: { height: 17, hash: "sol-block", commitment: "processed" },
        holdings: {
          chain_wallet_id: "sol-wallet",
          asset_id: "sol",
          settled: "1000000000",
          reserved: "0",
          available: "1000000000",
          pending_inbound: "0",
          as_of_sequence: 13,
        },
      },
    ],
    checkpoints: [],
  });
  return { catalog, status };
}

test("local native requests preserve exact quantities, source/version binding and available exposure", () => {
  const { catalog, status } = fixture();
  const input = {
    walletId: "evm-wallet",
    destination: "evm-payee:7",
    amount: "1.490000000000000001",
    fee: "0.009999999999999999",
    reference: "  Invoice-42  ",
  };
  const prepare = (changes = {}) =>
    prepareIntent(
      catalog,
      status,
      { ...input, ...changes },
      [],
      "intent-42",
      1792550000,
    );
  const pending = prepare();
  assert.equal(
    pending.intent.operation.asset_transfer.amount_base_units,
    "1490000000000000001",
  );
  assert.equal(
    pending.intent.constraints.max_network_fee_base_units,
    "9999999999999999",
  );
  assert.equal(pending.intent.operation.asset_transfer.destination_version, 7);
  assert.equal(pending.intent.chain_wallet_id, "evm-wallet");
  assert.equal(pending.intent.external_reference, "Invoice-42");
  assert.throws(() => prepare({ amount: "1.490000000000000002" }), /available/);
  assert.throws(() => prepare({ amount: "2" }), /available/); // pending inbound cannot fund this payment
  assert.throws(() => prepare({ destination: "sol-payee:2" }), /same network/);
  assert.throws(() => prepare({ destination: "evm-payee:6" }), /enrolled/);
  assert.throws(() => prepare({ amount: "0.0000000000000000001" }), /exact/);
  assert.throws(() => prepare({ fee: "1e-3" }), /exact/);
  assert.throws(() => prepare({ amount: "340282366920938463464" }), /u128/);
  assert.throws(
    () =>
      prepareIntent(
        catalog,
        status,
        input,
        ["invoice-42"],
        "intent-43",
        1792550000,
      ),
    /already exists/,
  );
  const sol = prepare({
    walletId: "sol-wallet",
    destination: "sol-payee:2",
    amount: "0.123456789",
    fee: "0.00002",
  });
  assert.equal(
    sol.intent.operation.asset_transfer.amount_base_units,
    "123456789",
  );
  assert.equal(sol.intent.constraints.max_network_fee_base_units, "20000");
});

test("retained intent identity survives JSON reload and fails closed on changed installation or request", () => {
  const { catalog, status } = fixture();
  const pending = prepareIntent(
    catalog,
    status,
    {
      walletId: "sol-wallet",
      destination: "sol-payee:2",
      amount: "0.123456789",
      fee: "0.00002",
      reference: "Recovery-42",
    },
    [],
    "intent-42",
    1792550000,
  );
  const recovered = readPending(JSON.stringify(pending), catalog);
  assert.deepEqual(recovered, pending);
  assert.equal(sameIntent(pending.intent, recovered.intent), true);
  const changed = structuredClone(recovered.intent);
  changed.operation.asset_transfer.destination_version++;
  assert.equal(sameIntent(pending.intent, changed), false);
  assert.throws(
    () =>
      readPending(JSON.stringify(pending), {
        ...catalog,
        event_verifying_key: "cd".repeat(32),
      }),
    /another installation/,
  );
  assert.throws(
    () =>
      readPending(
        JSON.stringify({
          ...pending,
          intent: { ...pending.intent, proposer_credential_id: "someone-else" },
        }),
        catalog,
      ),
    /scope/,
  );
  assert.throws(() => readPending("{partial", catalog));
});

test("read models reject rounded sequences, invalid holdings, unsupported lifecycles and mismatched candidate identity", () => {
  const { catalog, status } = fixture();
  for (const value of [
    "01",
    "-1",
    "1.5",
    "340282366920938463463374607431768211456",
  ]) {
    const bad = structuredClone(status);
    bad.balances[0].holdings.settled = value;
    assert.throws(() => readStatus(bad));
  }
  const unsafe = structuredClone(status);
  unsafe.balances[0].holdings.as_of_sequence = 9007199254740992;
  assert.throws(() => readStatus(unsafe));
  const wrongAvailable = structuredClone(status);
  wrongAvailable.balances[0].holdings.available = "2000000000000000000";
  assert.throws(() => readStatus(wrongAvailable));
  assert.throws(() => readCatalog({ ...catalog, environment_id: "prod" }));
  assert.throws(() =>
    readOperation({
      operation_family_id: "family",
      lifecycle: "Submitted",
      issuance: null,
      submission: null,
    }),
  );
  assert.equal(
    readOperation({
      operation_family_id: "family",
      lifecycle: "ISSUANCE_UNKNOWN",
      issuance: null,
      submission: null,
    }).lifecycle,
    "ISSUANCE_UNKNOWN",
  );
  const ambiguous = readOperation({
    operation_family_id: "family",
    lifecycle: "ISSUANCE_COMMITTED",
    issuance: { lifecycle: "ISSUANCE_UNKNOWN" },
    submission: null,
  });
  assert.equal(ambiguous.lifecycle, "ISSUANCE_COMMITTED");
  assert.equal(ambiguous.issuance?.lifecycle, "ISSUANCE_UNKNOWN");
  assert.throws(() =>
    readOperation({ ...ambiguous, issuance: { lifecycle: "unknown" } }),
  );
  const pending = prepareIntent(
    catalog,
    status,
    {
      walletId: "evm-wallet",
      destination: "evm-payee:7",
      amount: "0.1",
      fee: "0.01",
      reference: "Read-42",
    },
    [],
    "intent-42",
    1792550000,
  );
  const record = {
    intent: pending.intent,
    built: {
      candidate: {
        operation_family_id: "family",
        candidate_id: "candidate",
        candidate_revision: 1,
        intent_id: "intent-42",
      },
      package: {
        wallet: catalog.wallets[0],
        asset: catalog.assets[0],
        destination: catalog.destinations[0],
        policy: catalog.policy,
      },
    },
    approvals: [],
    dispatch: "ready",
    issuance: null,
    last_error: null,
  };
  assert.equal(readIntentRecord(record).intent.intent_id, "intent-42");
  const withRules = (rules: unknown[]) =>
    readIntentRecord({
      ...record,
      built: {
        ...record.built,
        package: { ...record.built.package, policy: { ...catalog.policy, rules } },
      },
    });
  const rule = (vaults: string[], required_approvals: number) => ({
    rule_id: `r${required_approvals}`,
    vaults,
    assets: [],
    destinations: [],
    purposes: [],
    required_approvals,
    max_amount_per_operation: "1000000000000000000000",
    max_native_fee_per_operation: "1000000000000000000",
    exclude_proposer: true,
  });
  // No rule: the console says so instead of inventing a requirement.
  assert.equal(requiredApprovals(withRules([])), null);
  // First matching rule in bundle order wins, as in the kernel's match_rule.
  assert.equal(
    requiredApprovals(withRules([rule(["other-vault"], 5), rule([], 2), rule([], 3)])),
    2,
  );
  // Approval queue: unexpired grants below the rule's requirement, before dispatch.
  const two = withRules([rule([], 2)]);
  const grant = (expires_at: number) => ({
    body: { approver_credential_id: "a", issued_at: 1, expires_at },
  });
  const now = 1000;
  assert.equal(needsApproval(two, "AWAITING_APPROVAL", now), true);
  const oneLive = { ...two, approvals: [grant(2000), grant(500)] };
  assert.equal(liveApprovals(oneLive, now), 1, "expired grants do not count");
  assert.equal(needsApproval(oneLive, "AWAITING_APPROVAL", now), true);
  const satisfied = { ...two, approvals: [grant(2000), grant(3000)] };
  assert.equal(needsApproval(satisfied, "AWAITING_APPROVAL", now), false);
  assert.equal(needsApproval(two, "SIGNING", now), false, "after dispatch");
  assert.equal(needsApproval({ ...two, dispatch: "dispatching" }, "AWAITING_APPROVAL", now), false);
  assert.equal(needsApproval(withRules([]), "AWAITING_APPROVAL", now), false, "no rule: denied, not queued");
  // Search spans reference, intent, family, destination, and asset fields.
  assert.equal(matchesQuery(two, ""), true);
  assert.equal(matchesQuery(two, "READ-42"), true, "case-insensitive reference");
  assert.equal(matchesQuery(two, "intent-42"), true);
  assert.equal(matchesQuery(two, "family"), true);
  assert.equal(matchesQuery(two, catalog.destinations[0].display_name.slice(0, 4)), true);
  assert.equal(matchesQuery(two, "no-such-transfer"), false);
  assert.throws(() =>
    readIntentRecord({
      ...record,
      built: {
        ...record.built,
        candidate: { ...record.built.candidate, intent_id: "other" },
      },
    }),
  );
  assert.throws(() =>
    readIntentRecord({
      ...record,
      built: {
        ...record.built,
        package: {
          ...record.built.package,
          destination: catalog.destinations[1],
        },
      },
    }),
  );
});

test("every lifecycle state has an RFC 004 label, action, and tone", () => {
  for (const state of lifecycles) {
    const d = lifecycleDisplay[state];
    assert.ok(d.label && d.action, state);
  }
  // Green only for a verified outcome; red for denied or failed.
  const tone = (t: string) =>
    lifecycles.filter((s) => lifecycleDisplay[s].tone === t).sort();
  assert.deepEqual(tone("success"), ["FINALIZED_SUCCESS"]);
  assert.deepEqual(tone("danger"), [
    "APPROVAL_EXPIRED",
    "DEFINITIVELY_INVALIDATED",
    "FINALIZED_FAILURE",
    "REJECTED",
  ]);
  // Uncertain outcomes never read as done or failed.
  for (const s of ["ISSUANCE_UNKNOWN", "SUBMISSION_UNKNOWN", "REORGED"] as const)
    assert.equal(lifecycleDisplay[s].tone, "attention");
});

test("reconciliation is shown as a current match only while the checkpoint is fresh", () => {
  const checkpoint = (at: number, journal_balance = "5") => ({
    body: {
      checkpoint_id: "checkpoint-1",
      chain_profile_id: "evm",
      at,
      state: { height: 3, hash: "h", commitment: "finalized" },
      journal_sequence: 2,
      balances: [
        { chain_wallet_id: "w", asset_id: "a", chain_balance: "5", journal_balance },
      ],
      cases_opened: [],
    },
    signature: {},
  });
  const status = (c: unknown) => readStatus({ balances: [], checkpoints: [c] });
  const now = 10_000;
  const fresh = status(checkpoint(now - 10)).checkpoints[0].body;
  assert.equal(checkpointView(fresh, now).tone, "success");
  const stale = status(checkpoint(now - CHECKPOINT_STALE_SECONDS - 1)).checkpoints[0].body;
  assert.equal(checkpointView(stale, now).tone, "attention");
  assert.match(checkpointView(stale, now).label, /stale/);
  const mismatch = status(checkpoint(now - 10, "4")).checkpoints[0].body;
  assert.equal(checkpointView(mismatch, now).tone, "danger");
  // A checkpoint without its timestamp is not accepted at all.
  const undated = checkpoint(now) as { body: Record<string, unknown> };
  delete undated.body.at;
  assert.throws(() => status(undated));
});
