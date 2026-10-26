// Display validation only. Independent approval still recomputes signed objects
// against separately pinned trust; this browser model is not that verifier.
export type LocalAsset = {
  asset_id: string;
  network_id: string;
  asset: "native";
  decimals: number;
  symbol: string;
  behavior: "standard";
};
export type LocalWallet = {
  chain_wallet_id: string;
  vault_id: string;
  chain_profile_id: string;
  network_id: string;
  address_display: string;
  active: boolean;
  key_id: string;
};
export type LocalDestination = {
  destination_id: string;
  version: number;
  network_id: string;
  address_display: string;
  display_name: string;
  allowed_assets: string[];
};
type Policy = {
  policy_id: string;
  policy_epoch: number;
  rules: {
    vaults: string[];
    assets: string[];
    destinations: string[];
    purposes: string[];
    required_approvals: number;
    max_amount_per_operation: string;
    max_native_fee_per_operation: string;
    exclude_proposer: boolean;
  }[];
};
export type LocalCatalog = {
  schema_version: 1;
  profile: string;
  institution_id: string;
  environment_id: "dev";
  proposer_credential_id: string;
  event_verifying_key: string;
  vaults: { vault_id: string; display_name: string; policy_id: string }[];
  wallets: LocalWallet[];
  assets: LocalAsset[];
  destinations: LocalDestination[];
  profiles: {
    chain_profile_id: string;
    adapter_id: "evm" | "solana";
    network_id: string;
    display_name: string;
    network_binding: string;
  }[];
  policy: Policy;
  backend_limits: Record<string, string>;
};
export type CustodyIntent = {
  schema_version: 1;
  intent_id: string;
  institution_id: string;
  environment_id: "dev";
  vault_id: string;
  chain_wallet_id: string;
  chain_profile_id: string;
  operation: {
    asset_transfer: {
      asset_id: string;
      amount_base_units: string;
      destination_id: string;
      destination_version: number;
    };
  };
  constraints: {
    max_network_fee_base_units: string;
    approval_mode: "exact_candidate";
    maximum_successful_payments: 1;
  };
  purpose: "settlement";
  external_reference: string;
  proposer_credential_id: string;
  created_at: number;
};
/** Approvals the first matching policy rule requires, mirroring the kernel's
 * `match_rule` (empty scope lists match everything). Explanation only: the
 * custody service decides. `null` when no rule matches. */
export function requiredApprovals(record: CustodyIntentRecord): number | null {
  const { intent } = record;
  const transfer = intent.operation.asset_transfer;
  const matches = (list: string[], value: string) =>
    list.length === 0 || list.includes(value);
  const rule = record.built.package.policy.rules.find(
    (r) =>
      matches(r.vaults, intent.vault_id) &&
      matches(r.assets, transfer.asset_id) &&
      matches(r.destinations, transfer.destination_id) &&
      matches(r.purposes, intent.purpose),
  );
  return rule ? rule.required_approvals : null;
}

const preDispatchStates = new Set<string>([
  "DRAFT",
  "BUILT",
  "VERIFIED",
  "POLICY_EVALUATED",
  "AWAITING_APPROVAL",
]);
/** Distinct credentials with an unexpired grant at `now` (Unix seconds).
 * Two grants from one credential are one approver, as in the kernel. */
export function liveApprovals(record: CustodyIntentRecord, now: number): number {
  return new Set(
    record.approvals
      .filter((grant) => grant.body.expires_at > now)
      .map((grant) => grant.body.approver_credential_id),
  ).size;
}
/** Whether the transfer belongs in the approval queue: still before dispatch,
 * not issued, a policy rule matches, and fewer unexpired grants are recorded
 * than that rule requires. Explanation only; the custody service decides. */
export function needsApproval(
  record: CustodyIntentRecord,
  lifecycle: string,
  now: number,
): boolean {
  const required = requiredApprovals(record);
  return (
    record.dispatch === "ready" &&
    record.issuance === null &&
    preDispatchStates.has(lifecycle) &&
    required !== null &&
    liveApprovals(record, now) < required
  );
}

/** Checkpoints older than this are reported as stale, not as a current match. */
export const CHECKPOINT_STALE_SECONDS = 120;
export type CheckpointView = {
  tone: "success" | "attention" | "danger";
  label: string;
  ageSeconds: number;
};
/** RFC 004 §9: a reconciliation result is shown as current only while fresh. */
export function checkpointView(
  body: LocalStatus["checkpoints"][number]["body"],
  now: number,
): CheckpointView {
  const ageSeconds = Math.max(0, now - body.at);
  const consistent =
    body.balances.every((b) => b.chain_balance === b.journal_balance) &&
    body.cases_opened.length === 0;
  if (!consistent)
    return { tone: "danger", label: "Reconciliation exception", ageSeconds };
  if (ageSeconds > CHECKPOINT_STALE_SECONDS)
    return {
      tone: "attention",
      label: `Matched ${Math.round(ageSeconds / 60)} min ago; stale`,
      ageSeconds,
    };
  return { tone: "success", label: "Reported balances match", ageSeconds };
}

/** Case-insensitive match of `query` against a record's reference, intent,
 * operation family, candidate, vault, wallet, destination, asset, and
 * transaction identifiers. An empty query matches everything. */
export function matchesQuery(record: CustodyIntentRecord, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const { intent, built } = record;
  const fields = [
    intent.external_reference,
    intent.intent_id,
    intent.vault_id,
    intent.chain_wallet_id,
    intent.operation.asset_transfer.asset_id,
    intent.operation.asset_transfer.destination_id,
    built.candidate.operation_family_id,
    built.candidate.candidate_id,
    built.package.destination.address_display,
    built.package.destination.display_name,
    built.package.asset.symbol,
    record.issuance?.signed.signed.chain_tx_id ?? "",
  ];
  return fields.some((f) => f.toLowerCase().includes(q));
}

export type CustodyIntentRecord = {
  intent: CustodyIntent;
  built: {
    candidate: {
      operation_family_id: string;
      candidate_id: string;
      candidate_revision: number;
    };
    package: {
      wallet: LocalWallet;
      asset: LocalAsset;
      destination: LocalDestination;
      policy: Policy;
    };
  };
  approvals: {
    body: {
      approver_credential_id: string;
      issued_at: number;
      expires_at: number;
    };
  }[];
  dispatch: "ready" | "dispatching" | "signed" | "cancelled";
  issuance: null | { signed: { signed: { chain_tx_id: string } } };
  last_error: null | { code: string; detail: string };
};
export const lifecycles = [
  "DRAFT",
  "BUILT",
  "VERIFIED",
  "POLICY_EVALUATED",
  "AWAITING_APPROVAL",
  "RESERVED",
  "AUTHORIZED",
  "ISSUANCE_COMMITTED",
  "SIGNING",
  "SIGNATURE_OBSERVED",
  "SUBMITTED",
  "INCLUDED",
  "FINALIZED_SUCCESS",
  "FINALIZED_FAILURE",
  "REJECTED",
  "APPROVAL_EXPIRED",
  "ABORTED_BEFORE_ISSUANCE",
  "ISSUANCE_UNKNOWN",
  "SUBMISSION_UNKNOWN",
  "REORGED",
  "REPLACEMENT_PENDING",
  "DEFINITIVELY_INVALIDATED",
] as const;
type Lifecycle = (typeof lifecycles)[number];
/** RFC 004 §7 display label and safe action per exact lifecycle state, and
 * §9 tone: green only for a verified outcome, amber for wait or
 * uncertainty, red for denied or failed, neutral for ordinary progress. */
export const lifecycleDisplay: Record<
  Lifecycle,
  { label: string; action: string; tone: "success" | "attention" | "danger" | "neutral" }
> = {
  DRAFT: { label: "Draft", action: "Edit or submit where permitted.", tone: "neutral" },
  BUILT: { label: "Checking", action: "Wait for verification.", tone: "neutral" },
  VERIFIED: { label: "Checking", action: "Wait for policy evaluation.", tone: "neutral" },
  POLICY_EVALUATED: { label: "Policy checked", action: "Submit for approval where permitted.", tone: "neutral" },
  AWAITING_APPROVAL: { label: "Awaiting approvals", action: "Open the verifier; inspect expiry.", tone: "attention" },
  RESERVED: { label: "Funds reserved", action: "Inspect. Exposure is held.", tone: "attention" },
  AUTHORIZED: { label: "Authorized", action: "Inspect. Exposure is held.", tone: "attention" },
  ISSUANCE_COMMITTED: { label: "Signature may exist", action: "Do not cancel; ordinary cancellation is no longer safe.", tone: "attention" },
  SIGNING: { label: "Signing", action: "Do not cancel; ordinary cancellation is no longer safe.", tone: "attention" },
  SIGNATURE_OBSERVED: { label: "Signed", action: "Inspect, or make the approved initial submit.", tone: "attention" },
  SUBMITTED: { label: "Submitted to network", action: "Inspect the transaction. Never resend as a new payment.", tone: "attention" },
  INCLUDED: { label: "Included, awaiting finality", action: "Wait for finality.", tone: "attention" },
  FINALIZED_SUCCESS: { label: "Finalized successfully", action: "Check reconciliation separately.", tone: "success" },
  FINALIZED_FAILURE: { label: "Finalized with execution failure", action: "Inspect actual fees. A new payment needs a new authorization.", tone: "danger" },
  REJECTED: { label: "Rejected", action: "Inspect the reason.", tone: "danger" },
  APPROVAL_EXPIRED: { label: "Approval expired", action: "Create a new intent if still needed.", tone: "danger" },
  ABORTED_BEFORE_ISSUANCE: { label: "Cancelled before issuance", action: "No signature was issued.", tone: "neutral" },
  ISSUANCE_UNKNOWN: { label: "Outcome uncertain", action: "Investigate. A signature may exist; do not re-sign.", tone: "attention" },
  SUBMISSION_UNKNOWN: { label: "Outcome uncertain", action: "Investigate. A signature may exist; do not re-sign.", tone: "attention" },
  REORGED: { label: "Chain reorganization", action: "Tracking the canonical outcome.", tone: "attention" },
  REPLACEMENT_PENDING: { label: "Replacement pending", action: "Inspect the original and the candidate family.", tone: "attention" },
  DEFINITIVELY_INVALIDATED: { label: "Proven unable to execute", action: "Inspect the evidence.", tone: "danger" },
};

export type CustodyOperation = {
  operation_family_id: string;
  lifecycle: (typeof lifecycles)[number];
  issuance: null | { lifecycle: (typeof lifecycles)[number] };
  submission: unknown;
};
type State = { height: number; hash: string; commitment: string };
export type LocalStatus = {
  balances: {
    chain: "evm" | "solana";
    head: State;
    holdings: {
      chain_wallet_id: string;
      asset_id: string;
      settled: string;
      reserved: string;
      available: string;
      pending_inbound: string;
      as_of_sequence: number;
    };
  }[];
  checkpoints: {
    body: {
      checkpoint_id: string;
      chain_profile_id: string;
      /** Unix seconds the reconciler took this checkpoint. */
      at: number;
      state: State;
      journal_sequence: number;
      balances: {
        chain_wallet_id: string;
        asset_id: string;
        chain_balance: string;
        journal_balance: string;
      }[];
      cases_opened: string[];
    };
    signature: unknown;
  }[];
};

function require(value: unknown): asserts value {
  if (!value)
    throw new Error(
      "The local custody response does not match the supported development contract. Actions are paused.",
    );
}
function object(value: unknown): Record<string, unknown> {
  require(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}
function list(value: unknown): unknown[] {
  require(Array.isArray(value));
  return value;
}
function strings(value: unknown) {
  list(value).forEach(text);
}
function text(value: unknown) {
  require(typeof value === "string" && value.length > 0);
}
function integer(value: unknown) {
  require(
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0,
  );
}
function amount(value: unknown) {
  require(
    typeof value === "string" &&
      /^(0|[1-9][0-9]{0,38})$/.test(value) &&
      BigInt(value) <= 340282366920938463463374607431768211455n,
  );
}
function fields(value: unknown, keys: string[], check = text) {
  const v = object(value);
  keys.forEach((key) => check(v[key]));
  return v;
}
function safeNumbers(value: unknown): void {
  if (typeof value === "number") integer(value);
  else if (Array.isArray(value)) value.forEach(safeNumbers);
  else if (value && typeof value === "object")
    Object.values(value).forEach(safeNumbers);
}
function wallet(value: unknown) {
  const v = fields(value, [
    "chain_wallet_id",
    "vault_id",
    "chain_profile_id",
    "network_id",
    "address_display",
    "key_id",
  ]);
  require(typeof v.active === "boolean");
}
function asset(value: unknown) {
  const v = fields(value, ["asset_id", "network_id", "symbol"]);
  integer(v.decimals);
  require(
    Number(v.decimals) <= 38 &&
      v.asset === "native" &&
      v.behavior === "standard",
  );
}
function destination(value: unknown) {
  const v = fields(value, [
    "destination_id",
    "network_id",
    "address_display",
    "display_name",
  ]);
  integer(v.version);
  require(Number(v.version) > 0);
  strings(v.allowed_assets);
}
function policy(value: unknown) {
  const v = fields(value, ["policy_id"]);
  integer(v.policy_epoch);
  list(v.rules).forEach((rule) => {
    const r = object(rule);
    ["vaults", "assets", "destinations", "purposes"].forEach((key) =>
      strings(r[key]),
    );
    integer(r.required_approvals);
    amount(r.max_amount_per_operation);
    amount(r.max_native_fee_per_operation);
    require(typeof r.exclude_proposer === "boolean");
  });
}
function state(value: unknown) {
  const v = fields(value, ["hash", "commitment"]);
  integer(v.height);
}
function intent(value: unknown) {
  const v = fields(value, [
    "intent_id",
    "institution_id",
    "vault_id",
    "chain_wallet_id",
    "chain_profile_id",
    "external_reference",
    "proposer_credential_id",
  ]);
  require(
    v.schema_version === 1 &&
      v.environment_id === "dev" &&
      v.purpose === "settlement",
  );
  integer(v.created_at);
  const op = fields(object(v.operation).asset_transfer, [
    "asset_id",
    "destination_id",
  ]);
  amount(op.amount_base_units);
  integer(op.destination_version);
  const c = object(v.constraints);
  amount(c.max_network_fee_base_units);
  require(
    c.approval_mode === "exact_candidate" &&
      c.maximum_successful_payments === 1,
  );
}

export function readCatalog(value: unknown): LocalCatalog {
  safeNumbers(value);
  const v = fields(value, [
    "profile",
    "institution_id",
    "proposer_credential_id",
    "event_verifying_key",
  ]);
  require(/^[0-9a-f]{64}$/.test(String(v.event_verifying_key)));
  require(
    v.schema_version === 1 &&
      v.environment_id === "dev" &&
      String(v.profile).startsWith("DEVELOPMENT-ONLY"),
  );
  list(v.vaults).forEach((vault) => {
    fields(vault, ["vault_id", "display_name", "policy_id"]);
  });
  list(v.wallets).forEach(wallet);
  list(v.assets).forEach(asset);
  list(v.destinations).forEach(destination);
  list(v.profiles).forEach((profile) => {
    const p = fields(profile, [
      "chain_profile_id",
      "network_id",
      "display_name",
      "network_binding",
    ]);
    require(p.adapter_id === "evm" || p.adapter_id === "solana");
  });
  policy(v.policy);
  Object.values(object(v.backend_limits)).forEach(text);
  require(list(v.wallets).length > 0 && list(v.assets).length > 0);
  const catalog = value as LocalCatalog;
  require(
    new Set(catalog.wallets.map((w) => w.chain_wallet_id)).size ===
      catalog.wallets.length,
  );
  require(
    new Set(catalog.assets.map((a) => a.asset_id)).size ===
      catalog.assets.length,
  );
  require(
    new Set(catalog.destinations.map((d) => `${d.destination_id}:${d.version}`))
      .size === catalog.destinations.length,
  );
  catalog.wallets.forEach((w) =>
    require(
      catalog.vaults.some((v) => v.vault_id === w.vault_id) &&
        catalog.profiles.some(
          (p) =>
            p.chain_profile_id === w.chain_profile_id &&
            p.network_id === w.network_id,
        ),
    ),
  );
  return catalog;
}
export function readStatus(value: unknown): LocalStatus {
  safeNumbers(value);
  const v = object(value);
  list(v.balances).forEach((balance) => {
    const b = object(balance);
    require(b.chain === "evm" || b.chain === "solana");
    state(b.head);
    const h = fields(b.holdings, ["chain_wallet_id", "asset_id"]);
    ["settled", "reserved", "available", "pending_inbound"].forEach((key) =>
      amount(h[key]),
    );
    integer(h.as_of_sequence);
    require(
      BigInt(String(h.available)) ===
        (BigInt(String(h.settled)) > BigInt(String(h.reserved))
          ? BigInt(String(h.settled)) - BigInt(String(h.reserved))
          : 0n),
    );
  });
  list(v.checkpoints).forEach((checkpoint) => {
    const c = object(checkpoint);
    const b = fields(c.body, ["checkpoint_id", "chain_profile_id"]);
    state(b.state);
    integer(b.at);
    integer(b.journal_sequence);
    strings(b.cases_opened);
    list(b.balances).forEach((balance) => {
      const r = fields(balance, ["chain_wallet_id", "asset_id"]);
      amount(r.chain_balance);
      amount(r.journal_balance);
    });
    require(c.signature !== undefined);
  });
  return value as LocalStatus;
}
export function readIntentRecord(value: unknown): CustodyIntentRecord {
  safeNumbers(value);
  const v = object(value);
  intent(v.intent);
  const b = object(v.built);
  const c = fields(b.candidate, ["operation_family_id", "candidate_id"]);
  integer(c.candidate_revision);
  const p = object(b.package);
  wallet(p.wallet);
  asset(p.asset);
  destination(p.destination);
  policy(p.policy);
  list(v.approvals).forEach((grant) => {
    const g = fields(object(grant).body, ["approver_credential_id"]);
    integer(g.issued_at);
    integer(g.expires_at);
  });
  require(
    ["ready", "dispatching", "signed", "cancelled"].includes(
      String(v.dispatch),
    ),
  );
  if (v.issuance !== null)
    fields(object(object(v.issuance).signed).signed, ["chain_tx_id"]);
  if (v.last_error !== null) fields(v.last_error, ["code", "detail"]);
  const record = value as CustodyIntentRecord;
  const i = record.intent;
  const transfer = i.operation.asset_transfer;
  require(
    c.intent_id === i.intent_id &&
      record.built.package.wallet.chain_wallet_id === i.chain_wallet_id &&
      record.built.package.wallet.vault_id === i.vault_id &&
      record.built.package.wallet.chain_profile_id === i.chain_profile_id,
  );
  require(
    record.built.package.asset.asset_id === transfer.asset_id &&
      record.built.package.destination.destination_id ===
        transfer.destination_id &&
      record.built.package.destination.version === transfer.destination_version,
  );
  require(
    record.built.package.wallet.network_id ===
      record.built.package.asset.network_id &&
      record.built.package.wallet.network_id ===
        record.built.package.destination.network_id,
  );
  return record;
}
export function readOperation(value: unknown): CustodyOperation {
  safeNumbers(value);
  const v = fields(value, ["operation_family_id"]);
  require(
    lifecycles.some((state) => state === v.lifecycle) &&
      "issuance" in v &&
      "submission" in v,
  );
  if (v.issuance !== null) {
    const issuance = object(v.issuance);
    require(lifecycles.some((state) => state === issuance.lifecycle));
  }
  return value as CustodyOperation;
}
export function readIntentIds(value: unknown): string[] {
  strings(value);
  require(new Set(value as string[]).size === (value as string[]).length);
  return value as string[];
}

export function readIntent(value: unknown): CustodyIntent {
  safeNumbers(value);
  intent(value);
  return value as CustodyIntent;
}
