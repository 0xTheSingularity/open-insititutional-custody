import { parseDecimalUnits } from "./amount";
import {
  readIntent,
  type CustodyIntent,
  type LocalCatalog,
  type LocalStatus,
} from "./custody-model";

export const pendingStorageKey = "oic-local-custody-pending-v1";
export type PendingIntent = {
  installation: string;
  idempotencyKey: string;
  intent: CustodyIntent;
};

export function sameIntent(
  expected: CustodyIntent,
  actual: CustodyIntent,
): boolean {
  function matches(a: unknown, b: unknown): boolean {
    if (a === null || typeof a !== "object") return a === b;
    return (
      b !== null &&
      typeof b === "object" &&
      Object.entries(a).every(([key, value]) =>
        matches(value, (b as Record<string, unknown>)[key]),
      )
    );
  }
  return matches(expected, actual);
}

export function readPending(raw: string, catalog: LocalCatalog): PendingIntent {
  const value = JSON.parse(raw) as PendingIntent;
  if (
    !value ||
    value.installation !== catalog.event_verifying_key ||
    typeof value.idempotencyKey !== "string" ||
    !/^[A-Za-z0-9-]{1,128}$/.test(value.idempotencyKey)
  ) {
    throw new Error(
      "A pending request belongs to another installation or is unreadable. Preserve this browser record and inspect the original installation before creating another payment.",
    );
  }
  readIntent(value.intent);
  if (
    value.intent.institution_id !== catalog.institution_id ||
    value.intent.environment_id !== catalog.environment_id ||
    value.intent.proposer_credential_id !== catalog.proposer_credential_id
  )
    throw new Error(
      "Pending request scope differs from the connected installation. Actions are paused.",
    );
  return value;
}

export function prepareIntent(
  catalog: LocalCatalog,
  status: LocalStatus,
  input: {
    walletId: string;
    destination: string;
    amount: string;
    fee: string;
    reference: string;
  },
  existingReferences: string[],
  id: string,
  now: number,
): PendingIntent {
  const wallet = catalog.wallets.find(
    (w) => w.chain_wallet_id === input.walletId && w.active,
  );
  const asset = catalog.assets.find((a) => a.network_id === wallet?.network_id);
  const destination = catalog.destinations.find(
    (d) =>
      `${d.destination_id}:${d.version}` === input.destination &&
      d.network_id === wallet?.network_id,
  );
  if (
    !wallet ||
    !asset ||
    !destination ||
    (destination.allowed_assets.length &&
      !destination.allowed_assets.includes(asset.asset_id))
  )
    throw new Error(
      "Select an active source and an enrolled destination on the same network.",
    );
  const amount = parseDecimalUnits(input.amount, asset.decimals);
  const fee = parseDecimalUnits(input.fee, asset.decimals);
  const max = 340282366920938463463374607431768211455n;
  if (
    amount === null ||
    fee === null ||
    BigInt(amount) === 0n ||
    BigInt(fee) === 0n ||
    BigInt(amount) > max ||
    BigInt(fee) > max
  )
    throw new Error(
      `Enter positive exact amounts with at most ${asset.decimals} decimals, within u128. No rounding or exponents.`,
    );
  const balance = status.balances.find(
    (b) =>
      b.holdings.chain_wallet_id === wallet.chain_wallet_id &&
      b.holdings.asset_id === asset.asset_id,
  );
  if (
    !balance ||
    BigInt(amount) + BigInt(fee) > BigInt(balance.holdings.available)
  )
    throw new Error(
      "Amount plus maximum fee exceeds observed available holdings. Refresh funding and reservations first.",
    );
  const reference = input.reference.trim();
  if (
    !reference ||
    new TextEncoder().encode(reference).length > 80 ||
    /[\u0000-\u001f\u007f]/.test(reference)
  )
    throw new Error(
      "Enter a business reference of 1–80 UTF-8 bytes without control characters.",
    );
  if (
    existingReferences.some(
      (r) => r.trim().toLowerCase() === reference.toLowerCase(),
    )
  )
    throw new Error(
      "This reference already exists. Inspect that transfer before creating another payment.",
    );
  const intent: CustodyIntent = {
    schema_version: 1,
    intent_id: id,
    institution_id: catalog.institution_id,
    environment_id: catalog.environment_id,
    vault_id: wallet.vault_id,
    chain_wallet_id: wallet.chain_wallet_id,
    chain_profile_id: wallet.chain_profile_id,
    operation: {
      asset_transfer: {
        asset_id: asset.asset_id,
        amount_base_units: amount,
        destination_id: destination.destination_id,
        destination_version: destination.version,
      },
    },
    constraints: {
      max_network_fee_base_units: fee,
      approval_mode: "exact_candidate",
      maximum_successful_payments: 1,
    },
    purpose: "settlement",
    external_reference: reference,
    proposer_credential_id: catalog.proposer_credential_id,
    created_at: now,
  };
  readIntent(intent);
  return {
    installation: catalog.event_verifying_key,
    idempotencyKey: id,
    intent,
  };
}
