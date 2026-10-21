import { mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { parse } from "csv-parse/sync";
import { keccak_256 } from "@noble/hashes/sha3.js";
import bs58 from "bs58";
import { consoleRequestAllowed } from "./boundary";
import type { Setup, Snapshot, Preview } from "./contracts";
import { sampleTreasury } from "./sample-treasury";

const MAX_BODY = 128 * 1024;
const now = () => Math.floor(Date.now() / 1000);
const networks = new Set([
  "ethereum-mainnet",
  "ethereum-sepolia",
  "solana-mainnet",
  "solana-devnet",
]);

class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function snapshot(setup: Setup, demo = false): Snapshot {
  return {
    schema_version: 1,
    environment: "test",
    mode: demo ? "demo" : "local",
    local_only: !demo,
    setup,
    sample_treasury: demo ? sampleTreasury : null,
    preflight: {
      os: process.platform,
      architecture: process.arch,
      version: "0.1.0",
      durable_state: !demo,
      release_signature_verified: false,
    },
    production_ready: false,
    blockers: [
      {
        title: "Local money loop",
        reason:
          "API, reconciler, simulator orchestration and independent verifier are not connected to this console.",
      },
      {
        title: "Independent signer domains",
        reason:
          "Domain ownership and independent provisioning have not been verified.",
      },
      {
        title: "Separate approval authority",
        reason:
          "Business and administrative credential enrollment have not been verified.",
      },
      {
        title: "Supported recovery",
        reason:
          "A supported backend and a completed recovery drill have not been verified.",
      },
      {
        title: "Production controls",
        reason:
          "Authentication, authority fencing, monitoring, policy review and receiving-address activation have not been verified.",
      },
    ],
  };
}

function validLabel(value: string) {
  return (
    Buffer.byteLength(value) <= 80 &&
    !/[\u0000-\u001f\u007f-\u009f]/u.test(value)
  );
}

function publicAddress(network: string, address: string): boolean {
  if (network.startsWith("ethereum-")) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return false;
    const hex = address.slice(2);
    if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return true;
    const hash = Buffer.from(
      keccak_256(new TextEncoder().encode(hex.toLowerCase())),
    ).toString("hex");
    return [...hex].every(
      (char, i) =>
        !/[a-f]/i.test(char) ||
        (char === char.toUpperCase()) === Number.parseInt(hash[i], 16) >= 8,
    );
  }
  if (network.startsWith("solana-")) {
    try {
      return address.length <= 44 && bs58.decode(address).length === 32;
    } catch {
      return false;
    }
  }
  return false;
}

function addressKey(network: string, address: string) {
  return `${network}:${network.startsWith("ethereum-") ? address.toLowerCase() : address}`;
}

function preview(csv: string, setup: Setup): Preview {
  if (!setup.workspace_name)
    throw new ApiError(
      409,
      "Create a test workspace before importing addresses.",
    );
  let records: string[][];
  try {
    records = parse(csv, {
      trim: true,
      bom: true,
      skip_empty_lines: true,
      max_record_size: MAX_BODY,
    }) as string[][];
  } catch {
    throw new ApiError(
      422,
      "Malformed CSV. Every row needs network,address,label; quote labels containing commas.",
    );
  }
  const headers = records.shift();
  if (
    headers?.length !== 3 ||
    headers[0] !== "network" ||
    headers[1] !== "address" ||
    headers[2] !== "label"
  )
    throw new ApiError(
      422,
      "Use exactly these CSV headers: network,address,label. Public addresses only.",
    );
  if (!records.length || records.length > 500)
    throw new ApiError(
      422,
      "Import between 1 and 500 public-address rows at a time.",
    );
  const seen = new Set(
    setup.inventory.map((row) => addressKey(row.network, row.address)),
  );
  const rows: Preview["rows"] = records.map(
    ([network, address, label], index) => {
      const supported = networks.has(network);
      const valid = supported && publicAddress(network, address);
      let status: Preview["rows"][number]["status"];
      let reason: string;
      if (!supported) {
        status = "unsupported";
        reason =
          "Network not supported. Keep this account with the source custodian.";
      } else if (!valid) {
        status = "invalid";
        reason =
          "Invalid public-address format or EVM checksum. Value not retained.";
      } else if (!validLabel(label)) {
        status = "invalid";
        reason = "Use a label of at most 80 bytes without control characters.";
      } else if (seen.has(addressKey(network, address))) {
        status = "duplicate";
        reason = "Already in this import or saved inventory for this network.";
      } else {
        status = "valid";
        reason =
          "Syntax checked only. Ownership, network activity and balances are unverified.";
        seen.add(addressKey(network, address));
      }
      return {
        row: index + 2,
        network: supported ? network : "Unsupported network",
        address: valid ? address : "Not retained",
        label: valid && validLabel(label) ? label : "",
        status,
        reason,
      };
    },
  );
  const importable = rows.filter((row) => row.status === "valid").length;
  return { rows, importable, excluded: rows.length - importable };
}

async function commandBody(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get("content-type")?.split(";")[0] !== "application/json")
    throw new ApiError(415, "Commands require application/json.");
  const reader = request.body?.getReader();
  if (!reader) throw new ApiError(422, "A JSON command body is required.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY) {
        await reader.cancel();
        throw new ApiError(
          413,
          "Request exceeds 128 KiB. Import a smaller batch.",
        );
      }
      chunks.push(value);
    }
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error("Not an object");
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(422, "Provide a valid JSON command object.");
  } finally {
    reader.releaseLock();
  }
}

function exactFields(body: Record<string, unknown>, keys: string[]) {
  if (
    Object.keys(body).length !== keys.length ||
    keys.some((key) => !(key in body))
  )
    throw new ApiError(422, `Command requires exactly: ${keys.join(", ")}.`);
}

function openStore(directory: string) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const path = join(directory, "console.sqlite");
  const db = new DatabaseSync(path);
  try {
    chmodSync(path, 0o600);
    db.exec(
      "PRAGMA busy_timeout = 5000; PRAGMA synchronous = FULL; CREATE TABLE IF NOT EXISTS setup (id INTEGER PRIMARY KEY CHECK(id = 1), value TEXT NOT NULL);",
    );
    db.prepare("INSERT OR IGNORE INTO setup (id, value) VALUES (1, ?)").run(
      JSON.stringify({
        revision: 0,
        workspace_name: null,
        inventory: [],
        updated_at: 0,
      } satisfies Setup),
    );
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

/** Next route-handler boundary. State is local public metadata, never custody authority. */
export async function handle(
  request: Request,
  directory = process.env.OIC_CONSOLE_STATE_DIR,
  demo = process.env.OIC_CONSOLE_DEMO === "1",
): Promise<Response> {
  const headers: Record<string, string> = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  let db: DatabaseSync | undefined;
  try {
    if (!consoleRequestAllowed(request, demo))
      throw new ApiError(403, "Console request origin is not allowed.");
    const path = new URL(request.url).pathname.replace(
      /^\/console-api\/v1\//,
      "",
    );
    const mutation = request.method !== "GET";
    const allowed =
      request.method === "GET"
        ? ["setup", "export"]
        : request.method === "POST"
          ? ["inventory/preview"]
          : request.method === "PUT"
            ? ["workspace", "inventory"]
            : [];
    if (!allowed.includes(path))
      throw new ApiError(404, "Unknown console command or query.");
    if (demo && request.method === "PUT")
      throw new ApiError(
        403,
        "The public sample is read-only. Saving is unavailable.",
      );
    const body = mutation ? await commandBody(request) : {};
    let setup: Setup;
    if (demo) {
      setup = {
        revision: 0,
        workspace_name: "Sample treasury",
        updated_at: 0,
        inventory: [
          {
            network: "ethereum-sepolia",
            address: "0x52908400098527886E0F7030069857D2E4169EE7",
            label: "EVM public example",
            imported_at: 0,
          },
          {
            network: "solana-devnet",
            address: "11111111111111111111111111111111",
            label: "Solana system program example",
            imported_at: 0,
          },
        ],
      };
    } else {
      if (!directory)
        throw new ApiError(
          503,
          "OIC_CONSOLE_STATE_DIR is not configured. Set a private local state directory and restart the console.",
        );
      db = openStore(directory);
      db.exec("BEGIN IMMEDIATE");
      const row = db.prepare("SELECT value FROM setup WHERE id = 1").get() as {
        value: string;
      };
      setup = JSON.parse(row.value) as Setup;
    }
    let result: unknown;
    let changed = false;
    if (path === "workspace" || path === "inventory") {
      exactFields(
        body,
        path === "workspace"
          ? ["base_revision", "name"]
          : ["base_revision", "csv"],
      );
      if (
        !Number.isSafeInteger(body.base_revision) ||
        (body.base_revision as number) < 0
      )
        throw new ApiError(
          422,
          "base_revision must be a nonnegative safe integer.",
        );
      if (setup.revision !== body.base_revision)
        throw new ApiError(
          409,
          "Setup changed in another request. Reload saved state before continuing.",
        );
      if (path === "workspace") {
        if (
          typeof body.name !== "string" ||
          !body.name.trim() ||
          !validLabel(body.name.trim())
        )
          throw new ApiError(
            422,
            "Use a workspace name of 1–80 bytes without control characters.",
          );
        setup.workspace_name = body.name.trim();
      } else {
        if (typeof body.csv !== "string")
          throw new ApiError(422, "csv must be a public-address CSV string.");
        const importPreview = preview(body.csv, setup);
        if (!importPreview.importable)
          throw new ApiError(
            422,
            "No new valid addresses to save. Inspect excluded rows.",
          );
        setup.inventory.push(
          ...importPreview.rows
            .filter((row) => row.status === "valid")
            .map((row) => ({
              network: row.network,
              address: row.address,
              label: row.label,
              imported_at: now(),
            })),
        );
      }
      setup.revision += 1;
      setup.updated_at = now();
      changed = true;
      result = snapshot(setup, demo);
    } else if (path === "inventory/preview") {
      exactFields(body, ["csv"]);
      if (typeof body.csv !== "string")
        throw new ApiError(422, "csv must be a public-address CSV string.");
      result = preview(body.csv, setup);
    } else if (path === "export") {
      headers["Content-Disposition"] =
        'attachment; filename="oic-watch-only-inventory.json"';
      result = {
        schema_version: 1,
        kind: "watch_only_inventory",
        exported_at: now(),
        source: demo ? "public_sample_fixtures" : "operator_public_address_csv",
        snapshot: { ...snapshot(setup, demo), sample_treasury: null },
        limitations: [
          demo
            ? "Read-only sample fixtures; no user data is saved. Not a custody audit."
            : "Unsigned local inventory, not a custody audit export.",
          "No chain discovery, ownership verification, balance observation or funds movement.",
          "Imported policy and signing authority are not supported.",
        ],
      };
    } else {
      result = snapshot(setup, demo);
    }
    if (changed)
      db!
        .prepare("UPDATE setup SET value = ? WHERE id = 1")
        .run(JSON.stringify(setup));
    db?.exec("COMMIT");
    return Response.json(result, { headers });
  } catch (error) {
    // No raw input, public addresses or database paths enter error responses/logs.
    return Response.json(
      {
        error:
          error instanceof ApiError
            ? error.message
            : "State unavailable. Check the console service and reload; do not reset saved setup.",
      },
      { status: error instanceof ApiError ? error.status : 500, headers },
    );
  } finally {
    db?.close();
  }
}
