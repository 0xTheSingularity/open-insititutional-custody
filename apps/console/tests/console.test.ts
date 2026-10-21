import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { handle } from "../src/lib/server";
import type { Snapshot, Preview } from "../src/lib/contracts";

function client(t: TestContext) {
  const directory = mkdtempSync(join(tmpdir(), "oic-console-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const call = async <T = Snapshot>(
    path: string,
    method = "GET",
    body?: unknown,
    headers: Record<string, string> = {},
  ) => {
    const request = new Request(
      `http://localhost:4174/console-api/v1/${path}`,
      {
        method,
        headers: {
          host: "localhost:4174",
          "content-type": "application/json",
          "x-oic-console": "1",
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
    );
    const response = await handle(request, directory);
    return {
      status: response.status,
      body: (await response.json()) as T,
      headers: response.headers,
    };
  };
  return {
    directory,
    call,
    workspace: () =>
      call("workspace", "PUT", {
        base_revision: 0,
        name: "Treasury evaluation",
      }),
  };
}

const evm = "0x52908400098527886E0F7030069857D2E4169EE7";
const solana = "11111111111111111111111111111111";

test("watch-only discovery previews exclusions, persists valid rows, and resumes without duplicates", async (t) => {
  const { call, workspace } = client(t);
  assert.equal((await workspace()).status, 200);
  const csv = `network,address,label\nethereum-mainnet,${evm},"Treasury, source A"\nethereum-mainnet,${evm.toLowerCase()},Duplicate\nethereum-sepolia,${evm},Test\nsolana-devnet,${solana},Solana example\nbitcoin-mainnet,not-supported,Unsupported\nethereum-mainnet,not-a-public-address,Invalid`;
  const preview = await call<Preview>("inventory/preview", "POST", { csv });
  assert.equal(preview.status, 200);
  assert.equal(preview.body.importable, 3);
  assert.equal(preview.body.excluded, 3);
  assert.deepEqual(
    preview.body.rows.map((row) => row.status),
    ["valid", "duplicate", "valid", "valid", "unsupported", "invalid"],
  );
  assert.deepEqual((await call("setup")).body.setup.inventory, []);
  const saved = await call("inventory", "PUT", { base_revision: 1, csv });
  assert.equal(saved.status, 200);
  assert.equal(saved.body.setup.revision, 2);
  assert.equal(saved.body.setup.inventory[0].label, "Treasury, source A");
  // Every call opens a fresh SQLite connection, so this is a disk reload, not a cache assertion.
  assert.deepEqual((await call("setup")).body.setup, saved.body.setup);
  assert.equal((await call("setup")).body.sample_treasury, null);
  assert.equal(
    (await call<Preview>("inventory/preview", "POST", { csv })).body.importable,
    0,
  );
  assert.equal(
    (await call("inventory", "PUT", { base_revision: 2, csv })).status,
    422,
  );
  const report = await call<{ kind: string; snapshot: Snapshot }>("export");
  assert.equal(report.body.kind, "watch_only_inventory");
  assert.equal(report.body.snapshot.setup.inventory.length, 3);
  assert.equal(report.body.snapshot.production_ready, false);
  assert.match(report.headers.get("content-disposition")!, /attachment/);
  assert.doesNotMatch(
    JSON.stringify(report.body),
    /not-a-public-address|not-supported/,
  );
});

test("stale, malformed, and authority-expanding commands leave saved state unchanged", async (t) => {
  const { call, workspace } = client(t);
  assert.equal(
    (
      await call("inventory/preview", "POST", {
        csv: "network,address,label\n",
      })
    ).status,
    409,
  );
  await workspace();
  const concurrent = await Promise.all([
    call("workspace", "PUT", { base_revision: 1, name: "Winner" }),
    call("workspace", "PUT", { base_revision: 1, name: "Stale writer" }),
  ]);
  assert.deepEqual(
    concurrent.map((r) => r.status),
    [200, 409],
  );
  for (const csv of [
    "private_key,address,label\nsecret,x,y",
    "network,address,label\nethereum-mainnet,abc",
    "network,address,label\n",
    '"network,address,label"\n"ethereum-mainnet"',
  ]) {
    assert.equal(
      (await call("inventory", "PUT", { base_revision: 2, csv })).status,
      422,
    );
  }
  assert.equal(
    (
      await call("workspace", "PUT", {
        base_revision: 2,
        name: "Escalation",
        production_ready: true,
      })
    ).status,
    422,
  );
  const state = (await call("setup")).body;
  assert.equal(state.setup.workspace_name, "Winner");
  assert.equal(state.setup.revision, 2);
  assert.equal(state.production_ready, false);
  assert.equal(state.blockers.length, 5);
});

test("EIP-55 checksum, Solana byte length, and both sides of the CSV limits are enforced", async (t) => {
  const { call, workspace } = client(t);
  await workspace();
  const csv = `network,address,label\nethereum-mainnet,0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed,Valid\nethereum-mainnet,0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed,Flipped checksum nibble\nsolana-devnet,${"1".repeat(31)},31 bytes\nsolana-devnet,${"1".repeat(33)},33 bytes\nsolana-devnet,${"0".repeat(32)},Not base58`;
  const result = await call<Preview>("inventory/preview", "POST", { csv });
  assert.equal(result.body.importable, 1);
  assert.equal(result.body.excluded, 4);
  assert.equal(result.body.rows[1].address, "Not retained");
  const row = `ethereum-mainnet,${evm},Example\n`;
  assert.equal(
    (
      await call("inventory/preview", "POST", {
        csv: `network,address,label\n${row.repeat(500)}`,
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await call("inventory/preview", "POST", {
        csv: `network,address,label\n${row.repeat(501)}`,
      })
    ).status,
    422,
  );
  assert.equal(
    (await call("inventory/preview", "POST", { csv: "a".repeat(128 * 1024) }))
      .status,
    413,
  );
});

test("direct API calls reject cross-origin access, DNS rebinding, and CSRF without writing", async (t) => {
  const { call } = client(t);
  const blockedHeaders: Record<string, string>[] = [
    { host: "attacker.example:4174" },
    { origin: "https://attacker.example" },
    { origin: "null" },
    { "x-oic-console": "" },
    { "sec-fetch-site": "cross-site" },
  ];
  for (const headers of blockedHeaders) {
    assert.equal(
      (
        await call(
          "workspace",
          "PUT",
          { base_revision: 0, name: "Intruder" },
          headers,
        )
      ).status,
      403,
    );
  }
  const result = await call("setup");
  assert.equal(result.body.setup.revision, 0);
  assert.equal(result.body.setup.workspace_name, null);
  assert.equal(result.headers.get("cache-control"), "no-store");
});

test("corrupt local storage fails closed instead of creating a replacement workspace", async (t) => {
  const { directory, call, workspace } = client(t);
  await workspace();
  const path = join(directory, "console.sqlite");
  writeFileSync(path, "corrupt database");
  assert.equal((await call("setup")).status, 500);
  assert.equal(readFileSync(path, "utf8"), "corrupt database");
});

test("public demo serves only sample fixtures, previews without persistence, and refuses writes", async (t) => {
  const { directory } = client(t);
  const store = join(directory, "console.sqlite");
  writeFileSync(store, "must not be opened by the public demo");
  const call = (path: string, method = "GET", body?: unknown, headers = {}) =>
    handle(
      new Request(`https://demo.example/console-api/v1/${path}`, {
        method,
        headers: {
          host: "demo.example",
          origin: "https://demo.example",
          "x-oic-console": "1",
          "content-type": "application/json",
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
      directory,
      true,
    );
  const response = await call("setup");
  assert.equal(response.status, 200);
  const before = (await response.json()) as Snapshot;
  assert.equal(before.mode, "demo");
  assert.equal(before.local_only, false);
  assert.equal(before.preflight.durable_state, false);
  assert.equal(before.production_ready, false);
  assert.equal(before.setup.inventory.length, 2);
  assert.equal(before.sample_treasury?.source, "illustrative_fixtures");
  const uncertain = before.sample_treasury?.transfers.find(
    (transfer) => transfer.id === "sample-eth-042",
  );
  assert.equal(uncertain?.state, "SubmissionUnknown");
  assert.equal(uncertain?.amount_units, "125000000000000001");
  assert.equal(uncertain?.reserved_units, "125042000000000001");
  assert.equal(uncertain?.reconciliation, "pending");
  const finalized = before.sample_treasury?.transfers.find(
    (transfer) => transfer.id === "sample-sol-040",
  );
  assert.equal(finalized?.state, "FinalizedSuccess");
  assert.equal(finalized?.reconciliation, "pending");
  const csv = `network,address,label\nethereum-sepolia,0x000000000000000000000000000000000000dead,New example\nethereum-sepolia,${evm},Duplicate`;
  const previewResponse = await call("inventory/preview", "POST", { csv });
  assert.equal(previewResponse.status, 200);
  const preview = (await previewResponse.json()) as Preview;
  assert.equal(preview.importable, 1);
  assert.equal(preview.excluded, 1);
  // Next normalizes the URL's loopback hostname, but keeps the original Host.
  const normalized = await handle(
    new Request("http://localhost:4175/console-api/v1/inventory/preview", {
      method: "POST",
      headers: {
        host: "127.0.0.1:4175",
        origin: "http://127.0.0.1:4175",
        "x-oic-console": "1",
        "content-type": "application/json",
      },
      body: JSON.stringify({ csv }),
    }),
    directory,
    true,
  );
  assert.equal(normalized.status, 200);
  assert.equal(
    (await call("workspace", "PUT", { base_revision: 0, name: "Intruder" }))
      .status,
    403,
  );
  assert.equal(
    (await call("inventory", "PUT", { base_revision: 0, csv })).status,
    403,
  );
  assert.equal(
    (
      await call(
        "inventory/preview",
        "POST",
        { csv },
        { origin: "https://attacker.example" },
      )
    ).status,
    403,
  );
  assert.equal(
    (await call("inventory/preview", "POST", { csv }, { "x-oic-console": "" }))
      .status,
    403,
  );
  assert.deepEqual(await (await call("setup")).json(), before);
  const report = await (await call("export")).json();
  assert.equal(report.source, "public_sample_fixtures");
  assert.equal(report.snapshot.mode, "demo");
  assert.equal(report.snapshot.sample_treasury, null);
  assert.doesNotMatch(JSON.stringify(report), /New example|Intruder/);
  assert.equal(
    readFileSync(store, "utf8"),
    "must not be opened by the public demo",
  );
});
