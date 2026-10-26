import assert from "node:assert/strict";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { once } from "node:events";
import { test, type TestContext } from "node:test";
import { handleCustody } from "../src/lib/custody-server";

async function backend(
  t: TestContext,
  respond: (request: IncomingMessage, response: ServerResponse) => void,
) {
  const server = createServer(respond);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(
    () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      }),
  );
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const env = {
    OIC_CONSOLE_CUSTODY_ORIGIN: `http://127.0.0.1:${address.port}`,
    OIC_CONSOLE_CUSTODY_TOKEN: "test-only-console-capability",
  };
  const call = (
    path: string,
    method = "GET",
    body?: string,
    headers: Record<string, string> = {},
    overrides: Record<string, string> = {},
  ) =>
    handleCustody(
      new Request(`http://localhost:4174/custody-api/v1/${path}`, {
        method,
        headers: {
          host: "localhost:4174",
          "x-oic-console": "1",
          "content-type": "application/json",
          ...headers,
        },
        body,
      }),
      { ...env, ...overrides },
    );
  return { call, env };
}

test("local custody bridge preserves exact request/response JSON and stable idempotency", async (t) => {
  const exact = '{"sequence":9007199254740993,"amount":"125000000000000001"}';
  const { call } = await backend(t, async (request, response) => {
    assert.equal(
      request.headers.authorization,
      "Bearer test-only-console-capability",
    );
    assert.equal(request.headers.cookie, undefined);
    if (request.method === "POST") {
      let body = "";
      for await (const chunk of request) body += chunk;
      assert.equal(body, exact);
      assert.equal(request.headers["idempotency-key"], "persisted-intent-042");
      assert.equal(request.url, "/v1/intents");
    } else {
      assert.ok(
        [
          "/local/v1/catalog",
          "/local/v1/status",
          "/local/v1/intents",
          "/v1/intents/intent-042/preview",
          "/v1/operations/family-042/evidence",
          "/v1/wallets/evm-wallet/balances",
          "/v1/events?after=9007199254740993&limit=1000",
          "/v1/export",
        ].includes(request.url!),
      );
    }
    response.writeHead(200, {
      "content-type": "application/json",
      "set-cookie": "upstream-secret=must-not-reach-browser",
      "x-private": "must-not-reach-browser",
    });
    response.end(exact);
  });
  for (const path of [
    "catalog",
    "status",
    "intents",
    "intents/intent-042/preview",
    "operations/family-042/evidence",
    "wallets/evm-wallet/balances",
    "events?after=9007199254740993&limit=1000",
    "export",
  ]) {
    const response = await call(path, "GET", undefined, {
      authorization: "Bearer caller-cannot-select-authority",
      cookie: "browser-session=not-an-api-credential",
    });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), exact);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("set-cookie"), null);
    assert.equal(response.headers.get("x-private"), null);
    if (path === "export")
      assert.match(response.headers.get("content-disposition")!, /attachment/);
  }
  const created = await call("intents", "POST", exact, {
    "idempotency-key": "persisted-intent-042",
  });
  assert.equal(created.status, 200);
  assert.equal(await created.text(), exact);
});

test("samples, forbidden authority, remote origins and CSRF never reach the custody service", async (t) => {
  let reached = false;
  const { call } = await backend(t, (_request, response) => {
    reached = true;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  for (const path of [
    "controls",
    "../local/v1/controls",
    "intents/i/approvals",
    "admin",
    "catalog/../controls",
  ]) {
    assert.equal((await call(path, "POST")).status, 404);
  }
  const forbiddenHeaders: Record<string, string>[] = [
    { host: "intruder.example:4174" },
    { origin: "https://intruder.example" },
    { origin: "null" },
    { "sec-fetch-site": "cross-site" },
    { "x-oic-console": "" },
  ];
  for (const headers of forbiddenHeaders) {
    assert.equal(
      (await call("intents/i/submit", "POST", undefined, headers)).status,
      403,
    );
  }
  assert.equal(
    (await call("catalog", "GET", undefined, {}, { OIC_CONSOLE_DEMO: "1" }))
      .status,
    403,
  );
  assert.equal(
    (await call("catalog", "GET", undefined, {}, { VERCEL: "1" })).status,
    403,
  );
  for (const origin of [
    "https://public.example",
    "http://localhost:8787",
    "http://127.0.0.1:8787/unexpected",
    "http://user:password@127.0.0.1:8787",
    "http://127.0.0.1:8787/?redirect=remote",
  ]) {
    assert.equal(
      (
        await call(
          "catalog",
          "GET",
          undefined,
          {},
          { OIC_CONSOLE_CUSTODY_ORIGIN: origin },
        )
      ).status,
      503,
    );
  }
  const absent = await call(
    "catalog",
    "GET",
    undefined,
    {},
    { OIC_CONSOLE_CUSTODY_TOKEN: "" },
  );
  assert.equal(absent.status, 503);
  assert.equal(reached, false);
});

test("failed or ambiguous submission is not retried, redirected, or presented as a safe replacement", async (t) => {
  let redirected = false;
  let submissions = 0;
  const target = await backend(t, (_request, response) => {
    redirected = true;
    response.end("must not follow");
  });
  const { call } = await backend(t, (request, response) => {
    submissions++;
    if (request.url === "/v1/intents/redirect/submit") {
      response.writeHead(307, {
        location: `${target.env.OIC_CONSOLE_CUSTODY_ORIGIN}/steal`,
      });
      response.end();
    } else if (request.url === "/v1/intents/disconnected/submit") {
      request.socket.destroy();
    } else if (request.url === "/v1/intents/malformed/submit") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{partial-json");
    } else if (request.url === "/v1/intents/denied/submit") {
      response.writeHead(409, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          code: "POLICY_DENIED",
          detail: "[EvidenceStale]; stale evidence cannot be refreshed",
        }),
      );
    } else {
      response.writeHead(409, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          code: "ISSUANCE_UNCERTAIN",
          detail: "private backend diagnostic",
        }),
      );
    }
  });
  for (const id of ["uncertain", "redirect", "disconnected", "malformed"]) {
    const response = await call(`intents/${id}/submit`, "POST");
    assert.equal(response.status, id === "uncertain" ? 409 : 502);
    const body = await response.json();
    assert.equal(body.outcome_unknown, true);
    assert.match(body.error, /Inspect the existing intent and operation/);
    assert.doesNotMatch(
      JSON.stringify(body),
      /private backend diagnostic|test-only-console-capability|steal/,
    );
  }
  // A definitive policy denial is reported as a rejection with the backend's
  // code and detail, not as an unknown outcome.
  const denied = await call("intents/denied/submit", "POST");
  assert.equal(denied.status, 409);
  const deniedBody = await denied.json();
  assert.equal(deniedBody.outcome_unknown, false);
  assert.match(deniedBody.error, /POLICY_DENIED/);
  assert.match(deniedBody.error, /stale evidence cannot be refreshed/);
  assert.equal(submissions, 5);
  assert.equal(redirected, false);
});

test("creation and replay validate both sides of request limits without rounding event cursors", async (t) => {
  let reached = 0;
  const { call } = await backend(t, async (request, response) => {
    reached++;
    for await (const _chunk of request) {
      /* consume the bounded request */
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  for (const path of [
    "events?after=18446744073709551616",
    "events?after=-1",
    "events?after=01",
    "events?limit=0",
    "events?limit=1001",
    "events?limit=1&limit=2",
    "events?upstream=http://intruder.example",
    "catalog?token=not-forwarded",
  ]) {
    assert.equal((await call(path)).status, 400);
  }
  assert.equal((await call("intents", "POST", "{}")).status, 400);
  const headers = { "idempotency-key": "one-intent-only" };
  for (const body of ["", "null", "[]", "{not-json"]) {
    assert.equal((await call("intents", "POST", body, headers)).status, 400);
  }
  assert.equal(
    (
      await call("intents", "POST", "{}", {
        ...headers,
        "content-type": "text/plain",
      })
    ).status,
    415,
  );
  assert.equal((await call("intents/i/submit", "POST", "{}")).status, 400);
  const exact = `{"value":"${"x".repeat(1024 * 1024 - 12)}"}`;
  assert.equal(Buffer.byteLength(exact), 1024 * 1024);
  assert.equal(
    (await call("intents", "POST", exact + " ", headers)).status,
    413,
  );
  assert.equal(reached, 0);
  assert.equal((await call("intents", "POST", exact, headers)).status, 200);
  assert.equal(
    (await call("events?after=18446744073709551615&limit=1")).status,
    200,
  );
  assert.equal(reached, 2);
});
