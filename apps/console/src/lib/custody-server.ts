import { Buffer } from "node:buffer";
import { consoleRequestAllowed } from "./boundary";

const MAX_BODY = 1024 * 1024;
const TIMEOUT_MS = 30000;
const responseHeaders = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function failure(status: number, error: string, outcomeUnknown = false) {
  return Response.json(
    { error, outcome_unknown: outcomeUnknown },
    { status, headers: responseHeaders },
  );
}

// Keep this list narrower than the backend: no approval grant ingestion,
// simulator controls, administrative updates, or caller-selected upstream URL.
function upstreamPath(path: string, method: string): string | null {
  if (method === "GET" && path === "catalog") return "/local/v1/catalog";
  if (method === "GET" && path === "status") return "/local/v1/status";
  if (method === "GET" && path === "intents") return "/local/v1/intents";
  if (method === "POST" && path === "intents") return "/v1/intents";
  if (method === "GET" && ["events", "export"].includes(path)) {
    return `/v1/${path}`;
  }
  const parts = path.split("/");
  const [resource, encodedId, action] = parts;
  if (parts.length < 2 || parts.length > 3) return null;
  let id: string;
  try {
    id = decodeURIComponent(encodedId);
  } catch {
    return null;
  }
  if (!/^[\x21-\x7e]{1,128}$/.test(id) || id === "." || id === "..") {
    return null;
  }
  const allowed =
    (resource === "intents" &&
      ((method === "GET" && (!action || action === "preview")) ||
        (method === "POST" && ["submit", "cancel"].includes(action)))) ||
    (resource === "operations" &&
      ((method === "GET" && (!action || action === "evidence")) ||
        (method === "POST" && action === "refresh"))) ||
    (resource === "wallets" && method === "GET" && action === "balances");
  if (!allowed) return null;
  return `/v1/${resource}/${encodeURIComponent(id)}${action ? `/${action}` : ""}`;
}

function eventQuery(query: URLSearchParams): string | null {
  for (const key of query.keys()) {
    if (!["after", "limit"].includes(key) || query.getAll(key).length !== 1) {
      return null;
    }
  }
  const after = query.get("after");
  const limit = query.get("limit");
  if (
    (after !== null &&
      (!/^(0|[1-9][0-9]{0,19})$/.test(after) ||
        BigInt(after) > 18446744073709551615n)) ||
    (limit !== null &&
      (!/^[1-9][0-9]{0,3}$/.test(limit) || Number(limit) > 1000))
  ) {
    return null;
  }
  return query.size ? `?${query}` : "";
}

/**
 * Local simulator bridge, not institution login or a production control plane.
 * The route is unavailable in hosted/sample environments. Its bearer is the
 * local stack's read/propose/submit capability, never an approval credential.
 */
export async function handleCustody(
  request: Request,
  env: Readonly<Record<string, string | undefined>> = process.env,
): Promise<Response> {
  if (env.OIC_CONSOLE_DEMO === "1" || env.VERCEL) {
    return failure(403, "Custody integration is disabled in hosted samples.");
  }
  if (!consoleRequestAllowed(request)) {
    return failure(403, "Console request origin is not allowed.");
  }
  const url = new URL(request.url);
  const prefix = "/custody-api/v1/";
  if (!url.pathname.startsWith(prefix)) return failure(404, "Route not found.");
  const path = url.pathname.slice(prefix.length);
  const upstream = upstreamPath(path, request.method);
  if (!upstream)
    return failure(404, "Custody route or action is not available.");
  const query = path === "events" ? eventQuery(url.searchParams) : "";
  if (query === null || (path !== "events" && url.search)) {
    return failure(400, "Invalid custody query parameters.");
  }

  const token = env.OIC_CONSOLE_CUSTODY_TOKEN;
  let origin: URL;
  try {
    origin = new URL(env.OIC_CONSOLE_CUSTODY_ORIGIN ?? "http://127.0.0.1:8787");
    if (
      origin.protocol !== "http:" ||
      origin.hostname !== "127.0.0.1" ||
      origin.pathname !== "/" ||
      origin.username ||
      origin.password ||
      origin.search ||
      origin.hash ||
      !token ||
      !/^[A-Za-z0-9._~+/-]+=*$/.test(token)
    ) {
      throw new Error("Invalid local configuration");
    }
  } catch {
    return failure(503, "The local custody connection is not configured.");
  }

  const mutation = request.method === "POST";
  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
  };
  let body: string | undefined;
  if (mutation) {
    if (path === "intents") {
      const key = request.headers.get("idempotency-key");
      if (!key || !/^[\x21-\x7e]{1,128}$/.test(key)) {
        return failure(
          400,
          "A stable Idempotency-Key is required for this intent.",
        );
      }
      headers["Idempotency-Key"] = key;
      if (
        request.headers.get("content-type")?.split(";")[0] !==
        "application/json"
      ) {
        return failure(415, "Intent requests require application/json.");
      }
    }
    try {
      // Bound the stream, not just Content-Length, which may be absent or false.
      const reader = request.body?.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      if (reader) {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > MAX_BODY) {
              await reader.cancel();
              return failure(413, "Custody request exceeds 1 MiB.");
            }
            chunks.push(value);
          }
        } finally {
          reader.releaseLock();
        }
      }
      if (size) {
        if (path !== "intents") {
          return failure(400, "This custody action does not accept a body.");
        }
        body = new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.concat(chunks),
        );
        const value: unknown = JSON.parse(body);
        if (
          value === null ||
          typeof value !== "object" ||
          Array.isArray(value)
        ) {
          return failure(400, "An intent JSON object is required.");
        }
        headers["Content-Type"] = "application/json";
      } else if (path === "intents") {
        return failure(400, "An intent JSON object is required.");
      }
    } catch {
      return failure(
        400,
        "The custody request body could not be read as JSON.",
      );
    }
  }

  const unknown =
    "The custody service did not confirm the outcome. Inspect the existing intent and operation before repeating any action; do not create a replacement payment.";
  try {
    const response = await fetch(`${origin.origin}${upstream}${query}`, {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      return failure(
        502,
        mutation ? unknown : "The custody service redirected unexpectedly.",
        mutation,
      );
    }
    if (!response.ok) {
      // A mutation refused with a known definitive error code did not happen:
      // report the backend's {code, detail} envelope (sanitized) instead of
      // the unknown-outcome message. Any other failure — ISSUANCE_UNCERTAIN,
      // an unknown code, an unreadable body — keeps the fail-safe unknown
      // message, and no other backend body text is ever reflected.
      if (
        mutation &&
        response.status >= 400 &&
        response.status < 500 &&
        response.headers.get("content-type")?.split(";")[0] ===
          "application/json"
      ) {
        // Reflect only the backend's error CODE, never its detail text: a
        // detail can carry sensitive diagnostics (for example a
        // credential-bearing RPC URL). The explanation shown is authored
        // here, per code. Only the create route is ever definitive: no
        // signing can have happened for an intent whose create returned
        // 4xx. On submit, several codes (NOT_FOUND from a missing
        // broadcaster client, STALE_EVIDENCE from a chain client) can
        // arrive AFTER a signature exists, so every submit, cancel, or
        // refresh error keeps the fail-safe unknown-outcome instruction,
        // with the code named for context.
        const explain: Record<string, string> = {
          POLICY_DENIED: "policy refused this action",
          INVALID_REQUEST: "the request was invalid",
          SCOPE_MISMATCH: "this credential lacks the required permission",
          NOT_FOUND: "the custody service does not know this record",
          APPROVAL_REQUIRED: "the approval quorum is incomplete",
          STALE_EVIDENCE:
            "the candidate's chain evidence expired and cannot be refreshed; a new intent must be created and approved within the evidence window",
          BUDGET_EXCEEDED:
            "a policy budget or rolling limit refused this amount",
        };
        let code: string | undefined;
        try {
          const raw = await response.text();
          if (raw.length <= 4096) {
            const parsed: unknown = JSON.parse(raw);
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
              const claimed = (parsed as { code?: unknown }).code;
              if (
                typeof claimed === "string" &&
                /^[A-Z0-9_]{1,64}$/.test(claimed)
              ) {
                code = claimed;
              }
            }
          }
        } catch {
          // Unreadable body: report without a code.
        }
        const meaning = code ? explain[code] : undefined;
        if (path === "intents" && code && meaning) {
          return failure(
            response.status,
            `The custody service rejected this request (${code}): ${meaning}. No intent was created.`,
            false,
          );
        }
        return failure(
          response.status,
          code && meaning
            ? `The custody service reported ${code}: ${meaning}. ${unknown}`
            : unknown,
          true,
        );
      }
      await response.body?.cancel();
      return failure(
        response.status,
        mutation
          ? unknown
          : `The custody service could not return this record (${response.status}).`,
        mutation,
      );
    }
    if (
      response.headers.get("content-type")?.split(";")[0] !== "application/json"
    ) {
      await response.body?.cancel();
      return failure(
        502,
        mutation ? unknown : "The custody response was not JSON.",
        mutation,
      );
    }
    const text = await response.text();
    JSON.parse(text);
    // Preserve original JSON bytes: u64 event sequences and signed packages
    // must not be rounded by a JavaScript parse/stringify round trip.
    return new Response(text, {
      status: response.status,
      headers: {
        ...responseHeaders,
        ...(path === "export"
          ? {
              "Content-Disposition":
                'attachment; filename="oic-local-custody-export.json"',
            }
          : {}),
      },
    });
  } catch {
    return failure(
      502,
      mutation ? unknown : "The local custody service is unavailable.",
      mutation,
    );
  }
}
