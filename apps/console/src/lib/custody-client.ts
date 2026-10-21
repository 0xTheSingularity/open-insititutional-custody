export class CustodyRequestError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly outcomeUnknown: boolean,
  ) {
    super(message);
  }
}

export async function custodyRequest(
  path: string,
  options: {
    method?: "GET" | "POST";
    body?: unknown;
    idempotencyKey?: string;
  } = {},
): Promise<unknown> {
  const method = options.method ?? "GET";
  let response: Response;
  try {
    response = await fetch(`/custody-api/v1/${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-OIC-Console": "1",
        ...(options.idempotencyKey
          ? { "Idempotency-Key": options.idempotencyKey }
          : {}),
      },
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
      cache: "no-store",
      signal: AbortSignal.timeout(35000),
    });
  } catch {
    throw new CustodyRequestError(
      "The local custody service did not acknowledge this request. Inspect saved intent and operation records before repeating an action.",
      null,
      method === "POST",
    );
  }
  const value: unknown = await response.json().catch(() => null);
  if (!response.ok || value === null) {
    const error =
      value &&
      typeof value === "object" &&
      "error" in value &&
      typeof value.error === "string"
        ? value.error
        : "The custody response was not readable. Reload authoritative state before acting.";
    throw new CustodyRequestError(error, response.status, method === "POST");
  }
  return value;
}
