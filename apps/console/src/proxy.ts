import { NextResponse, type NextRequest } from "next/server";
import { consoleRequestAllowed } from "./lib/boundary";

export function proxy(request: NextRequest) {
  if (!consoleRequestAllowed(request, process.env.OIC_CONSOLE_DEMO === "1")) {
    return NextResponse.json(
      { error: "Console request origin is not allowed." },
      { status: 403 },
    );
  }
  const nonce = btoa(crypto.randomUUID());
  const development = process.env.NODE_ENV !== "production";
  const csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}'${development ? " 'unsafe-eval'" : ""}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'${development ? " ws://127.0.0.1:* ws://localhost:*" : ""}; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
  const headers = new Headers(request.headers);
  headers.set("Content-Security-Policy", csp);
  headers.set("x-nonce", nonce);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("Cache-Control", "no-store");
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
