import { NextResponse, type NextRequest } from "next/server";
import { localRequestAllowed } from "./lib/boundary";

export function proxy(request: NextRequest) {
  if (!localRequestAllowed(request)) {
    return NextResponse.json(
      { error: "Local same-origin console requests only." },
      { status: 403 },
    );
  }
  const nonce = btoa(crypto.randomUUID());
  const development = process.env.NODE_ENV !== "production";
  const csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}'${development ? " 'unsafe-eval'" : ""}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'${development ? " ws://127.0.0.1:* ws://localhost:*" : ""}; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
  const headers = new Headers(request.headers);
  headers.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("Cache-Control", "no-store");
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
