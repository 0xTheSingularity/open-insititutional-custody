export function localRequestAllowed(request: Request): boolean {
  const port =
    new URL(process.env.OIC_CONSOLE_ORIGIN ?? "http://127.0.0.1:4174").port ||
    "80";
  const hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
  const host = request.headers.get("host");
  const origin = request.headers.get("origin");
  return (
    host !== null &&
    hosts.includes(host) &&
    (origin === null || hosts.some((host) => origin === `http://${host}`)) &&
    request.headers.get("sec-fetch-site") !== "cross-site" &&
    (["GET", "HEAD"].includes(request.method) ||
      request.headers.get("x-oic-console") === "1")
  );
}
