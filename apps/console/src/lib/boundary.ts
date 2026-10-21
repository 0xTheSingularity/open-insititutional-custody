export function consoleRequestAllowed(request: Request, demo = false): boolean {
  const port =
    new URL(process.env.OIC_CONSOLE_ORIGIN ?? "http://127.0.0.1:4174").port ||
    "80";
  const hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
  const host = request.headers.get("host");
  const origins = demo
    ? [`${new URL(request.url).protocol}//${host}`]
    : hosts.map((host) => `http://${host}`);
  const origin = request.headers.get("origin");
  return (
    host !== null &&
    (demo || hosts.includes(host)) &&
    (origin === null || origins.includes(origin)) &&
    request.headers.get("sec-fetch-site") !== "cross-site" &&
    (["GET", "HEAD"].includes(request.method) ||
      request.headers.get("x-oic-console") === "1")
  );
}
