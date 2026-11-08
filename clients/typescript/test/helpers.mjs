import { createServer } from "node:http";
import { readFileSync } from "node:fs";

export const vectors = JSON.parse(
  readFileSync(new URL("../testdata/vectors.json", import.meta.url), "utf8"),
);

/**
 * Starts a local fake sidecar. `handler(req, body)` returns
 * `{status, body, headers?, delayMs?, destroy?}`; every request is recorded.
 */
export async function fakeServer(handler) {
  const requests = [];
  const server = createServer((req, res) => {
    let chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const rec = { method: req.method, url: req.url, headers: req.headers, body };
      requests.push(rec);
      const r = await handler(rec, requests.length);
      if (r.delayMs) await new Promise((ok) => setTimeout(ok, r.delayMs));
      if (r.destroy) {
        req.socket.destroy();
        return;
      }
      const text = typeof r.body === "string" ? r.body : JSON.stringify(r.body);
      res.writeHead(r.status, { "content-type": "application/json", "x-request-id": "req-1", ...(r.headers ?? {}) });
      res.end(text);
    });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise((ok) => {
        server.closeAllConnections?.();
        server.close(() => ok());
      }),
  };
}

export function vector(name) {
  const v = vectors.vectors.find((x) => x.name === name);
  if (!v) throw new Error(`no vector ${name}`);
  return v;
}
