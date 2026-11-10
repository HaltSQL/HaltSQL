import { createServer } from "node:http";
import { readFileSync } from "node:fs";

/** The lab Postgres (make -C lab up), or the one named by HALTSQL_PG*. */
export const PG = {
  host: process.env.HALTSQL_PGHOST ?? "localhost",
  port: Number(process.env.HALTSQL_PGPORT ?? 5417),
  user: process.env.HALTSQL_PGUSER ?? "postgres",
  password: process.env.HALTSQL_PGPASSWORD ?? "haltlab",
};

let reachable;

/**
 * Whether Postgres answers. Tests that need it skip when it does not, unless
 * HALTSQL_REQUIRE_POSTGRES=1 (set in CI): then this throws, which fails the
 * test file instead of skipping its Postgres tests.
 */
export async function pgReachable() {
  if (reachable === undefined) {
    const { default: pg } = await import("pg");
    const c = new pg.Client({ ...PG, database: "postgres", connectionTimeoutMillis: 1500 });
    try {
      await c.connect();
      await c.end();
      reachable = true;
    } catch (e) {
      reachable = false;
      console.log(`# skipping Postgres tests: ${PG.host}:${PG.port} not reachable (run: make -C lab up)`);
      if (process.env.HALTSQL_REQUIRE_POSTGRES === "1") {
        throw new Error(`HALTSQL_REQUIRE_POSTGRES=1 but Postgres at ${PG.host}:${PG.port} is not reachable: ${e}`);
      }
    }
  }
  return reachable;
}

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
