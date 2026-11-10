# HaltSQL Console: architecture

The console is a control plane for a HaltSQL deployment. It never sits in the
query path: agents keep talking to `haltsql-server`, `haltsql-proxy` or
`haltsql-mcp`, and the console only **reads** what those verifiers already
publish (audit records, `/v1/admin/status`, `/v1/admin/report`, `/readyz`) plus
the policy and catalog files the verifiers load. If the console is down,
nothing about enforcement changes.

```
             agents (SDKs, LangChain, LlamaIndex, Vanna, CrewAI, ADK, MCP clients, psql)
                │ verify / wire protocol / MCP
                ▼
   ┌───────────────────────────┐   audit JSONL (file, S3, GCS)   ┌──────────────────────┐
   │ haltsql-server / proxy /  │ ───────────────────────────────▶│                      │
   │ haltsql-mcp  (verifiers)  │   GET /v1/admin/status, report, │   haltsql-console    │──▶ browser (frontend, later PR)
   │                           │◀─────── /readyz, /metrics ──────│   /api/v1/*          │──▶ GitHub, Slack, PagerDuty
   └───────────────────────────┘                                 │                      │
         ▲ policies / bundles / catalogs (same files)            └──────────┬───────────┘
         └──────────────────────────────────────────────────────────────────┘
                                                                  state_dir (cases, activity,
                                                                  signal state, evidence packs)
```

## Process

`haltsql-console` is an OCaml binary in the `haltsql-server` opam package
(`bin/console`, private library `haltsql_console` in `bin/console/lib`). It
reuses the libraries the verifiers use, so the console and the verifiers can't
disagree about what a record means or what a policy allows:

| Concern | Library reused |
|---|---|
| Parse audit records from server and proxy | `haltsql.report` (`Record`) |
| Shadow report and suggestions | `haltsql.report` (`Summary`, `Suggest`) |
| Re-verify a record, Playground | `haltsql` (`Haltsql.verify`, `Policy_load`) |
| Audit hash chain | `haltsql.cloud` (`Audit_chain`) |
| S3/GCS listing and secrets | `haltsql.cloud` |
| Data catalogs (dbt, DataHub, Unity, OpenMetadata) | `haltsql.catalog_fetch`, `haltsql.catalog_tools` |
| OIDC token verification | `haltsql-server.auth` (`Oidc_client`) |
| HTTP | `cohttp-lwt-unix`, same as `haltsql-server` |

## Modules (`bin/console/lib`)

| Module | Role |
|---|---|
| `Console_config` | YAML config: listen, environment, auth, verifiers, audit sources, policies, catalogs, integrations. |
| `Rbac` | The five roles and the permission matrix, an exhaustive `grant : role -> permission -> grant` (see [api.md](api.md#roles)). A principal's access is `grant_union` over all of its roles; `precedence` only picks the display role. |
| `Console_auth` | Authenticates a request: OIDC bearer, trusted auth-proxy headers, static service tokens, or dev mode. |
| `Store` | Durable JSON documents in `state_dir` (one JSONL file per collection, rewritten atomically). |
| `Activity` | Append-only activity log ("who saw or did what, and why"). |
| `Index` | In-memory index of audit records for the retention window, with search and aggregation. |
| `Ctx` | The shared runtime context passed to every handler: config, store, index, a typed per-feature state registry, and `require` for permission checks. |
| `Api` | JSON responses, errors, query parameters, body parsing. |
| `Router` | Method and path-pattern routing; collects every feature's routes. |
| feature modules | `Overview`, `Signals`, `Records`, `Cases`, `Agents`, `Playground`, `Policies`, `Fleet`, `Data`, `Evidence`, `Access`. Each exports `routes` and, when it needs one, a background `start` loop. |
| `Console_server` | Listener, background loops, graceful shutdown, static frontend. |

## Data flow

1. **Audit ingestion** (`Ingest`): every `audit.sources` entry (file glob,
   directory, `s3://`, `gs://`) is polled; new lines are parsed with
   `Report.Record.of_line` and added to the `Index` with their request id,
   hash, previous hash, verifier name and location (file and line or object
   key). Records older than `audit.retention_hours` are dropped.
2. **Fleet polling** (`Fleet`): every `fleet.poll_seconds` (with jitter)
   each configured verifier's `/v1/admin/status` (with its admin token),
   `/readyz` (no token) and `/metrics` (the token only when `metrics_url` has
   the verifier's own origin) are read, at most
   `fleet.max_concurrent_probes` verifiers at a time; unreachable verifiers
   back off. A `kind: proxy` verifier with a non-HTTP url gets a TCP connect
   check instead. The token goes only over https (verified with
   `verifiers[].ca_file` or the system store) or loopback http, unless
   `allow_insecure_http` is set. The last snapshot and its history feed
   Fleet, Posture and Signals.
3. **Signals** (`Signals`): detectors run over the index and the fleet
   snapshot every 30 seconds and open, update or close signals. Their
   workflow state (assignee, status, acknowledgement) is kept in `Store`.
4. **Policies** (`Policies`): the console loads the same policy files or
   server config as the verifiers, to run the Playground, re-derive decision
   trails and compute exposure of tagged columns. Shadow reports come from the
   index (and, when configured, each verifier's `/v1/admin/report`).

## Feature state

`Ctx.t` carries only what every feature shares (config, store, index, start
time). It has no per-feature fields. Runtime state a feature derives (the
fleet snapshot, loaded policies, catalog tags, ingestion and audit-chain
status) lives in a typed, heterogeneous registry on the context:

```ocaml
module Key : sig type 'a t val create : string -> 'a t end
val get : Ctx.t -> 'a Key.t -> 'a option
val set : Ctx.t -> 'a Key.t -> 'a -> unit
```

Each feature declares its key privately and exports read accessors only:

```ocaml
(* fleet.ml *)
let state : Fleet_state.t Ctx.Key.t = Ctx.Key.create "fleet"
let snapshot ctx = Ctx.get ctx state       (* exported *)
(* the poll loop calls Ctx.set ctx state s *)
```

Because the key isn't exported, only the owning module can write its state;
other features read it through the owner's accessors, with the owner's types.
Adding a feature never edits `Ctx`. Keys are built on `Type.Id`, so two keys
never collide even with the same name, and `get` before the first `set` is
`None`.

## Persistence

Everything the console derives (index, fleet snapshots, signals) is rebuilt
from the verifiers on restart. Only human input is durable, in `state_dir`:
cases, signal workflow state, activity log, evidence packs. One replica per
environment; `state_dir` on a persistent volume. The store is a deliberate
seam: a Postgres-backed `Store` is a later change and needs no API change.

## Security

- The console holds verifier **admin** tokens (read-only endpoints) and,
  optionally, a GitHub token and webhook URLs. All are read from the secrets
  manager through the same `${vault:...}`, `${aws-sm:...}`, `${gcp-sm:...}`
  and `${env:...}` placeholders as the server config.
- Raw SQL is never returned by search endpoints. `GET /records/{id}/sql`
  requires the `see_raw_sql` permission and a reason, and the view is written
  to the activity log.
- Every mutating endpoint is permission-checked and logged.
- The console never writes to verifiers. Actions that change enforcement
  (policy changes) go through a pull request; restarts go through the
  Kubernetes API with a namespaced service account.

## Deployment

The console's HTTP server bounds its own resources:

- a request is abandoned after 30 seconds (`503 TIMEOUT`) and at most 512
  requests are handled at once (`503 OVERLOADED`; `/healthz` and `/readyz` are
  exempt);
- at most 1024 client connections are open at once; a connection over the cap
  is closed as soon as it is accepted;
- a connection with no request in progress is closed 15 seconds after it was
  opened or after its last response was produced. This bounds how long a
  client may take to send request headers and how long a keep-alive
  connection may sit idle.

The idle timer is per connection, not per header byte, and the server has no
limit on concurrent TLS handshakes because it doesn't terminate TLS. Run the
console behind a reverse proxy or load balancer (an ingress controller, an
ALB, Cloud Load Balancing, Application Gateway, nginx, Envoy) that terminates
TLS and enforces its own header-read and idle timeouts and connection limits.
Set `public_url` to the URL users open, so the CSRF check compares origins
with it instead of relying on the proxy to preserve `Host` (see
[config.md](config.md#origins)).

See [api.md](api.md) for the HTTP contract and [deploy.md](deploy.md) for
running it locally and on AWS, GCP and Azure.
