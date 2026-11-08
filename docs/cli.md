# CLI reference

HaltSQL ships two executables:

- `haltsql`: verify SQL, debug denials, validate and convert documents, run
  policy tests.
- `haltsql-server`: the HTTP sidecar (see [http-api.md](http-api.md)).

Every command accepts `--help`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `verify`/`explain`: the query is allowed. For `validate`/`test`: everything passed. |
| `1` | For `verify`/`explain`: the query is denied. For `test`: at least one case failed. For `validate`: at least one document is invalid. |
| `2` | Usage error, or a policy, config, context, or input file could not be loaded. |

A shadow-mode policy always yields `allowed: true`, so `verify` exits `0`;
would-be denials appear in `shadow_reasons`.

## haltsql verify

Check one SQL statement against a policy.

```
haltsql verify --policy FILE
               [--context JSON | --context-file FILE]
               [--sql SQL | --file FILE]
               [--json]
haltsql verify --policy FILE --batch [--jobs N] [--context JSON | --context-file FILE]
```

| Flag | Meaning |
|---|---|
| `-p`, `--policy FILE` | Policy document (YAML or JSON). Required. |
| `-c`, `--context JSON` | Context as a JSON object, for example `'{"tenant_id":"acme"}'`. Values are strings, integers, or arrays of those. |
| `--context-file FILE` | Read the context from a YAML or JSON file. |
| `-s`, `--sql SQL` | The SQL string to check. |
| `-f`, `--file FILE` | Read the SQL string from a file. |
| `--json` | Print the verdict as JSON (see [verdict.md](verdict.md)). Without it, `ALLOWED` or `DENIED` is printed with the reasons, hints, and values to bind. |
| `--batch` | Read JSONL requests from stdin and write one JSON verdict per line. |
| `-j`, `--jobs N` | With `--batch`: verify on N OCaml domains in parallel. Output order is preserved. Default 1. |

If neither `--sql` nor `--file` is given, the SQL is read from stdin. If no
context is given, the context is empty, and any policy with tenancy keys will
deny with `E_CONTEXT_MISSING`.

Examples:

```sh
haltsql verify --policy policy.yaml --context '{"tenant_id":"acme"}' \
  --sql 'SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10'

echo 'SELECT id FROM orders LIMIT 10' | \
  haltsql verify --policy policy.yaml --context-file ctx.json --json
```

In scripts, branch on the exit code:

```sh
if haltsql verify --policy policy.yaml --context-file ctx.json --file q.sql; then
  echo "allowed"
else
  case $? in 1) echo "denied" ;; *) echo "error" ;; esac
fi
```

### Batch mode

`--batch` checks many statements with one process. Each input line is a JSON
object:

```json
{"id": "q1", "sql": "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10", "context": {"tenant_id": "acme"}}
{"id": "q2", "sql": "SELECT id FROM orders LIMIT 10", "context": {"tenant_id": "acme"}}
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Any JSON string or number; echoed back so you can match results. |
| `sql` | yes | The SQL string. |
| `context` | no | Context for this line. If omitted, the `--context` / `--context-file` value is used. |

Each output line is the compact verdict JSON with `"id"` as the first field,
in input order (also with `--jobs`). Blank lines are skipped:

```json
{"id":"q1","allowed":true,"reasons":[],"bind_params":[{"param":1,"value":"acme"}], ...}
{"id":"q2","allowed":false,"reasons":[{"code":"E_TENANT_MISSING", ...}], ...}
```

A line that cannot be read (invalid JSON, missing `sql`, invalid context)
produces `{"id": ..., "error": "message"}` and does not stop the batch. In
batch mode the exit code is `0` once all lines are processed, whatever the
verdicts, and `2` if the policy or default context cannot be loaded; check each
line's `allowed` field.

## haltsql explain

Same inputs as `verify` (except `--batch` and `--json`), but prints a
human-readable report for debugging a denial:

```
haltsql explain --policy FILE [--context JSON | --context-file FILE] [--sql SQL | --file FILE]
```

The report shows:

- the verdict and the policy name and version;
- the statement kind;
- the tables and columns the statement touches;
- each reason with its code, message, position in the SQL (with a caret under
  the offending text when the position is known), and the hint;
- the values to bind, when allowed in bound mode.

Exit codes are the same as `verify`. The output format is for people and may
change between releases; use `verify --json` in scripts.

## haltsql validate

Check one or more documents of any kind. The kind is detected from the `kind`
field: `Policy`, `Config`, `TestSuite`, `Catalog`, or `Scenario`.

```
haltsql validate FILE...
```

All errors are printed with file, line, column, and key path. Exit code `0` if
all documents are valid, `1` if any is invalid, `2` if a file cannot be read.

## haltsql convert

Convert a document between YAML and JSON without changing its meaning.

```
haltsql convert FILE --to json|yaml [-o OUT]
```

The result is written to stdout, or to `OUT` with `-o`/`--output`. The input is validated first; an invalid
document is not converted. A converted policy has the same `policy_version`
as the original.

## haltsql schema export

Write the JSON Schemas (draft 2020-12) for every document kind, for editor
autocomplete and CI validation.

```
haltsql schema export --out DIR
```

Writes files such as `policy.schema.json`, `config.schema.json`,
`catalog.schema.json`, and `scenario.schema.json` into `DIR` (created if
needed).

## haltsql test

Run policy test suites (`kind: TestSuite`).

```
haltsql test SUITE_FILE... [--filter TAG] [-v]
```

`--filter TAG` runs only cases tagged `TAG`; `-v`/`--verbose` also shows the
reasons for passing cases.

Each case is checked against the suite's policy. A case passes when the
verdict matches `expect`, every code in `codes` appears in the reasons, and
(when given) `bind` equals the returned `bind_params`. Failing cases are
printed with the reason. Exit code `0` if all cases pass, `1` if any fail,
`2` if a suite or its policy cannot be loaded. See
[testing.md](testing.md#policy-test-suites) for the format.

## haltsql lint-policy

Report risky or suspicious settings in a policy: tables exposing all columns,
unused tenancy keys, shadow mode, a missing `require_limit`, large function
allowlists, and tables missing from the catalog. Exits `0` unless the policy
fails to load (`2`).

```
haltsql lint-policy FILE
```

## haltsql config show

Print the effective configuration after merging the config file, `HALTSQL_*`
environment variables, and defaults. Secrets are replaced by `"<redacted>"`.
`${vault:...}`, `${aws-sm:...}` and `${gcp-sm:...}` placeholders are resolved
from the config's `secrets` section first (see [secrets.md](secrets.md));
`haltsql validate` does the same for `kind: Config` documents.

```
haltsql config show --config FILE
```

(`--effective` is accepted for compatibility; the output is always the merged
result.)

## haltsql schema pull / schema import

Snapshot a live Postgres catalog into a `Catalog` document (`schema pull`,
read-only, TLS and SCRAM-SHA-256), and import PII labels from dbt, DataHub,
Unity Catalog, Atlan or Collibra exports (`schema import`). See
[schema-and-pii.md](schema-and-pii.md).

```
haltsql schema pull --dsn postgres://... -o catalog.json
haltsql schema import --from dbt|datahub|unity|atlan|collibra FILE -o pii.json
```

## haltsql policy draft

Write a reviewable starter policy from a catalog snapshot and PII manifest:
explicit column lists without PII columns, tenant columns, and `require_limit`.
See [schema-and-pii.md](schema-and-pii.md).

## haltsql rls generate / rls check

Generate idempotent PostgreSQL role, grant and row-level-security DDL from a
policy (`rls generate`), and report drift between a live database and the
policy (`rls check`; exit 1 on drift). See [rls-generation.md](rls-generation.md).

## haltsql bundle

Build, sign (Ed25519), verify and inspect signed policy bundles:
`bundle keygen`, `bundle build`, `bundle sign`, `bundle verify`,
`bundle inspect`; publish and fetch them as OCI artifacts with
`bundle push --oci REF` and `bundle pull --oci REF` (exit code 3 when the
registry is unreachable or refuses the request; see
[policy-bundles.md](policy-bundles.md#publishing-and-pulling-with-the-cli)). The server loads bundles listed under `policies` and refuses
any whose signature does not verify. See [policy-bundles.md](policy-bundles.md)
and, for CI, [policy-ci.md](policy-ci.md).

## haltsql report

Shadow-mode analytics over audit records written by haltsql-server or
haltsql-proxy (files, directories, or `-`), and conservative policy
suggestions (`--suggest`), optionally applied to a copy of a policy
(`--apply-to FILE -o OUT`). Exit 1 if applying would turn a tenancy denial
into an allow or the patched policy does not validate. See
[shadow-reports.md](shadow-reports.md).

```
haltsql report audit.jsonl --since 7d --suggest --policy-file policies/shop.yaml
```

## haltsql audit verify

Verify the hash chain of audit logs: files, rotated sets (`--concat`), mixed
container logs (`--mixed`), downloaded object-sink directories (with
`--spool`), and `s3://bucket/prefix` read directly. Exit 0 when every chain
verifies, 1 when one is broken, 2 on usage or input errors. See
[audit-verify.md](audit-verify.md).

```
haltsql audit verify /var/log/haltsql/audit.jsonl
haltsql audit verify --json s3://corp-haltsql-audit/haltsql/audit/
```

## haltsql version

Print the HaltSQL version, the Postgres grammar version of the vendored
libpg_query, and the OCaml version. `--json` prints them as JSON.

```
haltsql version [--json]
```

## haltsql-server

Run the HTTP sidecar.

```
haltsql-server --config FILE [flags]
haltsql-server --policy FILE [--policy FILE ...] [flags]
```

At least one of `--config` or `--policy` is required.

| Flag | Meaning |
|---|---|
| `--config FILE` | Config document (see [config-reference.md](config-reference.md)). |
| `-p`, `--policy FILE` | Load a policy file (repeatable). Added to the config's policies; a policy with the same name replaces the config's. |
| `--listen HOST:PORT` | Override `server.listen` (default `127.0.0.1:8080`). |
| `--allow-unauthenticated` | Accept requests without a bearer token. Local development only. |
| `--default-policy NAME` | Policy used by unauthenticated requests. |
| `--log-level LEVEL` | `debug`, `info`, `warn`, or `error`. |
| `--log-format FORMAT` | `json` or `text`. Logs go to stderr. |
| `--audit SINK` | `stdout`, `file:PATH`, or `none` (repeatable; replaces the config's sinks). |
| `--log-raw-sql` | Include the raw SQL in audit records. |
| `--watch` / `--no-watch` | Reload when policy or config files change (polled every 2 seconds). |
| `--max-request-bytes N` | Maximum request body size (HTTP 413 above). A body whose declared `Content-Length` is over the limit is rejected before any of it is read, and before authentication. |
| `--max-connections N` | Maximum open client connections (default `1024`). At the limit the server stops accepting and new clients wait in the listen backlog. The `--health-listen` port has its own budget of 64. |
| `--request-timeout SECONDS` | Time allowed to receive a request's head and body once its first byte arrives (default `30`). Request heads are capped at 64 KiB. |
| `--idle-timeout SECONDS` | How long a keep-alive connection may stay silent, and how long a response write may stall (default `60`). |
| `--shutdown-timeout SECONDS` | How long `SIGTERM` waits for in-flight requests to finish (default `15`). |
| `--no-metrics` | Disable `GET /metrics`. |
| `--health-listen HOST:PORT` | Extra plain-HTTP listener serving only `/healthz` and `/readyz` (for probes when the main port requires client certificates). |

Flags override `HALTSQL_*` environment variables, which override the config
file. The server reloads all policies atomically on `SIGHUP` (keeping the last
good set on error), and shuts down gracefully on `SIGTERM` or `SIGINT`. Exit
code `0` after a graceful shutdown, `2` if the configuration cannot be loaded
or the listener cannot start.

Quick local start:

```sh
haltsql-server --policy policy.yaml --listen 127.0.0.1:8080 --allow-unauthenticated
```

TLS is not built into `haltsql-server` in 0.1.0; terminate TLS in a proxy or
service mesh, or keep the listener on localhost.
