# Catalog snapshots, PII metadata and starter policies

Three commands take you from a live database to a reviewable policy:

```sh
# 1. Snapshot the schema (typed, complete column lists).
PGPASSWORD=... haltsql schema pull --dsn postgres://ro@db.internal:5432/app \
    --schema app -o policies/catalog.json

# 2. Import PII classifications from your data catalog (one or more tools).
haltsql schema import --from dbt target/manifest.json -o policies/pii.dbt.json
haltsql schema import --from datahub datahub_export.json -o policies/pii.datahub.json

# 3. Draft a starter policy, then review and lint it.
haltsql policy draft --catalog policies/catalog.json \
    --pii policies/pii.dbt.json --pii policies/pii.datahub.json \
    --tenant-column tenant_id --schema app -o policies/agent.yaml
haltsql lint-policy policies/agent.yaml
```

`haltsql schema fetch` reads the labels of step 2 from a live data catalog API
instead of an export file; see [below](#haltsql-schema-fetch-live).

All three exit `0` on success, `1` when the result fails validation, and `2` on
usage errors, unreadable input or connection failures. `--json` prints a
machine-readable summary when `-o` is given. Every command has `--help` with
examples.

## `haltsql schema pull`

Connects to PostgreSQL and writes a catalog snapshot (`kind: Catalog`, see
[policy-reference.md](policy-reference.md#catalog)).

| Option | Meaning |
|---|---|
| `--dsn DSN` | Connection string, URL or keyword form. Also read from `HALTSQL_DSN`. |
| `--schema S` | Only this schema; repeatable. Default: every schema except `pg_catalog`, `information_schema`, `pg_toast*` and `pg_temp_*`. |
| `-o FILE` | Write the snapshot to FILE (atomically). Default: stdout. |
| `--timeout SECONDS` | Connection timeout (default 10). The query itself runs with `statement_timeout = 120s`. |

**What is captured.** Every relation a query can name in `FROM`: tables,
partitioned tables, partitions, views, materialized views, foreign tables and
sequences. Each has its complete column list in position order, with the type
as `lower(format_type(atttypid, atttypmod))` (`bigint`, `character(2)`,
`numeric(10,2)`, `timestamp with time zone`, `text[]`). Dropped columns are
left out. Relations are sorted by schema and name (byte order), so repeated
pulls of an unchanged database produce identical files that diff cleanly.
`metadata.relations` records each relation's kind; the policy drafter uses it.

Names are stored exactly as Postgres stores them. A name that is not a plain
lower-case identifier is double-quoted in the table key, for example
`"app.\"Mixed Case\""`, so it loads back unchanged.

**Why `pg_catalog`, not `information_schema.columns`.**
`information_schema.columns` only shows columns the connecting role has a
privilege on. A snapshot made by a restricted role would then list *fewer*
columns than the real table, and the analyzer trusts typed snapshot entries as
complete (that is how `SELECT *` is expanded). `pg_attribute` always lists
every column, so the snapshot is complete whatever the role's grants are.
Sequences and partitions are included for the same reason: the analyzer's
`search_path` shadowing check assumes it knows every relation in a schema.

**Safety.**

- The session starts with `default_transaction_read_only=on`, and the
  introspection runs in a `REPEATABLE READ READ ONLY` transaction that is
  always rolled back. Use a role with no write privileges anyway.
- The password is never printed, written to the snapshot, or included in error
  messages (they show `postgres://user@host:port/db?sslmode=...`). Prefer
  `PGPASSWORD` or `HALTSQL_DSN` over a password on the command line, where it
  is visible in the process list.
- The output is loaded with the catalog loader before it is written. A pull
  that finds no relations exits `1`.

**Connection strings.** URL form
`postgres://user:pass@host:port/db?sslmode=verify-full&sslrootcert=/etc/ca.pem`
(percent-encoding decoded, IPv6 hosts in brackets) or keyword form
`host=db port=5432 user=ro dbname=app sslmode=require`. Missing fields come
from `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`, `PGSSLMODE` and
`PGSSLROOTCERT`. Supported parameters: `host`, `hostaddr`, `port`, `user`,
`password`, `dbname`, `sslmode`, `sslrootcert`, `connect_timeout`,
`application_name`. Any other parameter is an error, so a typo such as
`sslmod=` cannot silently turn TLS off. A host starting with `/` is a Unix-socket
directory.

| `sslmode` | Behaviour |
|---|---|
| `disable` | Plaintext. |
| `prefer` (`allow`) | TLS if the server offers it, else plaintext. The default for loopback hosts and Unix sockets. |
| `require` | TLS required, certificate not checked (libpq semantics). The default for every other host. |
| `verify-ca` | TLS required; the chain must verify against `sslrootcert`, or the system CAs. |
| `verify-full` | As `verify-ca`, and the certificate must match the host name (or IP). Use this across networks. |

Note that HaltSQL's default for remote hosts (`require`) is stricter than
libpq's (`prefer`).

**Authentication.** SCRAM-SHA-256 (the server's signature is verified, and a
server that skips that step is refused), MD5, and trust. Cleartext password
authentication is refused unless the connection uses TLS or goes to a loopback
host. Kerberos, GSSAPI, SSPI and SCRAM channel binding (`-PLUS`) are not
supported. The client is a small built-in implementation of the PostgreSQL v3
protocol (`Haltsql_catalog_tools.Pg_wire`), because `pgx` supports neither SCRAM
nor TLS.

## `haltsql schema import`

Normalizes the PII classifications of a data catalog export into a PII
manifest:

```json
{
  "metadata": { "source": "dbt", "file": "manifest.json", "generated_by": "haltsql schema import" },
  "tables": {
    "app.customers": {
      "columns": {
        "email": { "classifications": ["pii"], "source": "dbt" },
        "ssn": { "classifications": ["classification=confidential", "gdpr"], "source": "dbt" }
      }
    }
  }
}
```

| Option | Meaning |
|---|---|
| `--from TOOL` | `dbt`, `datahub`, `unity`, `atlan` or `collibra`. |
| `FILE` | The export (JSON). |
| `-o FILE` | Write the manifest to FILE. Default: stdout. |
| `--pii-tag TERM` | A tag/classification term that marks PII; repeatable. Replaces the defaults. |
| `--pii-term TERM` | A business-glossary term that marks PII; repeatable. Replaces the defaults. |

Default terms for both lists: `pii`, `sensitive`, `confidential`, `restricted`,
`gdpr`, `phi`, `pci`, `personal`, `email`, `phone`, `ssn`, `secret`.

**Matching.** Labels and terms are split into lower-case words on every
non-alphanumeric character and on camelCase boundaries. A term matches when its
words appear consecutively in the label: `pii` matches `contains_pii`,
`urn:li:tag:PII` and `pii_email`, but not `piiset`; `credit card` matches
`is_credit_card_number`. A single-word term of three or more letters also
matches the acronym of a multi-word label (`Personally Identifiable
Information` matches `pii`). Key/value metadata becomes `key` (for true values)
or `key=value` labels; `false`, `null`, `no`, `0` and empty values do not count.
The manifest records the matching labels as the tool shows them, without URN
prefixes. Matching errs towards flagging: a false positive only removes a
column from the draft, which you can add back after review.

A file in which the importer finds no column metadata at all exits `1` (it is
probably the wrong `--from`).

### What each importer reads

| Tool | Accepted input | Labels used |
|---|---|---|
| dbt | `target/manifest.json` (models, seeds, snapshots, sources; tests are ignored) | column `tags`, `meta`, `config.tags`, `config.meta`, `policy_tags`; nested meta such as `{governance: {sensitivity: restricted}}`. The table is `schema` plus `alias`, `identifier` or `name`. |
| dbt | `target/catalog.json` | column `comment`, matched word by word, recorded as `comment:<term>`. |
| DataHub | file-sink exports (MCE snapshots, MCPs with `aspect.json` or a JSON-string `aspect.value`) and GraphQL `dataset` responses | `urn:li:tag:*` tags and `urn:li:glossaryTerm:*` terms (plus their `name`/`properties.name`) on `schemaMetadata` and `editableSchemaMetadata` fields. The table is the last two dot-separated parts of the dataset URN name; v2 field paths are reduced to the last name. |
| Unity Catalog | `information_schema.column_tags` rows (JSON array, `{"column_tags": [...]}`, or a SQL Statement Execution API result), or REST table JSON (one table, a list, or `{"tables": [...]}`) | `tag_name` and `tag_name=tag_value`; REST column `tags` as a map or a list of `{key, value}`. The catalog name is ignored. |
| Atlan | asset search results (`{"entities": [...]}`, a list, or `{"entity": ...}`) of `Column` assets | `classifications`/`atlanTags` (`typeName`, `displayName`, `tagName`), `classificationNames`, glossary `meanings` (`displayText`) and `meaningNames`. The table is `tableName`/`viewName`/`materialisedViewName` with `schemaName`, else the end of `qualifiedName`. |
| Collibra | asset exports (a list, `{"results": [...]}` or `{"assets": [...]}`) of `Column` assets | attributes whose type name mentions classification, sensitivity, privacy, confidentiality, personal/PII, security (as a list of `{type: {name}, value}` or a map); `tags`; `classificationMatches`/`dataClassifications` that are not `REJECTED`; relations to Business Terms. The column is identified by `fullName` (`db>schema>table>column`, or dotted). |
| OpenMetadata | table entities from `GET /api/v1/tables?fields=columns,tags` (one table, a list, or the paged `{"data": [...]}` response) | `columns[].tags[].tagFQN`: `source: "Glossary"` labels are glossary terms, others (classifications) tags. The full FQN is matched, so `PII.Sensitive`, `PII.NonSensitive`, `PersonalData.Personal` count and `Tier.Tier1` does not. Tags on nested `children` (STRUCT fields) flag the top-level column. Column descriptions and table-level tags are ignored. The table is `databaseSchema.name` plus `name`. |

Atlan classification `typeName`s are often opaque hashes; export with display
names (`displayName`) so they can be matched.

Sample exports for every tool, based on the `lab/schemas/saas_shared.sql`
schema, are in [`examples/metadata/`](../examples/metadata/).

## `haltsql schema fetch` (live)

Reads the same PII labels as `schema import` straight from a data catalog's
API over HTTPS, so the manifest does not depend on someone exporting a file:

```sh
export OPENMETADATA_TOKEN=...            # never on the command line
haltsql schema pull --dsn "$DATABASE_URL" --schema app -o policies/catalog.json
haltsql schema fetch --from openmetadata --url https://om.example.com/api \
    --service prod_pg --database app --schema app -o policies/pii.om.json
haltsql policy draft --catalog policies/catalog.json --pii policies/pii.om.json \
    --tenant-column tenant_id --schema app -o policies/agent.yaml
```

The manifest is the same format as `schema import`'s, with
`metadata: {source: PROVIDER, url: URL, generated_by: "haltsql schema fetch"}`
(the URL never carries credentials). Exit codes are those of `schema import`:
`0` on success, `1` when the catalog returns no column metadata, `2` on usage
errors and network or HTTP failures.

### Security model: labels are trusted, structure never is

A data catalog is a good source of **labels** (tags, classifications, glossary
terms). A stale or missing label can only make HaltSQL exclude too little,
which the column-name heuristics and review mitigate, and matching errs
towards flagging.

A data catalog is **never** trusted for **structure**. HaltSQL's analyzer
treats a typed catalog snapshot as the complete column list of every table
(to expand `SELECT *`) and as the complete list of relations in each schema
(to rule out `search_path` shadowing). A catalog crawler that has not yet seen
`ALTER TABLE customers ADD COLUMN ssn text` would turn that trust into a leak.
So there are two ways to use `schema fetch`:

- **Authoritative mode (recommended).** Structure from `haltsql schema pull`
  against Postgres, labels from `haltsql schema fetch`, as in the example
  above. The draft references the pulled snapshot with `catalog:`, and
  `SELECT *` is expanded against the real columns (and denied when it would
  read an excluded one).
- **Catalog-only mode** (no database access). `--snapshot-out FILE` also
  writes the tables and columns the catalog knows as a **non-authoritative**
  snapshot: every column untyped, `metadata.authoritative: false`,
  `metadata.source: "haltsql schema fetch"`. `haltsql policy draft --catalog`
  accepts it to choose the column lists, but the draft has **no `catalog:`**
  key and a header comment saying why. `SELECT *`, `t.*` and whole-row
  references therefore stay denied (`E_COLUMN_DENIED`), and queries must name
  the allowed columns. The policy loader (`catalog:` as a file or inline,
  `haltsql validate`, the server, bundles) **refuses** a non-authoritative
  snapshot, with an error telling you to use `haltsql schema pull`.
  Switch to authoritative mode later by pulling a snapshot and redrafting.

### Options

| Option | Meaning |
|---|---|
| `--from PROVIDER` | The data catalog (see the status table below). |
| `--url URL` | Base URL of the catalog API. `https` only (`http` is accepted for loopback hosts); a path prefix such as `https://datahub.example.com/gms` is kept; no credentials, query or fragment. |
| `--token-env VAR` | Environment variable that holds the API token. Default: the provider's (for example `OPENMETADATA_TOKEN`). If the default variable is unset and there is no `--token-file`, requests are unauthenticated (with a warning). A `--token-env` you name explicitly must be set. |
| `--token-file FILE` | Read the token from FILE (surrounding whitespace removed). Warns if the file is readable by other users. |
| `--ca-file PEM` | Trust only the CA certificates in this PEM file (private CA). Default: the system trust store. |
| `--service NAME` | Provider-specific scope: OpenMetadata database service, DataHub platform instance, Unity Catalog catalog. |
| `--database NAME` | Database name as the catalog records it. |
| `--schema S` | Only this schema; repeatable. Default: all. |
| `-o FILE` | Write the manifest to FILE (atomically). Default: stdout. |
| `--snapshot-out FILE` | Also write the non-authoritative snapshot (catalog-only mode). |
| `--pii-tag TERM`, `--pii-term TERM` | As for `schema import`. |
| `--timeout SECONDS` | Timeout of each HTTP request (default 30). |
| `--max-pages N` | Fail after N pages of one listing (default 1000), so a misbehaving server cannot page forever. A repeated page cursor is also an error. |
| `--json` | Machine-readable summary (with `-o`): output, source, url, scanned and PII column counts, tables, requests, snapshot, warnings. |

**Token handling.** There is deliberately no option that takes the token
itself: it would be visible in shell history and in the process list. The
token is sent only as an `Authorization: Bearer` header, only to the `--url`
origin (redirects are not followed), and is never printed, written to the
manifest, or included in an error message. Error messages name the method,
path and HTTP status (`GET /api/v1/tables: HTTP 401`) but never include
response bodies. Responses are capped at 32 MiB.

### Providers

| Provider | `--from` | Default token variable | Status |
|---|---|---|---|
| _providers are added by their own PRs_ | | | |

Coming soon (not yet validated against a live instance): Atlan, Collibra,
dbt Cloud, Unity Catalog. The offline `schema import --from atlan|collibra`
file importers (and `--from dbt` for `manifest.json`) remain available.

Unity Catalog live sync is on hold because the open-source Unity Catalog
server (v0.7.0, the newest image) has no column-tag API. Its `ColumnInfo` has
no tags field, column tags are silently dropped on create, `PATCH /tables`
returns 405, and the tag endpoints return 404. A live provider therefore cannot
be validated against a runnable instance. Databricks-hosted Unity Catalog
column tags are still supported offline through `schema import --from unity`,
using `information_schema.column_tags` rows or table JSON with column tags.

## `haltsql policy draft`

Generates a starter policy from a snapshot and any number of PII manifests
(merged).

| Option | Meaning |
|---|---|
| `--catalog FILE` | Snapshot from `schema pull` (required), or a non-authoritative snapshot from `schema fetch --snapshot-out` (the draft then has no `catalog:`; see [catalog-only mode](#security-model-labels-are-trusted-structure-never-is)). |
| `--pii FILE` | PII manifest; repeatable. |
| `--tenant-column COL` | Tenant column (required). Every table that has it is tenant-scoped. |
| `--tenancy-key KEY` | Tenancy key name (default `tenant`). |
| `--context-field FIELD` | Context field read by `${ctx.FIELD}` (default `tenant_id`). |
| `--schema S` | Only this schema; repeatable. Also becomes `search_path`. Default: all schemas in the snapshot. |
| `-o FILE` | Output file. Default: stdout. |
| `--name NAME` | `metadata.name` (default: the output file name without extension). |
| `--require-limit N` | `require_limit.max` (default 1000). |
| `--no-name-heuristics` | Do not exclude columns by name. |
| `--name-pattern WORD` | Column-name words that mark PII; repeatable, replaces the defaults (`email`, `phone`, `mobile`, `ssn`, `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `iban`, `card`, `dob`, `birth`, `address`, `ip`). |
| `--include-partitions` | Also list partitions (default: only their parents). |
| `--catalog-ref PATH` | Value of `catalog:` (default: the snapshot path relative to the output file). |

The draft:

- lists every table, partitioned table, view, materialized view and foreign
  table in scope with an **explicit column list** that leaves out every column
  flagged by a manifest or by the name heuristics. A comment above each table
  says what was left out and why, for example
  `# excluded ssn (dbt+unity: gdpr, pii; name matches "ssn")`;
- sets `tenant_column` on tables that have the tenant column and marks the others
  `# GLOBAL: no tenant_id column`. The tenant column itself is never excluded
  (tenant predicates must reference it); a comment says so if it was flagged;
- skips partitions, sequences, and tables whose every column is excluded,
  listed under `# Not drafted:`;
- uses `statements: {allow: [select]}`, bound tenancy, `require_limit: {max: 1000}`,
  the `aggregates`, `math`, `string` and `datetime` presets, `mode: enforce` and a
  `catalog:` reference to the snapshot, so `SELECT *` is expanded against the
  real columns and denied when it would read an excluded one. From a
  non-authoritative snapshot (`schema fetch --snapshot-out`) there is no
  `catalog:` reference, and `SELECT *` is always denied.

The draft is loaded with the policy loader (including the check that every
table and column exists in the referenced catalog) before it is written; if it
does not load, nothing is written and the command exits `1`. Names from the
catalog and manifests are quoted as needed, and control characters in comments
are replaced, so a hostile column name cannot inject YAML.

**Review before use.** A draft is a starting point, not a policy:

- remove the tables and columns the agent does not need;
- check every `GLOBAL` table: if it holds tenant data under another column name,
  add the right `tenant_column` (or `tenant_columns`) by hand;
- data that is sensitive but untagged in your catalog is only caught if its
  name matches a heuristic;
- re-pull the snapshot and re-run `haltsql lint-policy` when the schema changes.

## Library

The commands are thin wrappers over the `haltsql.catalog_tools` library:
`Pg_dsn` (connection strings), `Pg_wire` (protocol client), `Scram`,
`Schema_pull`, `Snapshot`, `Pii` (manifest and matcher), `Pii_import` and
`Policy_draft`.
`schema fetch` uses the separate `haltsql.catalog_fetch` library (it adds the
HTTPS client): `Fetch_client` (endpoint checks, bearer auth, bounded
pagination), `Provider` (the signature each data catalog implements) and
`Catalog_fetch` (provider registry, import, non-authoritative snapshots).
