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

Atlan classification `typeName`s are often opaque hashes; export with display
names (`displayName`) so they can be matched.

Sample exports for every tool, based on the `lab/schemas/saas_shared.sql`
schema, are in [`examples/metadata/`](../examples/metadata/).

## `haltsql policy draft`

Generates a starter policy from a snapshot and any number of PII manifests
(merged).

| Option | Meaning |
|---|---|
| `--catalog FILE` | Snapshot from `schema pull` (required). |
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
  real columns and denied when it would read an excluded one.

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
