# Data catalogs

Your data catalog already knows which columns hold personal data. HaltSQL
turns those labels into a starter policy that leaves the labelled columns
out, so an agent cannot read them. This page gives one recipe per catalog;
the commands themselves are documented in
[schema-and-pii.md](../schema-and-pii.md).

Catalogs covered:

- [dbt](#dbt)
- [DataHub](#datahub)
- [Databricks Unity Catalog](#unity-catalog)
- [Atlan](#atlan)
- [Collibra](#collibra)
- [OpenMetadata](#openmetadata)

| Catalog | `schema import` (export file) in 0.0.1 | `schema fetch` (live API) |
|---|---|---|
| dbt | yes: `manifest.json`, `catalog.json` | no (dbt Cloud is not covered) |
| DataHub | yes: file-sink exports, GraphQL responses | with the catalog live-fetch work |
| Unity Catalog | yes: `column_tags` rows, table JSON | no |
| Atlan | yes: asset search results | no |
| Collibra | yes: asset exports | no |
| OpenMetadata | no | with the catalog live-fetch work (an importer arrives at the same time) |

## The workflow

Every catalog follows the same five steps. Only step 2 differs.

```sh
# 1. Structure: snapshot the real tables and columns from PostgreSQL.
PGPASSWORD=... haltsql schema pull --dsn postgres://ro@db.internal:5432/app \
    --schema app -o policies/catalog.json

# 2. Labels: turn the catalog's PII labels into a PII manifest (one per catalog).
haltsql schema import --from dbt target/manifest.json -o policies/pii.dbt.json
haltsql schema import --from unity column_tags.json -o policies/pii.unity.json

# 3. Draft: every table, with the labelled columns left out.
haltsql policy draft --catalog policies/catalog.json \
    --pii policies/pii.dbt.json --pii policies/pii.unity.json \
    --tenant-column tenant_id --schema app -o policies/agent.yaml

# 4. Lint.
haltsql lint-policy policies/agent.yaml

# 5. Test: prove the labelled columns are denied.
haltsql test policies/agent.test.yaml
```

**Structure always comes from PostgreSQL, labels from the catalog.** The
analyzer trusts a typed snapshot as the complete column list of each table
(that is how it expands `SELECT *`). A catalog that has not yet crawled a new
column would turn that trust into a leak, so HaltSQL never takes structure
from a catalog. See
[Security model](../schema-and-pii.md#security-model-labels-are-trusted-structure-never-is).

**What the draft looks like.** Run against the sample `manifest.json` and
`column_tags.json` in [`examples/metadata/`](../../examples/metadata/), the
draft for `app.customers` is:

```yaml
  # excluded email (dbt+unity: pii, pii=email; name matches "email")
  # excluded phone (dbt+unity: class.phone_number, governance.sensitivity=restricted; name matches "phone")
  app.customers:
    columns: [id, tenant_id, name, country, created_at]
    tenant_column: tenant_id
```

Each comment names the catalogs and labels that flagged the column. Several
manifests are merged; a column flagged by any of them is left out. Columns
are also left out when their name matches a heuristic (`email`, `phone`,
`ssn`, ...); `--no-name-heuristics` turns that off. Review the draft before
use: see [Review before use](../schema-and-pii.md#haltsql-policy-draft).

**A test suite for step 5.** Add one denied-column case for each column the
catalog flagged, and one allowed case, so a later redraft that loses a label
fails CI:

```yaml
apiVersion: haltsql.dev/v1
kind: TestSuite
metadata:
  name: agent-pii
policy: agent.yaml
defaults:
  context: { tenant_id: acme }
cases:
  - name: tagged column is denied
    sql: SELECT email FROM app.customers WHERE tenant_id = $1 LIMIT 10
    expect: deny
    codes: [E_COLUMN_DENIED]
  - name: SELECT * would read a tagged column
    sql: SELECT * FROM app.customers WHERE tenant_id = $1 LIMIT 10
    expect: deny
    codes: [E_COLUMN_DENIED]
  - name: untagged columns are allowed
    sql: SELECT id, name FROM app.customers WHERE tenant_id = $1 LIMIT 10
    expect: allow
    bind: [{ param: 1, value: acme }]
```

The suite format is in [testing.md](../testing.md#policy-test-suites).

### How labels match

The rules are the same for every catalog
([details](../schema-and-pii.md#haltsql-schema-import)):

- Labels are split into lower-case words on non-alphanumeric characters and
  camelCase boundaries. A term matches when its words appear consecutively:
  `pii` matches `contains_pii`, `urn:li:tag:PII` and `pii_email`, but not
  `piiset`.
- A single-word term of three or more letters also matches the acronym of a
  multi-word label, so `Personally Identifiable Information` matches `pii`.
- Key/value metadata becomes `key` (true values) or `key=value`. `false`,
  `null`, `no`, `0` and empty values do not count, so `meta: {pii: false}`
  does not flag a column.
- The default terms are `pii`, `sensitive`, `confidential`, `restricted`,
  `gdpr`, `phi`, `pci`, `personal`, `email`, `phone`, `ssn`, `secret`.
  `--pii-tag` and `--pii-term` **replace** the defaults; to add a term, repeat
  the defaults you want to keep.

### Pitfalls common to every catalog

- **Names must line up.** Manifests are keyed by `schema.table`; the
  database or catalog name is ignored. If the catalog's schema or table
  name differs from PostgreSQL's, the label is lost. `policy draft` warns
  `PII column app.users.email is not in the catalog` for each label it could
  not place: treat those warnings as failures until each is explained.
- **Two databases, one schema name.** Because the database name is ignored,
  an export that covers `staging.app.users` and `prod.app.users` merges both
  into `app.users`. Export one database at a time.
- **Wrong `--from`.** A file in which the importer finds no column metadata
  at all exits `1`. With `-o`, `--json` prints `scanned_columns` and
  `pii_columns`; a
  scan count far below your column count means the export is incomplete.
- **Untagged sensitive data** is only caught by the column-name heuristics.
  A catalog is a good source of labels, not a complete one.

## dbt

**What HaltSQL reads.** From `target/manifest.json`: models, seeds,
snapshots and sources (tests are ignored). Per column: `tags`, `meta`,
`config.tags`, `config.meta` and `policy_tags`, including nested meta such
as `{governance: {sensitivity: restricted}}`. The table is the node's
`schema` plus its `alias`, `identifier` or `name`. From
`target/catalog.json`: column comments, matched word by word and recorded
as `comment:<term>`.

**Obtaining the input.** dbt writes `manifest.json` to `target/` on every
`dbt parse`, `dbt compile`, `dbt run` or `dbt build`. `catalog.json` comes
from `dbt docs generate` and holds the comments the database returns, which
are your dbt descriptions only when `persist_docs` is enabled.

**Command.**

```sh
dbt parse --target prod
haltsql schema import --from dbt target/manifest.json -o policies/pii.dbt.json
# optional: column comments from the database
dbt docs generate --target prod
haltsql schema import --from dbt target/catalog.json -o policies/pii.dbt-comments.json
```

**Labels that match.** From the sample
[`dbt_manifest.json`](../../examples/metadata/dbt_manifest.json):

```yaml
columns:
  - name: email
    tags: [pii]                     # -> pii
    meta: { pii: true }             # -> pii
  - name: phone
    config:
      meta: { governance: { sensitivity: restricted } }   # -> governance.sensitivity=restricted
  - name: ssn
    tags: [gdpr]                    # -> gdpr
    meta: { classification: confidential }                # -> classification=confidential
  - name: full_name
    policy_tags: [pii_name]         # -> pii_name
  - name: password_hash
    meta: { security: secret }      # -> security=secret
  - name: name
    meta: { pii: false }            # does not count
```

The sample is shown as YAML, the way you write it in a dbt properties file;
the manifest holds the same values as JSON.

**Pitfalls.**

- **Use the target you deploy.** The table key uses the schema dbt resolved
  for the target you parsed with. A manifest parsed with a `dev` target names
  `dbt_alice.customers`, which matches nothing in production. Parse with the
  production target, or the target whose schemas you pulled.
- **Descriptions in `manifest.json` are not read** in 0.0.1. A description
  such as "Primary contact email" only counts through `catalog.json`, and only
  when `persist_docs` wrote it to the database as a comment.
- **dbt Cloud** (the Discovery API) is not supported. Download the
  `manifest.json` artifact of a production job run and import it as above.

## DataHub

**What HaltSQL reads.** Tags (`urn:li:tag:*`) and glossary terms
(`urn:li:glossaryTerm:*`, plus their `name` or `properties.name`) on the
fields of `schemaMetadata` (set by ingestion) and `editableSchemaMetadata`
(set in the UI or through the API). The table is the last two dot-separated
parts of the dataset URN's name: `urn:li:dataset:(urn:li:dataPlatform:postgres,saas.app.customers,PROD)`
becomes `app.customers`. v2 field paths such as
`[version=2.0].[type=struct].[type=string].phone` are reduced to `phone`.
Dataset-level tags do not count.

**Obtaining the input.** Two shapes are accepted, in any number in one JSON
document:

- **Ingestion file sink.** Run your PostgreSQL ingestion recipe with
  DataHub's `file` sink instead of the REST sink. The output holds MCE snapshots and
  MCPs, which the importer reads, including MCPs whose `aspect.value` is a
  JSON string.

  ```yaml
  source:
    type: postgres
    config: { host_port: db.internal:5432, database: saas, ... }
  sink:
    type: file
    config: { filename: ./datahub_export.json }
  ```

- **GraphQL.** Query each dataset through DataHub's GraphQL API and save
  the responses (one response, or a JSON array of them):

  ```graphql
  query {
    dataset(urn: "urn:li:dataset:(urn:li:dataPlatform:postgres,saas.app.payments,PROD)") {
      urn
      schemaMetadata { fields { fieldPath
        tags { tags { tag { urn properties { name } } } }
        glossaryTerms { terms { term { urn properties { name } } } } } }
      editableSchemaMetadata { editableSchemaFieldInfo { fieldPath
        tags { tags { tag { urn properties { name } } } }
        glossaryTerms { terms { term { urn properties { name } } } } } }
    }
  }
  ```

**Command.**

```sh
haltsql schema import --from datahub datahub_export.json -o policies/pii.datahub.json
```

**Labels that match.** From the samples
[`datahub_mce.json`](../../examples/metadata/datahub_mce.json) and
[`datahub_graphql.json`](../../examples/metadata/datahub_graphql.json):

| Label on the field | Recorded as |
|---|---|
| `urn:li:tag:PII` | `PII` |
| `urn:li:glossaryTerm:PersonalInformation.PhoneNumber` | `PersonalInformation.PhoneNumber` |
| `urn:li:tag:pci` with `properties.name: PCI` | `PCI`, `pci` |
| a glossary term with a UUID id and `properties.name: Payment Card Data (Sensitive)` | `Payment Card Data (Sensitive)` |

**Pitfalls.**

- **UI tags are not in an ingestion export.** Tags and terms applied in the
  DataHub UI live in `editableSchemaMetadata`, which an ingestion run does
  not emit. If your stewards tag columns in the UI, use the GraphQL export.
- **Glossary terms with UUID ids** only match by name. Include
  `properties { name }` in the query, or the term is recorded as an opaque
  id that matches nothing.
- **Platform instances and databases are ignored** (only `schema.table` is
  kept). Export one PostgreSQL database at a time.

### Live fetch from DataHub

> **Availability:** live fetch from OpenMetadata/DataHub is not in the 0.0.1 release; it lands with the catalog live-fetch work.

With that work, `haltsql schema fetch --from datahub` reads the same labels
straight from DataHub's GraphQL API, so nobody has to export a file:

```sh
export DATAHUB_TOKEN=...                       # a Personal Access Token; never on the command line
haltsql schema fetch --from datahub --url https://datahub.example.com \
    --database saas --schema app -o policies/pii.datahub.json
```

- `--url` is the GMS root (`http://datahub-gms:8080`) or the frontend root
  (`https://datahub.example.com`); HaltSQL posts to `/api/graphql`. `https`
  is required except for loopback hosts.
- The token is read from `DATAHUB_TOKEN`, or the variable named by
  `--token-env`, or `--token-file`. There is no option that takes the token
  itself. DataHub only checks tokens when metadata service authentication is
  enabled (`METADATA_SERVICE_AUTH_ENABLED=true`); otherwise requests go
  through as anonymous.
- Only `postgres`-platform datasets are read. `--service` is the platform
  instance (the recipe's `platform_instance`), `--database` the database and
  `--schema` the schemas. Without `--database`, every PostgreSQL database on
  the instance goes into one manifest, with a warning when there is more than
  one: pass `--database`.
- It was validated against DataHub v1.8.0.

The options (`--ca-file`, `--timeout`, `--max-pages`, `--snapshot-out`, ...)
are described in
[`haltsql schema fetch`](../schema-and-pii.md#haltsql-schema-fetch-live).

## Unity Catalog

**What HaltSQL reads.** Column tags, as `tag_name` and
`tag_name=tag_value`. Two input shapes are accepted:

- rows of `information_schema.column_tags` (`catalog_name`, `schema_name`,
  `table_name`, `column_name`, `tag_name`, `tag_value`): a JSON array of
  objects, `{"column_tags": [...]}`, or a Databricks SQL Statement Execution
  API result (`manifest.schema.columns` plus `result.data_array`);
- table JSON (one table, a list, or `{"tables": [...]}`) whose columns carry
  `tags` as a map or as a list of `{key, value}`.

The catalog name is ignored; the table is `schema_name.table_name`.

**Obtaining the input.** Query the tags of the catalog that holds the tables
the agent reads, and save the result as JSON:

```sql
SELECT catalog_name, schema_name, table_name, column_name, tag_name, tag_value
FROM main.information_schema.column_tags
WHERE schema_name = 'app';
```

Any client that writes the rows as a JSON array works. With the SQL
Statement Execution API, request `format: JSON_ARRAY` with
`disposition: INLINE` and save the response body as it is.

**Command.**

```sh
haltsql schema import --from unity column_tags.json -o policies/pii.unity.json
```

**Labels that match.** From the sample
[`unity_column_tags.json`](../../examples/metadata/unity_column_tags.json):

| `tag_name` | `tag_value` | Recorded as | Matches |
|---|---|---|---|
| `pii` | `email` | `pii`, `pii=email` | yes |
| `class.phone_number` | (empty) | `class.phone_number` | yes (`phone`) |
| `data_classification` | `Restricted` | `data_classification=Restricted` | yes (`restricted`) |
| `secret` | `null` | `secret` | yes |
| `domain` | `geo` | | no |
| `sensitivity` | `internal` | | no |

**Pitfalls.**

- **The PostgreSQL schema must match the Unity schema name.** Unity Catalog
  usually describes a lakehouse copy of the data. The labels only help if the
  copy keeps the source's schema and table names; otherwise every label is
  reported as "not in the catalog".
- **Chunked results.** A Statement Execution API response with a
  `next_chunk_index` holds only the first chunk. Narrow the query (by schema
  or table), or save the rows as a JSON array from another client.
- **Live sync is not available.** There is no `schema fetch` provider for
  Unity Catalog; the open-source Unity Catalog server has no column-tag API to
  validate one against
  ([details](../schema-and-pii.md#haltsql-schema-fetch-live)).

## Atlan

**What HaltSQL reads.** `Column` assets from asset search results
(`{"entities": [...]}`, a list, or `{"entity": ...}`): `classifications` and
`atlanTags` (`typeName`, `displayName`, `tagName`), `classificationNames`,
glossary `meanings` (`displayText`) and `meaningNames`. The table is
`tableName`, `viewName` or `materialisedViewName` with `schemaName`, else the
end of `qualifiedName`.

**Obtaining the input.** Search for the `Column` assets of the schema with
Atlan's search API or SDK, asking for the attributes above, and save the
JSON response. Make sure the tags come back with their display names.

**Command.**

```sh
haltsql schema import --from atlan atlan_columns.json -o policies/pii.atlan.json
```

**Labels that match.** From the sample
[`atlan_assets.json`](../../examples/metadata/atlan_assets.json):

```json
{
  "typeName": "Column",
  "attributes": { "name": "email", "tableName": "customers", "schemaName": "app",
                  "qualifiedName": "default/postgres/1729912345/saas/app/customers/email" },
  "classifications": [ { "typeName": "tQoN8XtNIRWkGWHgyHxYQx", "displayName": "PII" } ],
  "meanings": [ { "displayText": "Email Address" } ]
}
```

This column is recorded with `PII` and `Email Address`.

**Pitfalls.**

- **Opaque tag names.** Atlan's classification `typeName` is often a hash
  such as `tQoN8XtNIRWkGWHgyHxYQx`, which matches nothing. Export with
  `displayName`, or the label is lost.
- **Only what is in the file counts.** HaltSQL reads the tags and terms
  present on each `Column` asset in the export; check that your search
  request returns them for every column.

## Collibra

**What HaltSQL reads.** `Column` assets from an asset export (a list,
`{"results": [...]}` or `{"assets": [...]}`), identified by `fullName`
(`db>schema>table>column`, or dotted). Labels are:

- attributes whose type name mentions classification, sensitivity, privacy,
  confidentiality, personal/PII or security (a list of
  `{type: {name}, value}` or a map);
- `tags`;
- `classificationMatches` and `dataClassifications` that are not `REJECTED`;
- relations to Business Terms.

**Obtaining the input.** Export the `Column` assets of the database with the
fields above (through the Collibra REST API or an export job) and save them
as JSON.

**Command.**

```sh
haltsql schema import --from collibra collibra_columns.json -o policies/pii.collibra.json
```

**Labels that match.** From the sample
[`collibra_assets.json`](../../examples/metadata/collibra_assets.json):

```json
{
  "name": "phone",
  "fullName": "saas>app>customers>phone",
  "type": { "name": "Column" },
  "attributes": { "Data Classification": ["Restricted"], "Description": "Customer phone number" },
  "classificationMatches": [ { "classification": { "name": "Phone Number" }, "status": "ACCEPTED" } ]
}
```

This column is recorded with `Restricted` and `Phone Number`. The
`Description` attribute is not a label: its type name is not
classification-like.

**Pitfalls.**

- **`fullName` must end in `schema>table>column`** (or
  `schema.table.column`). Assets with fewer parts cannot be placed in a table
  and are skipped.
- **Only `REJECTED` classification matches are ignored.** A match with any
  other status, or with no status, counts. Review Collibra's automatic
  classification suggestions, or unreviewed ones will remove columns from the
  draft.

## OpenMetadata

There is no OpenMetadata importer in 0.0.1: `schema import --from` accepts
`dbt`, `datahub`, `unity`, `atlan` and `collibra` only. If the PII tags in
OpenMetadata come from dbt, import the dbt `manifest.json` directly in the
meantime.

> **Availability:** live fetch from OpenMetadata/DataHub is not in the 0.0.1 release; it lands with the catalog live-fetch work.

That work adds both an importer (`schema import --from openmetadata`) and a
live provider (`schema fetch --from openmetadata`). They read the same
labels.

**What HaltSQL reads.** Table entities as returned by
`GET /api/v1/tables?fields=columns,tags`: `columns[].tags[].tagFQN`. Labels
with `source: "Glossary"` are glossary terms, the others classification
tags. The full FQN is matched, so `PII.Sensitive` and
`PersonalData.Personal` count and `Tier.Tier1` does not. Tags on nested
`children` (STRUCT fields) flag the top-level column. Column descriptions and
table-level tags are ignored. The table is `databaseSchema.name` plus `name`.

**Command.**

```sh
export OPENMETADATA_TOKEN=...                  # a bot JWT; never on the command line
haltsql schema fetch --from openmetadata --url https://om.example.com/api \
    --service prod_pg --database app --schema app -o policies/pii.om.json

# or, from a saved response of GET /api/v1/tables?fields=columns,tags
haltsql schema import --from openmetadata om_tables.json -o policies/pii.om.json
```

- `--url` is the server root (`https://om.example.com`) or the API root
  (`https://om.example.com/api`).
- The token is a bot JWT (Settings > Bots); a bot whose user has only the
  `DataConsumer` role is enough. It is read from `OPENMETADATA_TOKEN`, the
  variable named by `--token-env`, or `--token-file`.
- `--service` is the database service name, `--database` the database inside
  it (requires `--service`), `--schema` the schema names.
- It was validated against OpenMetadata 2.0.7.

**Labels that match.** A column tagged `PersonalData.Personal` (source
`Classification`) is recorded as `PersonalData.Personal` and matches
`personal`. A column tagged only `Tier.Tier1` is not flagged.

**Pitfalls.**

- **Misspelt scope returns nothing.** OpenMetadata answers an unknown
  service or database name with an empty list, so "no tables found" usually
  means a typo in `--service` or `--database`.
- **Descriptions are not labels.** Tag the column; a description that says
  "contains PII" is ignored.

## Related

- [Catalog snapshots, PII metadata and starter policies](../schema-and-pii.md):
  every option of `schema pull`, `schema import`, `schema fetch` and
  `policy draft`.
- [Policy reference](../policy-reference.md#catalog): the `catalog:` key and
  how snapshots are used.
- [Testing](../testing.md#policy-test-suites): policy test suites in CI.
- [Policy CI](../policy-ci.md).
- [CLI reference](../cli.md).
