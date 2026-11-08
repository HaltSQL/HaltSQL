# DataHub live validation

Proves `haltsql schema fetch --from datahub` against a real DataHub server, end
to end. Opt-in: not part of `dune test` (it needs Docker and the lab Postgres).
Runs weekly and on demand in `.github/workflows/catalog-live.yml` (job
`datahub`).

```sh
make -C lab up                                   # lab Postgres on 127.0.0.1:5417
make -C lab venv                                 # tier-3 harness
opam exec -- dune build --root . ./bin/haltsql
test/catalog_live/datahub/run.sh                 # up -> seed -> fetch -> assert -> tier-3 -> down
```

| File | What it is |
|---|---|
| `docker-compose.yml` | DataHub **v1.8.0** (GMS, frontend, system-update job, MySQL 8.2, OpenSearch 2.19.3, Kafka 8.2.2), from the official quickstart compose at the v1.8.0 tag, minus the actions container and the `${HOME}` bind mounts, with **metadata service authentication on**. GMS on `127.0.0.1:${DH_GMS_PORT:-8596}`, frontend on `127.0.0.1:${DH_FRONTEND_PORT:-9596}`, nothing else published. About 4 GiB of memory. |
| `seed.py` | Creates the source database from `lab/schemas/saas_shared.sql` and a decoy database, creates a Personal Access Token, tags and glossary terms, ingests both databases with DataHub's real Postgres source (`datahub ingest` from `acryl-datahub[postgres]==1.7.0.19`, the CLI paired with v1.8.0), labels columns through GraphQL, and prints the expected manifest. Idempotent. |
| `assert_fetch.py` | Compares the fetched manifest and snapshot with what `seed.py` applied. |
| `run.sh` | The whole flow, including the frontend URL form and a bad-token check, with cleanup (`docker compose down -v`, both databases dropped) on exit. |

## What the seed does (governance-team style)

- **Auth**: logs in to the frontend as the default `datahub` user and creates a
  Personal Access Token (`createAccessToken`); ingestion and HaltSQL use it as
  a bearer token (`DATAHUB_TOKEN`).
- **Tags** `urn:li:tag:PII`, `urn:li:tag:Sensitive`, `urn:li:tag:Gold`
  (`createTag`), **glossary terms** `PersonalInformation` and `Revenue`
  (`createGlossaryTerm`) with opaque UUID ids, as the UI creates them: the term
  urn carries no name, so the term name in the fetched document is what flags
  the column.
- **Ingestion** of both databases with platform instance `haltsql_lab`; the
  source database's recipe has the `pattern_add_dataset_schema_tags` and
  `pattern_add_dataset_schema_terms` transformers, so these labels are in the
  ingested **`schemaMetadata`** aspect: `Sensitive` on `payments.card_token`,
  `PII` on `payments.card_last4`, term `PersonalInformation` on
  `audit_events.ip`, and (decoy) `Gold` on `order_items.description`.
- **GraphQL** `addTag` / `addTerm` on schemaField sub-resources (these land in
  **`editableSchemaMetadata`**): `PII` on `customers.email`, `customers.phone`,
  `users.email`, `payments.card_token`; `PII` + `Sensitive` on `customers.ssn`;
  `Sensitive` on `users.password_hash`; term `PersonalInformation` on
  `users.full_name` (its only label).
- **Must not count**: `Gold` on `orders.note` and on the `customers` dataset
  itself; term `Revenue` on `invoices.amount_cents`; a column description
  mentioning a "personal email address" on `orgs.name`; every other column
  untagged; and the decoy database's `app.leads.email`, tagged `PII`, which a
  `--database` filter must exclude.

Expected manifest: exactly 9 columns, each with exactly its labels
(`payments.card_token` gets `PII` and `Sensitive`, one from each aspect); the
snapshot lists the 9 `app` tables of the source database and is
non-authoritative.

## Recorded responses

The fixtures used by the offline tests were captured from this setup on
2026-11-08 (source database `dh_src_7719`, decoy `dh_decoy_7719`), by putting a
recording proxy between `haltsql schema fetch` and GMS, and saved
pretty-printed. Nothing was redacted: they hold no credentials, only urns,
container ids, timestamps and opaque scroll ids.

| Fixture | Request (`POST /api/graphql`, `scrollAcrossEntities`) |
|---|---|
| `test/catalog_fetch_datahub/fixtures/containers_database.json` | `CONTAINER`, filters `platform`, `platformInstance=haltsql_lab`, `typeNames=Database`, `name=dh_src_7719` |
| `test/catalog_fetch_datahub/fixtures/containers_schema.json` | `CONTAINER`, `typeNames=Schema`, `container=<database container>` |
| `test/catalog_fetch_datahub/fixtures/datasets_page{1,2,3}.json` | `DATASET`, `container=<schema container>`, `count=4`, then `scrollId=<nextScrollId>` twice |
| `test/catalog_fetch_datahub/fixtures/datasets_platform.json` | `DATASET`, `platform` only (both databases) |
| `test/catalog_fetch_datahub/fixtures/containers_platform.json` | `CONTAINER`, `platform` only |
| `test/catalog_fetch_datahub/fixtures/containers_empty.json` | database containers named `nosuch` |
| `test/catalog_fetch_datahub/fixtures/bad_scroll.json` | `DATASET` with `scrollId=bogus` (HTTP 200 with a GraphQL error) |
| `test/catalog_fetch_datahub/fixtures/unauthorized.json` | any request with an invalid bearer token (HTTP 401) |
| `examples/metadata/datahub_fetch.json` | `DATASET` in the source database's `app` schema, `count=100` (importer test) |

Observed server behaviour the provider relies on (v1.8.0): the `platform`,
`platformInstance`, `typeNames`, `name` and `container` filters all scope
`scrollAcrossEntities`; `container` matches only the direct parent (a dataset's
schema container), so the database is resolved to its schema containers first;
the last page has `nextScrollId: null`; a malformed scroll id is HTTP 200 with
a GraphQL error; an invalid token is HTTP 401 on both GMS and the frontend
(a missing one on GMS too); GMS serves `/api/graphql` only, the frontend both
`/api/graphql` and `/api/v2/graphql`.

To recapture after an upgrade, run with `KEEP_UP=1 SKIP_TIER3=1`, repeat the
fetches above through a recording proxy with the token in `$WORK/dh.token`, and
update the ids and expected counts in `test/catalog_fetch_datahub/` and
`test/catalog_tools/`.
