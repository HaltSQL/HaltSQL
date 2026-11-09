# OpenMetadata live validation

Proves `haltsql schema fetch --from openmetadata` against a real OpenMetadata
server, end to end. Opt-in: not part of `dune test` (it needs Docker and the lab
Postgres). Runs weekly and on demand in `.github/workflows/catalog-live.yml`
(job `openmetadata`).

```sh
make -C lab up                                   # lab Postgres on 127.0.0.1:5417
opam exec -- dune build --root . ./bin/haltsql
test/catalog_live/openmetadata/run.sh            # up -> seed -> fetch -> assert -> tier-3 -> down
```

| File | What it is |
|---|---|
| `docker-compose.yml` | OpenMetadata **2.0.7** (server, its Postgres, Elasticsearch 9.3.0), from the official release compose, minus the Airflow container. API on `127.0.0.1:${OM_PORT:-8595}`, nothing else published. About 3 GiB of memory. |
| `seed.py` | Creates a source database from `lab/schemas/saas_shared.sql`, ingests it with OpenMetadata's real Postgres connector (`metadata ingest` from `openmetadata-ingestion==2.0.7.2`), labels columns through the REST API, creates the read-only bot HaltSQL uses, and prints the expected manifest. Idempotent. |
| `assert_fetch.py` | Compares the fetched manifest and snapshot with what `seed.py` applied. |
| `run.sh` | The whole flow, with cleanup (`docker compose down -v`, source database dropped) on exit. |

## What the seed does (governance-team style)

All through the public REST API as the `admin` user, after ingestion:

- **Classification tags** (JSON-patch `add` on `/columns/{i}/tags` of
  `PATCH /api/v1/tables/{id}`): `PII.Sensitive` on `customers.email`,
  `customers.ssn`, `users.email`, `users.password_hash`, `payments.card_token`;
  `PersonalData.Personal` on `customers.phone`, `audit_events.ip`;
  `PersonalData.SpecialCategory` on `customers.ssn`; `PII.NonSensitive` on
  `payments.card_last4` (OpenMetadata defines it as PII that is publicly
  available, so it still counts).
- **Glossary term**: glossary `Business`, term `PersonalInformation`, applied to
  `users.full_name` (its only label, so the glossary path is what flags it).
- **Must not count**: `Tier.Tier1` on `orders.note` and on the `customers` table
  itself; a custom non-PII classification `DataDomain.Finance` on
  `invoices.amount_cents`; a column description mentioning a "personal email
  address" on `orgs.name`; every other column untagged.
- **Decoy database** `lake` in the same service, registered through the API only
  (`PUT /api/v1/databases`, `/databaseSchemas`, `/tables`), with a STRUCT column
  `context` whose child `user_email` is tagged `PII.Sensitive`. It exercises
  nested `children`, and a `--database` filter must exclude it.
- **Bot** `haltsql-reader` with only the `DataConsumer` role; its JWT
  (`GET /api/v1/users/auth-mechanism/{id}`) is the `OPENMETADATA_TOKEN`.

Expected manifest: exactly the 9 columns above, each with exactly its applied
tag FQNs; the snapshot lists the 9 `app` tables of the source database and is
non-authoritative.

## Recorded responses

The fixtures used by the offline tests were captured from this setup on
2026-11-08 (bot JWT, `curl`, pretty-printed with `jq`; nothing redacted: they
hold no credentials, only entity ids, the in-container `href` host
`localhost:8585`, timestamps and opaque paging cursors):

| Fixture | Request |
|---|---|
| `examples/metadata/openmetadata_tables.json` | `GET /api/v1/tables?fields=columns,tags&include=non-deleted&database=haltsql_lab_pg.om_src_7341&limit=100` |
| `examples/metadata/openmetadata_struct_table.json`, `test/catalog_fetch_openmetadata/fixtures/tables_lake.json` | same, `database=haltsql_lab_pg.lake` |
| `test/catalog_fetch_openmetadata/fixtures/tables_page{1,2,3}.json` | same, `limit=4`, then `after=<paging.after>` twice |
| `test/catalog_fetch_openmetadata/fixtures/tables_service.json` | same, `service=haltsql_lab_pg` instead of `database` |
| `test/catalog_fetch_openmetadata/fixtures/unauthorized.json` | any request with an invalid bearer token (HTTP 401) |

Observed server behaviour the provider relies on (2.0.7): `database`,
`databaseSchema` and `service` all scope `/api/v1/tables`; an unknown name
returns `{"data": [], "paging": {"total": 0}}` (not 404); the last page has no
`paging.after`; a malformed cursor is HTTP 400; re-running ingestion keeps
manually applied column tags.

To recapture after an upgrade, run with `KEEP_UP=1 SKIP_TIER3=1`, repeat the
requests above with the token in `$WORK/om.token`, and update the expected
counts in `test/catalog_fetch_openmetadata/` and `test/catalog_tools/`.
