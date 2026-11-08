# Tier-3 catalog check

Every data-catalog integration (dbt, DataHub, OpenMetadata, Unity Catalog,
Atlan, Collibra, ...) ends in a PII manifest (`haltsql schema import` or
`haltsql schema fetch`, format in [docs/schema-and-pii.md](../../docs/schema-and-pii.md)).
The tier-3 check proves, against a real Postgres, that the columns tagged in
that manifest are blocked, and that they are blocked *because of* the manifest.

```bash
cd lab
make venv
make catalog-tier3 PII=path/to/pii.json            # positive run + negative control
make catalog-tier3 PII="a.json b.json" FIXTURE=saas_shared MODE=both
make catalog-tier3-example                         # on examples/metadata/dbt_manifest.json
```

It needs the lab Postgres (`make up`, port 5417) and the `haltsql` binary
(`HALTSQL_BIN`, else `../_build/default/bin/haltsql/main.exe`). Every database
it creates has a per-run id in its name, so several runs can share one server.
Exit status: `0` pass, `1` a check failed, `2` usage or infrastructure error.
Output goes to `lab/out/catalog-tier3/<run id>/` (`summary.json`,
`positive/report.md`, `negative/report.md`, the snapshot and both policies).
`python -m catalogs.tier3 --help` lists every option.

## What it does

1. **Snapshot.** Creates a fresh database from the fixture (default
   `saas_shared`, `schemas/saas_shared.sql`) and runs `haltsql schema pull`.
2. **Draft.** `haltsql policy draft --pii <manifest> --tenant-column tenant_id
   --no-name-heuristics`, then `haltsql lint-policy`. Name heuristics are off,
   so the manifest is the only reason a column can be excluded.
3. **Structural check.** Every manifest column that exists in the database must
   be absent from the drafted policy. Manifest columns not in the fixture are
   listed and ignored; a manifest that matches *no* fixture column fails (the
   check would prove nothing). The tenant column is never excluded by the
   drafter, so a tag on it is reported as a warning and not checked.
4. **Positive run.** haltlab runs with the drafted policy as both the verifier
   policy and the oracle ground truth (`python -m harness run --policy P`):
   honeytokens are planted in every column the policy denies and `haltlab_cols`
   is re-granted `SELECT` on exactly its allowed columns. Workloads: 200 benign,
   400 adversarial (all transforms), 200 column attacks (`star_over_pii[_wrapped]`,
   `whole_row_reference`, `whole_row_wrapped`, `denied_column_{direct,wrapped,in_predicate}`)
   and `targeted.jsonl`: for every manifest column, `SELECT *`, `t.*`, `*` in a
   CTE and a derived table, `row_to_json(t)`, `to_json(t)`, `to_jsonb(t)`,
   `json_agg(t)`, `t::text`, a bare row reference, and per column a direct read,
   a predicate, a CTE, a derived table, a scalar subquery, a cast and an
   `ORDER BY`. Pass: 0 escapes, 0 column leaks, 0 side effects, and every
   targeted query denied.
5. **Negative control.** The same workloads, but the verifier gets a policy
   drafted from an **empty** manifest (`--negative-control empty-manifest`, the
   default) or the allow-everything fake verifier (`fake-allow`), while the
   oracles still judge against the catalog-drafted policy
   (`--oracle-policy`). Pass: column leaks are detected, and **every** manifest
   column in the database is individually seen leaking (by its honeytoken, or
   by the column-privilege oracle on a single-column targeted query). This is
   what shows the positive result is not vacuous: without the catalog tags the
   same pipeline leaks those exact columns.

`MODE=positive` or `MODE=negative` runs one half.

## For integration authors

Your end-to-end test is: export (or fetch) catalog metadata for the
`saas_shared` schema, produce a PII manifest with your integration, then

```bash
make -C lab catalog-tier3 PII=$PWD/out/pii.<tool>.json
```

and require exit status 0. Tag at least the columns the fixture treats as
sensitive (`users.email`, `users.password_hash`, `customers.email`,
`customers.phone`, `customers.ssn`, `payments.card_token`, `audit_events.ip`);
any other existing column you tag (for example `users.full_name`) is checked
too. Table keys must be `schema.table` as stored in Postgres (`app.customers`).

## Harness options used here

`python -m harness run SCENARIO` accepts:

| Option | Meaning |
|---|---|
| `--policy P` | Policy for the verifier (and, without `--oracle-policy`, the oracles). Overrides the scenario's `policy:` and the fixture's policy. |
| `--oracle-policy Q` | Ground truth for the oracles: honeytokens in every column `Q` denies, `haltlab_cols` granted exactly `Q`'s allowed columns, column attacks aimed at `Q`'s denied columns. Scenario key: `oracle_policy:`. |
| `--run-id ID` | Added to database names so concurrent runs on one server do not collide. |

Whenever the oracle policy is not the fixture's own policy, the harness
re-applies the `haltlab_cols` grants from it after loading (the fixture SQL
only grants the fixture's policy).
