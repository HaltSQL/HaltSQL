# haltlab: proxy mode

Runs a normal haltlab Scenario through a live `haltsql-proxy` instead of only
asking `haltsql verify --batch`. See `runner.py` for the oracles and
[docs/proxy.md](../../docs/proxy.md) for the proxy itself.

```bash
cd lab
make up
HALTSQL_BIN=../_build/default/bin/haltsql/main.exe \
HALTSQL_PROXY_BIN=../_build/default/bin/proxy/main.exe \
  .venv/bin/python -m proxy run proxy/scenarios/proxy-smoke.yaml
.venv/bin/python -m pytest proxy/test_proxylab.py   # helper unit tests
```

What a run does:

1. Creates `haltlab_<scenario>_proxy_pg17`, installs the fixture and data
   (same code as the normal harness), and generates the workloads.
2. Verifies everything with the CLI (the reference verdicts).
3. Starts `haltsql-proxy` with one SCRAM user per distinct context, upstream
   = the lab database.
4. Sends every query through the proxy with the extended protocol inside
   `BEGIN READ ONLY ... ROLLBACK`, passing **another tenant's id** for every
   tenancy parameter.
5. Checks: proxy decision == CLI verdict (parity); allowed queries return the
   same rows as the SQL executed directly with the CLI's `bind_params`
   (divergence); no foreign honeytokens in the proxy's output.
6. Writes `out/<scenario>-proxy/report.{md,json}`, stops the proxy (must exit
   0) and drops the database.

Exit 0 pass, 1 fail, 2 setup error. The binaries are found via
`HALTSQL_BIN` / `HALTSQL_PROXY_BIN`, then `_build*/default/...`, then `PATH`.
