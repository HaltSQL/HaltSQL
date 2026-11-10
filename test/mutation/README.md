# Mutation testing

Passing tests say nothing about whether the tests are any good. These scripts
check it directly: each *mutant* breaks one security rule in the source (for
example "a cast on the tenant column counts as a tenant predicate", or "the
guard runs a verdict computed for a different SQL string"), and the test suite
must fail. A mutant that survives is a rule nothing tests.

```sh
make build
test/mutation/mutate.py test/mutation/engine.py            # ~25 minutes
PYTHON=clients/python/.venv/bin/python \
  test/mutation/mutate.py test/mutation/python.py          # needs the lab Postgres
test/mutation/mutate.py test/mutation/engine.py --only tenancy
```

Run it on a clean working tree: sources are edited in place and restored after
each mutant.

| List | Covers |
|---|---|
| `engine.py` | the analyzer, the tenancy prover, the parser bridge and its limits, the facade |
| `python.py` | the Python guard, the verdict model, the HTTP client, the MCP tool core |
| `services/server.py`, `auth.py`, `load.py`, `chain.py`, `proxy.py` | the HTTP sidecar's request path, caller authentication (JWT, JWKS, OIDC, mTLS), the policy and config loaders' security defaults, the audit chain verifier, and the proxy's enforcement and session handling (the proxy list needs the lab Postgres and `lab/.venv`) |

## Rules for the lists

- A mutant is one realistic regression, written so that the source still
  builds (`cond && false`, `cond || true`, a swapped result).
- Every mutant must be killed. If one survives, add a test that fails with the
  mutant and passes without it; do not delete the mutant.
- A mutant that cannot be killed because the changed code is redundant goes in
  `EQUIVALENT` with the reason. Three engine checks are in that list today.
- When you change a security rule, add its mutant in the same pull request.

The run exits 1 on an unexpected survivor, on a mutant that no longer applies
(`STALE`) or no longer builds (`INVALID`), and on an `EQUIVALENT` entry that is
now killed.
