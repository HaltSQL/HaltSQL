# Shared client test vectors

Every HaltSQL client (Python, TypeScript, Go, Java, ...) should pass these.
Each file in `cases/` is one request and the verdict the real `haltsql` CLI
returned for it:

```json
{
  "name": "saas_allow_bound_simple",
  "description": "Bound tenancy: one table with its tenant predicate; binds $1 to the tenant.",
  "policy_file": "test/fixtures/policies/saas.yaml",
  "request": {
    "sql": "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
    "context": { "tenant_id": "acme" },
    "policy": "saas"
  },
  "verdict": { "allowed": true, "reasons": [], "bind_params": [{"param": 1, "value": "acme"}], "...": "..." },
  "compare": ["allowed", "reasons[].code", "shadow_reasons[].code", "policy.name", "policy.version",
              "statement_kind", "tables", "columns", "bind_params", "fingerprint", "sql_sha256"]
}
```

- `request` is exactly a `POST /v1/verify` body. `request.policy` is the
  policy's `metadata.name`; `policy_file` (relative to the repository root) is
  the document to load.
- `verdict` is the CLI's `verify --json` output. `elapsed_us` is not
  deterministic; `message`, `hint`, `rule`, and `loc` may change between
  releases. Compare only the fields listed in `compare`.

## How clients use them

1. **Parsing:** decode every `verdict` with your client's verdict type. Check
   that `sql_sha256` equals the SHA-256 of the UTF-8 bytes of `request.sql`
   (one case has non-ASCII SQL), and that `bind_args()` (or your equivalent)
   gives positional values in `$n` order, with tenant sets as lists.
2. **Against a real sidecar:** start `haltsql-server` with every distinct
   `policy_file` and `--allow-unauthenticated`, post each `request`, and compare
   the `compare` fields. The Python suite does this in
   `clients/python/tests/test_vectors.py`.

## Regenerating

```sh
eval $(opam env); dune build ./bin/haltsql/main.exe
python3 clients/testvectors/generate.py          # rewrite cases/
python3 clients/testvectors/generate.py --check  # exit 1 if any case drifted
```

Cases are defined in `generate.py`. Add new ones there, never by hand.
