// Package haltsql is a fail-closed client for the HaltSQL sidecar
// (haltsql-server), which verifies LLM-generated PostgreSQL against a policy.
//
// The contract is simple: run a SQL string only when Verify returned a
// Verdict with Allowed == true and a nil error. Every failure (non-200
// response, timeout, connection error, malformed or inconsistent body, a
// verdict whose sql_sha256 does not match the SQL that was sent) is returned
// as an error, never as an allow.
//
//	hc, err := haltsql.New("http://127.0.0.1:8080", haltsql.WithToken(os.Getenv("HALTSQL_TOKEN")))
//	if err != nil { ... }
//	rows, verdict, err := haltsql.GuardedQuery(ctx, hc, db,
//	    "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 50",
//	    haltsql.Context{"tenant_id": session.TenantID})
//	var denied *haltsql.DeniedError
//	if errors.As(err, &denied) { /* return denied.Verdict.Reasons to the agent */ }
//
// The package uses only the standard library. GuardedQuery and GuardedExec
// work with any database/sql driver; with github.com/jackc/pgx/v5/stdlib a
// set-valued bind param ([]string) is sent as a Postgres array, as
// "col = ANY($n)" requires. For drivers that cannot encode []string (lib/pq),
// use Verdict.ArgsArrayLiteral.
package haltsql
