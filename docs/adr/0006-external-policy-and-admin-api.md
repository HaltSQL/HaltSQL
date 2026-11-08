# ADR-0006: Deny-only external policy (OPA) and an opt-in admin API

- **Status:** Accepted
- **Date:** 2026-11-08
- **Deciders:** Arnav Dadarya
- **Related:** [ADR-0004](0004-verdict-schema-and-reason-codes.md); [docs/opa.md](../opa.md); [docs/http-api.md](../http-api.md); [docs/shadow-reports.md](../shadow-reports.md); [docs/reason-codes.md](../reason-codes.md)

## Context

Enterprises want two things the 0.1 sidecar does not offer:

1. **Organisation-specific rules that live outside HaltSQL policies**, often
   already written in Rego for Open Policy Agent (OPA): time windows, ticket
   requirements, per-team data classifications.
2. **Operational visibility**: which policy bundle version a running server
   serves, whether its sources and audit sinks are healthy, and what a policy
   in shadow mode would have denied.

Both affect stable contracts: the reason-code list (ADR-0004), the verdict
JSON and the HTTP API. Both also add new ways for an allow to be produced or
information to leak, so they must fail closed.

## Decision

**External policy (OPA).**

- OPA is consulted only **after** HaltSQL has allowed a statement (and, in
  shadow mode, to report what it would have denied). It is never consulted
  instead of HaltSQL.
- OPA can only turn an allow into a deny, **never a deny into an allow**.
  There is no configuration that changes this.
- An OPA denial uses a new stable reason code, **`E_EXTERNAL_POLICY`**, with
  rule `opa.decision`. Under ADR-0004 the code is never renamed or reused.
  OPA-supplied reasons are capped (16 reasons, 200 bytes each) and stripped
  of control characters.
- A denied verdict carries no `bind_params`, the same as every other denial.
- Any OPA error (undefined decision, malformed result, non-200 status, TLS or
  connection failure, timeout, response over 1 MiB) goes through `on_error`.
  The default is `deny`; `allow_haltsql_verdict` exists only for advisory
  rules and must be set explicitly.

**Admin API.**

- `GET /v1/admin/status` (served generation, bundle versions, source and sink
  health, pending audit restarts) and `GET /v1/admin/report` (the rolling
  shadow/enforce report and suggestions).
- **Off by default.** With `server.admin` disabled, both return `404`.
- When enabled, callers must authenticate (`401`) and be listed in
  `server.admin.callers` as `token:<name>`, `oidc:<provider>` or
  `mtls:<identity>` (`403` otherwise). Anonymous callers never match.
- Responses never contain secrets or tokens. Reports identify statements by
  SQL hash and fingerprint; raw SQL appears only when `audit.log_raw_sql` is
  explicitly enabled.

## Alternatives considered

- **Let OPA decide on its own, or override HaltSQL denials.** This would make
  tenancy and column rules bypassable by a misconfigured Rego policy. HaltSQL's
  parser-based checks are the security boundary, so OPA can only narrow them.
- **Reuse an existing code (for example `E_FUNCTION_DENIED` or `E_INTERNAL`) for OPA denials.** That would
  make an external denial impossible to tell apart from a HaltSQL denial in
  audit records and agent hints, and would change an existing code's meaning,
  which ADR-0004 forbids.
- **Fail open on OPA errors by default.** Rejected: an unreachable OPA would
  silently disable every external rule.
- **Expose status and reports on the public `/v1/verify` listener without a
  caller list.** Rejected: bundle versions, sink endpoints and denial patterns
  help an attacker. The API is opt-in and authorised per caller.

## Consequences

- Clients that already treat unknown reason codes as denials (required by
  ADR-0004) handle `E_EXTERNAL_POLICY` with no change.
- Each allowed request costs one extra HTTP round trip to OPA when it is
  configured; `timeout_ms` bounds it, and a timeout denies by default.
- The admin API is a new authenticated surface to keep stable within `/v1`:
  fields may be added, never renamed or removed.

## Follow-up

- Tests against a real OPA container cover allow, deny, every `on_error`
  mode, OPA down and "OPA cannot allow a HaltSQL deny" (`test/opa`,
  `test/e2e/test_opa.py`).
- Admin API authorisation is covered in `test/server`, `test/wiring` and the
  E2E suite.
