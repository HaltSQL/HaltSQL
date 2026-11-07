# ADR-0004: Versioned verdict schema and stable reason codes

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Arnav Dadarya
- **Related:** PLAN.md §6.1, §6.2; [docs/verdict.md](../verdict.md); [docs/reason-codes.md](../reason-codes.md)

## Context

HaltSQL's output is consumed by programs: agent frameworks that feed denials
back to a model, audit pipelines, dashboards, alerting, and CI tests. If the
output changes shape or meaning between releases, integrations break silently,
and in the worst case a client misreads a denial as an allow.

## Decision

- Every check returns a **verdict** (`lib/core/verdict.ml`) whose JSON form is
  a public API, versioned with `apiVersion: haltsql.dev/v1` and the HTTP `/v1`
  prefix.
- Verdict fields: `allowed`, `reasons`, `shadow_reasons`, `policy {name,
  version}`, `statement_kind`, `tables`, `columns`, `bind_params`,
  `fingerprint`, `sql_sha256`, `elapsed_us`.
- Within v1, fields are only **added**, never renamed, removed, or changed in
  meaning. Clients must ignore unknown fields.
- Each reason has a **stable `code`** (`lib/core/reason.ml`), plus `message`,
  `rule`, optional `loc` (byte offset), and optional `hint` for agents.
- Reason codes are **never renamed or reused**, even before 1.0. New codes may
  be added in minor releases; clients must treat unknown codes as denials.
- `message`, `rule`, and `hint` are human-oriented and may change at any time.
  Integrations must match on `code` only.
- In `enforce` mode, `allowed` is true exactly when `reasons` is empty. In
  `shadow` mode, `allowed` is always true and would-be denials go to
  `shadow_reasons`.
- `bind_params` is always empty when a query is denied.
- `policy.version` is a SHA-256 over the normalized policy, identical for YAML
  and JSON forms, so every decision can be traced to an exact policy.
- Determinism: for the same SQL, policy, and context, `allowed`, the reason
  codes, `tables`, `columns`, and `bind_params` are identical across runs and
  platforms. `elapsed_us` is the only intentionally nondeterministic field.

## Alternatives considered

- **Boolean only.** Gives agents nothing to act on and makes audits weak.
  Rejected.
- **Free-text reasons.** Unstable for programs and localization. Rejected.
- **Numeric codes.** Harder to read in logs and prompts; string codes are
  self-describing.
- **HTTP errors for denials.** Conflates "the query is not allowed" with "the
  request failed". Denials are `200` verdicts; HTTP errors mean the check did
  not happen, which clients treat as a denial.

## Consequences

- Adding a rule means choosing an existing code or adding a new one with
  documentation in `docs/reason-codes.md` and an OpenAPI update.
- Golden tests pin the verdict JSON shape.
- A v2 verdict format, if ever needed, will be served side by side with v1.
