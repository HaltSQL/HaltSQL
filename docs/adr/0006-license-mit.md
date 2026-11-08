# ADR-0006: License HaltSQL under MIT

- **Status:** Accepted
- **Date:** 2026-11-08
- **Deciders:** Arnav Dadarya
- **Supersedes:** [ADR-0005](0005-license-apache-2.md)
- **Related:** [LICENSE](../../LICENSE); [NOTICE](../../NOTICE)

## Context

ADR-0005 chose Apache-2.0. The maintainer prefers the MIT License: it is
short, widely understood, and the same license as sql-guardrail, whose design
inspired HaltSQL.

## Decision

- License HaltSQL under the **MIT License**, copyright Arnav Dadarya.
- Every package carries the same license identifier (`MIT`): the opam packages,
  the Python, MCP, TypeScript, Go and Java clients, the container image label
  and the OpenAPI document.
- Keep [NOTICE](../../NOTICE) for third-party attributions (libpg_query,
  PostgreSQL, sql-guardrail).

## Consequences

- MIT has no explicit patent grant, unlike Apache-2.0. Adopters who need one
  should know this.
- Vendored libpg_query (BSD-3-Clause) and PostgreSQL (PostgreSQL License)
  sources keep their own licenses. Both are compatible with MIT distribution,
  and their license texts still ship in every release.
- Test cases adapted from sql-guardrail are MIT, the same as the rest of the
  project, and are still attributed in the files that contain them.
