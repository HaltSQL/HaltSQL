# ADR-0005: License HaltSQL under Apache-2.0

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Arnav Dadarya
- **Related:** PLAN.md §4; [LICENSE](../../LICENSE); [NOTICE](../../NOTICE)

## Context

HaltSQL is security infrastructure intended for use inside companies. Its
adopters' legal teams look for a well-known, permissive license with clear
patent terms. HaltSQL also builds on third-party work:

- libpg_query (BSD-3-Clause) and the Postgres sources it contains (PostgreSQL
  License), vendored in `vendor/libpg_query`;
- the policy design of the sql-guardrail project (MIT), whose design (not
  code) inspired HaltSQL, and whose test cases may be adapted for conformance
  tests;
- OCaml libraries under permissive licenses.

## Decision

- License HaltSQL under the **Apache License 2.0**.
- Keep a `NOTICE` file crediting libpg_query, PostgreSQL, and sql-guardrail.
- Ship third-party license texts with source and binary releases
  (`vendor/libpg_query/LICENSE` is included in release archives) and publish a
  CycloneDX SBOM per release.
- Any test cases adapted from sql-guardrail keep their MIT attribution in the
  files that contain them.
- Contributions are accepted under the Developer Certificate of Origin
  (`git commit -s`), not a CLA.

## Alternatives considered

- **MIT.** Simple and compatible, but no explicit patent grant.
- **AGPL / BSL / other source-available licenses.** Would discourage adoption
  as an embedded security control. An open-core model for future components
  (for example a proxy or policy UI) remains an open question and would need
  its own ADR; it does not change the license of what is released here.
- **CLA instead of DCO.** More friction for contributors; DCO is sufficient
  for an Apache-2.0 project of this size.

## Consequences

- Users get a patent grant and a familiar license.
- All dependencies must be compatible with Apache-2.0 distribution; the
  security workflow's dependency review denies strong copyleft licenses.
- Release archives must include `LICENSE`, `NOTICE`, and the libpg_query
  license.
