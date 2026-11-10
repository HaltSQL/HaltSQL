# Compliance mapping

This page maps HaltSQL features to controls in common security and privacy
frameworks, and lists the evidence each feature can produce. It is for
compliance, GRC and audit teams who need to explain where HaltSQL fits in an
organization's control set.

> **Note:** HaltSQL is open-source, self-hosted software. It is not certified
> or attested under SOC 2, ISO/IEC 27001, HIPAA or any other framework, and
> this page does not claim that it is. It maps HaltSQL features to controls
> that *you* operate. Whether a control is met depends on how you configure,
> run and monitor HaltSQL together with your other controls, and that
> responsibility stays with you and your auditor.

## Where HaltSQL fits

HaltSQL is a preventive and detective technical control for one specific
access path: SQL that an LLM agent generates for PostgreSQL. It:

- **restricts access**: a query can read only the relations, columns and
  functions the policy lists, and, for tenant-scoped tables, only the caller's
  tenant ([tenancy.md](../tenancy.md));
- **binds callers to policies**: every authenticated identity is pinned to one
  policy ([authentication.md](../authentication.md));
- **records decisions**: one hash-chained audit record per verdict
  ([audit-sinks.md](../audit-sinks.md));
- **controls policy change**: policies can be tested in CI, signed, and
  verified by every server before use ([policy-bundles.md](../policy-bundles.md)).

It does not cover identity lifecycle, the database's own access controls,
encryption at rest, backups, the data returned by allowed queries, or the
prompt. Pair it with the database controls in
[defense-in-depth.md](../defense-in-depth.md).

## Evidence you can collect

These artifacts appear in the tables below.

| Evidence | How to produce it |
|---|---|
| **E1. Audit chain verification** | `haltsql audit verify --json --expect-head <head> <file, directory or s3://...>`; keep the output and the head hash ([audit-verify.md](../audit-verify.md)) |
| **E2. Audit records** | The sink itself (file, S3 with Object Lock, GCS with retention, Elasticsearch, Kafka). Each record has caller, subject, policy version, verdict, reason codes and SQL hash. |
| **E3. Policy CI results** | `haltsql validate --json`, `haltsql lint-policy --json`, `haltsql test --json`, and the JUnit report from the GitHub Action or GitLab template ([policy-ci.md](../policy-ci.md)) |
| **E4. Signed policy bundles** | The `.haltsqlbundle` and `.sig` files, `haltsql bundle verify --json` output, and the bundle's `metadata.source.commit` ([policy-bundles.md](../policy-bundles.md)) |
| **E5. Running configuration** | `haltsql config show` (secrets redacted) and `GET /v1/admin/status`: loaded policies, versions, origin, bundle signer key ids, audit sink health, OPA settings ([http-api.md](../http-api.md#get-v1adminstatus)) |
| **E6. Policy version in each decision** | `policy_version` in every verdict and audit record: a content hash of the normalized policy ([verdict.md](../verdict.md)) |
| **E7. Metrics** | `haltsql_verify_total`, `haltsql_reasons_total`, `haltsql_auth_total`, `haltsql_audit_errors_total`, `haltsql_policy_reload_total` ([http-api.md](../http-api.md#get-metrics)) |
| **E8. Shadow reports** | `haltsql report` over audit records, or `GET /v1/admin/report` ([shadow-reports.md](../shadow-reports.md)) |
| **E9. Database drift check** | `haltsql rls check --json` against the live database ([rls-generation.md](../rls-generation.md)) |
| **E10. Release verification** | `cosign verify`, `cosign verify-blob` and `gh attestation verify` output for the artifacts you deploy ([supply-chain.md](supply-chain.md)) |

## SOC 2 (Trust Services Criteria)

| Criterion | HaltSQL feature | Evidence |
|---|---|---|
| CC6.1 Logical access security over protected information assets | Policy allowlists of tables, columns, functions and statement kinds; tenant predicate proof; bound tenancy mode | E3, E4, E5 |
| CC6.1 (authentication of system users) | mTLS identities, OIDC/JWT verification, hashed static tokens; proxy SCRAM-SHA-256 or client certificates | E5, E7 (`haltsql_auth_total`) |
| CC6.2, CC6.3 Authorization and modification of access | Each identity pinned to one policy; OIDC `allowed_policies` or `policy_from_groups` ties access to IdP groups; changes go through policy CI and signing | E3, E4, E5 |
| CC6.6 Protection against threats from outside system boundaries | Denies SQL outside the policy before it reaches the database (statement smuggling, catalog access, side-effecting functions) | E2, E7 (`haltsql_reasons_total`) |
| CC6.7 Restriction of transmission of information | Built-in TLS 1.2/1.3 and mTLS on the server; TLS on both sides of the proxy | E5 |
| CC6.8 Prevention of unauthorized or malicious software | Signed releases and provenance for HaltSQL itself; signed policy bundles | E4, E10 |
| CC7.2 Monitoring of system components for anomalies | Audit records per decision; metrics and OTLP traces; alerts on internal errors and audit failures | E2, E7, E8 |
| CC7.3 Evaluation of security events | Reason codes identify why a query was denied; shadow reports group denials by query and reason | E2, E8 |
| CC8.1 Change management | Policies in version control, tested in CI, built into deterministic signed bundles with source commit; servers refuse unsigned or rolled-back bundles from bundle sources; shadow mode for staged rollout | E3, E4, E6 |

## ISO/IEC 27001:2022 Annex A

| Control | HaltSQL feature | Evidence |
|---|---|---|
| 5.15 Access control | Allowlist policies; deny by default for tables, columns and functions | E3, E5 |
| 5.18 Access rights | Policy pinning per identity; group-to-policy mapping from the IdP | E5 |
| 5.33 Protection of records | Hash-chained audit records; S3 Object Lock or GCS retention for WORM storage | E1, E2 |
| 8.2 Privileged access rights | Admin API off by default and limited to listed callers; `allow_unauthenticated` off by default | E5 |
| 8.3 Information access restriction | Column allowlists, tenant scoping, `require_limit` row bounds | E3, E5 |
| 8.5 Secure authentication | OIDC with algorithm allowlist (no `none` or HMAC), mTLS, constant-time token comparison | E5, E7 |
| 8.9 Configuration management | Unknown and duplicate config keys are load errors; `config show`; atomic reload that keeps the last good configuration | E5 |
| 8.11 Data masking | Sensitive columns can be left out of a policy (HaltSQL denies them; it does not mask values) | E3 |
| 8.12 Data leakage prevention | Denies queries touching columns, tables or tenants outside the policy | E2, E8 |
| 8.15 Logging | One audit record per decision, fail-closed by default; raw SQL off by default | E1, E2 |
| 8.16 Monitoring activities | Metrics, traces, shadow reports | E7, E8 |
| 8.20 Networks security | TLS and mTLS; NetworkPolicy in the Helm chart with egress denied by default | E5 |
| 8.24 Use of cryptography | TLS 1.2/1.3 with AEAD ciphers; Ed25519 bundle signatures; SHA-256 audit chain | E4, E5 |
| 8.25, 8.29 Secure development and security testing | Policy test suites in CI; HaltSQL's own attack corpus, fuzzing and lab ([how-it-works/assurance.md](../how-it-works/assurance.md)) | E3 |
| 8.32 Change management | Signed, versioned policy bundles with source commit; no rollback from bundle sources | E4, E6 |

## GDPR

HaltSQL processes whatever personal data appears in SQL text and context
values, in your environment. It sends nothing to the HaltSQL project.

| Principle or article | HaltSQL feature | Evidence |
|---|---|---|
| Art. 5(1)(c) Data minimisation | Column allowlists let an agent read only the columns its task needs; `require_limit` bounds rows; PII-flagging helps find sensitive columns ([schema-and-pii.md](../schema-and-pii.md)) | E3 |
| Art. 5(1)(f) Integrity and confidentiality | Tenant isolation proof; TLS; hash-chained audit records | E1, E5 |
| Art. 25 Data protection by design and by default | Deny by default; raw SQL not logged by default; context values not written to audit records; OPA receives no SQL and no context values | E5 |
| Art. 32 Security of processing | Access restriction, encryption in transit, audit, fail-closed behaviour | E1, E2, E5 |
| Art. 5(2) Accountability | Audit records tie every decision to a caller, subject and policy version | E2, E6 |

Things to consider in your own records of processing:

- Audit records contain the caller's identity (`caller`, and `subject` for
  OIDC and mTLS callers), which may be personal data.
- `sql_sha256` and `fingerprint` are not anonymisation. With
  `audit.log_raw_sql: true` the SQL text, including literals, is stored.
- HaltSQL has no built-in retention or deletion of audit records. Retention is
  set where records are stored (bucket lifecycle, Object Lock period, index
  lifecycle, topic retention). WORM retention conflicts with erasure requests,
  so choose it with your DPO.

## HIPAA Security Rule technical safeguards (45 CFR 164.312)

| Safeguard | HaltSQL feature | Evidence | Not covered by HaltSQL |
|---|---|---|---|
| (a)(1) Access control | Policy allowlists, tenant scoping, policy pinning | E3, E5 | Access to ePHI through any path other than the agent |
| (a)(2)(i) Unique user identification | Audit `subject` from the OIDC `sub` or certificate identity | E2 | Static tokens and proxy users identify a service, not a person. Use OIDC tokens that carry the end user if you need per-user records. |
| (a)(2)(ii) Emergency access procedure | None | | Your procedure |
| (a)(2)(iii) Automatic logoff | Proxy `idle_timeout_seconds`; OIDC token expiry | E5 | Application sessions |
| (a)(2)(iv) Encryption and decryption | None at rest | | Encrypt audit storage, spool and cache volumes, and the database |
| (b) Audit controls | One audit record per decision; fail-closed by default; chain verification | E1, E2 | Database audit logs, review process |
| (c)(1) Integrity | Write statements denied unless the policy allows them; side-effecting functions and data-modifying CTEs denied | E3 | Database integrity controls and backups |
| (c)(2) Mechanism to authenticate ePHI | None for data. Audit records are hash-chained; policy bundles are signed. | E1, E4 | Integrity of ePHI itself |
| (d) Person or entity authentication | mTLS, OIDC, static tokens; SCRAM or certificates on the proxy | E5, E7 | |
| (e)(1), (e)(2)(i), (e)(2)(ii) Transmission security | TLS 1.2/1.3 on the server and on both sides of the proxy | E5 | TLS for paths HaltSQL is not on |

Also relevant: 164.308(a)(1)(ii)(D), information system activity review, is
supported by E2, E7 and E8.

## Gaps an auditor may raise

- HaltSQL 0.0.1 has not had an external security audit or penetration test
  ([threat-model.md](../threat-model.md#guarantees-goals)).
- Audit records do not include the context values (for example the tenant
  id) of a request, or the caller's network address. Join with your
  application logs if you need them.
- The audit chain is a hash chain, not a signature. It needs WORM storage or
  an independently kept head hash to detect whole-log rewrites.
- HaltSQL does not encrypt anything at rest.
- There is no switch that forbids unsigned policy files; enforce "signed
  bundles only" in change control (see [hardening.md](hardening.md#policy-delivery)).
- The sidecar and the library trust the calling code to enforce the verdict.
  Only the proxy enforces it itself.

## Related

- [overview.md](overview.md)
- [hardening.md](hardening.md)
- [security-questionnaire.md](security-questionnaire.md)
- [supply-chain.md](supply-chain.md)
- [audit-verify.md](../audit-verify.md)
- [policy-ci.md](../policy-ci.md)
- [threat-model.md](../threat-model.md)
