# Security questionnaire answers

This page answers questions that commonly appear in vendor security
questionnaires (SIG, CAIQ and in-house forms). It is for the people filling
those forms in about HaltSQL, and for reviewers who receive them. Answers are
short and link to the page with the details.

Many service-oriented questions do not apply: HaltSQL is self-hosted
software that you run in your own environment, not a service operated by the
HaltSQL project.

## Product and deployment

| Question | Answer |
|---|---|
| What is HaltSQL? | A policy firewall that checks LLM-generated PostgreSQL queries against an allowlist policy and a trusted context before they run. See [overview.md](overview.md). |
| Is it SaaS, hosted or self-hosted? | Self-hosted. You run the library, CLI, `haltsql-server`, `haltsql-proxy` or `haltsql-mcp` in your own infrastructure. |
| Licence | MIT ([LICENSE](../../LICENSE)). The vendored libpg_query has its own licence, shipped as `LICENSE.libpg_query`. |
| Maturity | Pre-1.0 (0.1.x). Only the latest release receives security fixes ([SECURITY.md](../../SECURITY.md#supported-versions)). |
| Who maintains it? | The maintainers listed in [GOVERNANCE.md](../../GOVERNANCE.md). A change needs approval from one maintainer. |
| Is there a commercial support agreement or SLA? | None is described in this repository. |

## Data handling

| Question | Answer |
|---|---|
| What customer data does the vendor access? | None. HaltSQL does not send data to the HaltSQL project and has no usage telemetry. |
| What data does HaltSQL process? | SQL text, the context (for example tenant and user ids), policies and caller credentials. The wire proxy and `haltsql-mcp` also relay query results. See [overview.md](overview.md#what-each-component-sees-stores-logs-and-sends). |
| Does it store query results? | No. |
| Does it log SQL text? | Not by default. Audit records carry the SHA-256 and fingerprint of the SQL; the text is added only with `audit.log_raw_sql: true`. |
| Does it log bind values or context values? | No. The proxy's audit records list bind parameter numbers only. |
| Does it log credentials or tokens? | No. Tokens, passwords, SCRAM messages, keys and secret values are never logged ([secrets.md](../secrets.md), [proxy.md](../proxy.md#logs)). |
| Data residency | Wherever you deploy it. Data goes only to endpoints you configure (audit sinks, OIDC provider, secret stores, OPA, OTLP collector, bundle sources, the database). |
| Subprocessors | Not applicable: there is no hosted service. |
| Data retention | HaltSQL has no retention period of its own. Audit records are kept as long as the sink you choose keeps them (bucket lifecycle or Object Lock period, index lifecycle, topic retention). The admin report window is in memory and bounded by `report_window` (default 24h). |
| Data deletion | Delete records in the sink. HaltSQL has no deletion API. With WORM storage (S3 Object Lock, GCS retention), records cannot be deleted before the retention period ends. |
| Backups | Not applicable to HaltSQL itself; it is stateless apart from audit spools and bundle caches. Back up your audit storage and policy repository. |

## Encryption

| Question | Answer |
|---|---|
| Encryption in transit | `haltsql-server`: built-in TLS 1.2/1.3 with ECDHE and AEAD ciphers only, optional mTLS. `haltsql-proxy`: TLS to clients and to PostgreSQL. Outbound HTTPS checks the certificate chain and the host name against DNS SubjectAltNames. See [authentication.md](../authentication.md#built-in-tls) and [proxy.md](../proxy.md#config-reference). |
| Is TLS on by default? | No. The server listens on `127.0.0.1:8080` in plain HTTP unless `server.tls` is set; the proxy accepts plaintext unless `tls` is configured, and connects upstream without TLS unless `upstream.tls.mode` is set. See [hardening.md](hardening.md). |
| Encryption at rest | HaltSQL does not encrypt data at rest. Audit files, spool directories and bundle caches are written in plain text; use encrypted volumes and buckets. |
| Cryptographic libraries | OCaml `tls`, `x509`, `mirage-crypto` and `digestif`, statically linked. The release builds do not link OpenSSL. |
| FIPS 140 validation | No. |
| Key management | You manage all keys: TLS certificates (hot-reloaded on `SIGHUP` or file change), bundle signing keys (Ed25519), static token hashes. See [policy-bundles.md](../policy-bundles.md#key-management-and-rotation). |

## Identity and access

| Question | Answer |
|---|---|
| How do callers authenticate? | mTLS client certificates, OIDC/JWT bearer tokens, or static bearer tokens stored as SHA-256 hashes. The proxy uses SCRAM-SHA-256 or client certificates. See [authentication.md](../authentication.md). |
| SSO / IdP integration | OIDC: any issuer with a discovery document and JWKS. Policies can be selected from IdP groups or roles. |
| MFA | Not applicable: callers are services or tokens issued by your IdP. MFA is enforced by your IdP when it issues tokens. |
| Authorization model | Each identity is pinned to exactly one policy. The policy is an allowlist of statements, tables, columns and functions, with tenant scoping. |
| Can a caller choose its tenant? | Not with OIDC or mTLS: the tenant comes from the token or certificate configuration, and body fields outside `request_context_fields` are refused. With static tokens the calling service supplies the context. With the proxy, the context is bound to the proxy user. |
| Admin access | The admin API is off by default. When enabled, only callers listed in `server.admin.callers` may use it ([config-reference.md](../config-reference.md#serveradmin)). There is no web console and no default account or password. |
| Unauthenticated endpoints | `/healthz`, `/readyz` and `/metrics`. Restrict them at the network level, or use `--health-listen` ([http-api.md](../http-api.md#authentication)). |

## Logging and monitoring

| Question | Answer |
|---|---|
| Does it produce audit logs? | Yes. One record per decision, hash-chained, to stdout, file, S3, GCS, Elasticsearch/OpenSearch or Kafka ([audit-sinks.md](../audit-sinks.md)). |
| What is in an audit record? | Timestamp, request id, caller, caller type, subject, policy and policy version, verdict, reason codes, SQL hash, fingerprint, timing, and the chain hashes ([overview.md](overview.md#audit-records)). |
| Are logs tamper-evident? | The chain detects edited, deleted, inserted and reordered records. It is a hash chain, not a signature; use WORM storage or an independently stored head hash to detect a full rewrite ([audit-verify.md](../audit-verify.md#what-a-chain-does-not-prove)). |
| What happens if logging fails? | By default the request is refused (`503` from the server, SQLSTATE `58030` from the proxy). `buffer` and `drop` modes are opt-in. |
| SIEM integration | Elasticsearch/OpenSearch and Kafka sinks; stdout for any log shipper. |
| Monitoring | Prometheus metrics and OpenTelemetry (OTLP) traces and metrics ([observability.md](../observability.md)). |

## Secrets

| Question | Answer |
|---|---|
| Where are secrets stored? | In your secret store. Config files reference them with `${env:...}`, `${file:...}`, `${vault:...}`, `${aws-sm:...}` or `${gcp-sm:...}` placeholders ([secrets.md](../secrets.md)). |
| Are secrets ever shown? | No. `haltsql config show` and `haltsql-proxy validate` redact them; error messages never include them. |
| Hard-coded credentials | None. There are no default passwords or tokens. |

## Network

| Question | Answer |
|---|---|
| Listening ports | `haltsql-server` 8080 (default `127.0.0.1`), an optional health port; `haltsql-proxy` 6432 (default `127.0.0.1`). See [overview.md](overview.md#network-exposure). |
| Outbound connections | Only to endpoints you configure. None are required for verification. |
| Does it need internet access? | No. |

## Secure development and testing

| Question | Answer |
|---|---|
| Secure SDLC | Changes go through pull requests with maintainer approval; security-sensitive changes need allowed and denied tests; every fixed bypass adds an attack-corpus case ([GOVERNANCE.md](../../GOVERNANCE.md), [SECURITY.md](../../SECURITY.md)). |
| Testing | About 3,300 OCaml test cases, an attack corpus, property tests, a mutation fuzzer, integration tests, and a lab that runs every allowed query against real PostgreSQL under independent oracles ([how-it-works/assurance.md](../how-it-works/assurance.md), [testing.md](../testing.md)). |
| Static analysis (SAST) | No SAST tool runs on the OCaml code; CodeQL does not support OCaml. Trivy scans configuration and secrets weekly. |
| Penetration testing / external audit | None. HaltSQL 0.0.1 has not had an external security audit ([threat-model.md](../threat-model.md#guarantees-goals)). |
| Bug bounty | No bug bounty programme is described. [SECURITY.md](../../SECURITY.md#safe-harbor) offers safe harbor for good-faith research. |

## Vulnerability management

| Question | Answer |
|---|---|
| How are vulnerabilities reported? | Privately through GitHub Security Advisories ([SECURITY.md](../../SECURITY.md#reporting-a-vulnerability)). |
| Response targets | Acknowledgement within 3 business days, assessment within 10 business days, fixes for confirmed high or critical issues normally within 30 days ([SECURITY.md](../../SECURITY.md#what-to-expect)). |
| Disclosure policy | 90-day coordinated disclosure. Confirmed vulnerabilities get a GitHub Security Advisory and, where appropriate, a CVE. |
| How are customers notified? | Through GitHub Security Advisories and the changelog. There is no private customer notification list. |
| Dependency scanning | Weekly Trivy image scans (`HIGH`/`CRITICAL`), dependency review on pull requests, Dependabot for Actions, base images and SDK dependencies. OCaml dependencies are pinned by opam-repository commit and updated by hand ([supply-chain.md](supply-chain.md#scanning-and-dependency-updates)). |
| Incident response for the service | Not applicable: there is no hosted service. Your incident response covers your deployment. |

## Third-party dependencies and supply chain

| Question | Answer |
|---|---|
| Major dependencies | libpg_query (vendored, PostgreSQL's parser), OCaml libraries for TLS, X.509, crypto, HTTP and YAML/JSON. The exact opam package list is in `/usr/share/doc/haltsql/opam-packages.txt` in the image. |
| SBOM | Yes: a CycloneDX SBOM per release and an SPDX SBOM attestation on the image. Neither is guaranteed to list every statically linked OCaml library ([supply-chain.md](supply-chain.md#sboms)). |
| Signed releases | Yes: keyless cosign signatures on tarballs, checksums, SBOM and images; GitHub build-provenance attestations; npm provenance ([supply-chain.md](supply-chain.md)). |
| Container base image | `gcr.io/distroless/static-debian12:nonroot`, pinned by digest; runs as uid 65532 with a read-only root filesystem. |

## Availability and resilience

| Question | Answer |
|---|---|
| SLA / uptime | Not applicable: you operate it. |
| High availability | `haltsql-server` is stateless; run several replicas behind a Service (the Helm chart includes a PodDisruptionBudget and HPA), or one sidecar per agent pod ([deployment.md](../deployment.md)). |
| Behaviour on failure | Fail closed: errors produce denials, and an unavailable audit sink, IdP or OPA leads to refusals rather than unaudited or unchecked queries ([overview.md](overview.md#fail-closed-design)). |
| Policy updates without downtime | Atomic hot reload on `SIGHUP`, file change or a new signed bundle; a failed reload keeps the last good configuration. |

## Compliance

| Question | Answer |
|---|---|
| Certifications (SOC 2, ISO 27001, HIPAA, PCI DSS) | None. HaltSQL is open-source software, not a certified service. [compliance.md](compliance.md) maps its features to controls you operate. |
| Will you sign a BAA or DPA? | Not applicable: the HaltSQL project does not process your data. |

## Related

- [overview.md](overview.md)
- [hardening.md](hardening.md)
- [compliance.md](compliance.md)
- [supply-chain.md](supply-chain.md)
- [threat-model.md](../threat-model.md)
- [SECURITY.md](../../SECURITY.md)
