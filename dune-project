(lang dune 3.0)

(name haltsql)

(version 0.1.0)

(generate_opam_files true)

(license Apache-2.0)

(authors "Arnav Dadarya")

(maintainers "Arnav Dadarya")

(source
 (github ardada2468/HaltSQL))

(documentation "https://github.com/ardada2468/HaltSQL/tree/main/docs")

; Package layout (see PLAN.md section 14):
;  - haltsql: the core libraries (haltsql, haltsql.core/parse/load/analyzer/
;    pgquery: no network or TLS dependencies), the `haltsql` CLI, and the
;    libraries the CLI links: haltsql.cloud (secret resolvers), haltsql.bundle
;    (signed bundles), haltsql.rlsgen and haltsql.catalog_tools (Postgres
;    clients).
;  - haltsql-server: the HTTP sidecar plus its server-only libraries
;    haltsql-server.auth (OIDC/JWT/mTLS) and haltsql-server.telemetry (OTLP).
;  - haltsql-proxy: the wire-protocol firewall and haltsql-proxy.pgwire.

(package
 (name haltsql)
 (synopsis "Policy firewall for LLM-generated PostgreSQL")
 (description
  "HaltSQL verifies that an exact SQL string is allowed for a caller under a declarative policy (tables, columns, functions, limits, tenant isolation) using the real PostgreSQL parser. It never rewrites SQL and never connects to the database.")
 (tags
  (sql postgres security llm policy firewall))
 (depends
  (ocaml
   (>= 5.1))
  (dune
   (>= 3.0))
  (yojson
   (>= 2.0))
  (yaml
   (>= 3.0))
  (digestif
   (>= 1.0))
  (cmdliner
   (>= 1.1))
  (lwt
   (>= 5.6))
  (cohttp
   (>= 6.0))
  (cohttp-lwt
   (>= 6.0))
  (cohttp-lwt-unix
   (>= 6.0))
  (http
   (>= 6.0))
  (conduit-lwt-unix
   (>= 7.0))
  (uri
   (>= 4.0))
  (base64
   (>= 3.5))
  (ptime
   (>= 1.0))
  (x509
   (>= 1.2))
  (tls
   (>= 1.0))
  (tls-lwt
   (>= 1.0))
  (ca-certs
   (>= 1.0))
  (domain-name
   (>= 0.4))
  (ipaddr
   (>= 5.0))
  (eqaf
   (>= 0.9))
  (mirage-crypto-pk
   (>= 1.0))
  (mirage-crypto-ec
   (>= 1.0))
  (mirage-crypto-rng
   (>= 1.0))
  (alcotest :with-test)
  (qcheck-core :with-test)
  (qcheck-alcotest :with-test)))

(package
 (name haltsql-server)
 (synopsis "HTTP sidecar for the HaltSQL policy firewall")
 (description
  "haltsql-server serves POST /v1/verify over HTTP or built-in TLS/mTLS, authenticates callers with static tokens, OIDC/JWT or client certificates, writes a hash-chained audit log to files, S3 or GCS, loads signed policy bundles, resolves secrets from Vault, AWS or GCP, and exports OpenTelemetry traces and metrics.")
 (depends
  (ocaml
   (>= 5.1))
  (haltsql
   (= :version))
  (cmdliner
   (>= 1.1))
  (yojson
   (>= 2.0))
  (digestif
   (>= 1.0))
  (cohttp
   (>= 6.0))
  (cohttp-lwt
   (>= 6.0))
  (cohttp-lwt-unix
   (>= 6.0))
  (http
   (>= 6.0))
  (conduit-lwt-unix
   (>= 7.0))
  (lwt
   (>= 5.6))
  (uri
   (>= 4.0))
  (zarith
   (>= 1.12))
  (tls
   (>= 1.0))
  (tls-lwt
   (>= 1.0))
  (x509
   (>= 1.2))
  (ptime
   (>= 1.0))
  (eqaf
   (>= 0.9))
  (mirage-crypto-pk
   (>= 1.0))
  (mirage-crypto-ec
   (>= 1.0))
  (mirage-crypto-rng
   (>= 1.0))
  (domain-name :with-test)
  (alcotest :with-test)))

(package
 (name haltsql-proxy)
 (synopsis "PostgreSQL wire-protocol firewall for LLM-generated SQL")
 (description
  "haltsql-proxy sits in front of PostgreSQL, authenticates clients (SCRAM-SHA-256 or TLS client certificates), verifies every statement with HaltSQL and enforces bound tenancy by rewriting Bind parameters.")
 (depends
  (ocaml
   (>= 5.1))
  (haltsql
   (= :version))
  (cmdliner
   (>= 1.1))
  (yojson
   (>= 2.0))
  (digestif
   (>= 1.0))
  (lwt
   (>= 5.6))
  (tls
   (>= 1.0))
  (tls-lwt
   (>= 1.0))
  (x509
   (>= 1.2))
  (ptime
   (>= 1.0))
  domain-name
  ipaddr
  (mirage-crypto-rng
   (>= 1.0))
  (mirage-crypto-pk :with-test)
  (mirage-crypto-ec :with-test)
  (alcotest :with-test)))
