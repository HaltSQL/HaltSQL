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
  (alcotest :with-test)
  (qcheck-core :with-test)
  (qcheck-alcotest :with-test)))

(package
 (name haltsql-server)
 (synopsis "HTTP sidecar for the HaltSQL policy firewall")
 (depends
  (ocaml
   (>= 5.1))
  (haltsql
   (= :version))
  (cohttp-lwt-unix
   (>= 5.0))
  (lwt
   (>= 5.6))))
