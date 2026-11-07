# ADR-0001: Parse SQL with a vendored libpg_query and our own thin C binding

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Arnav Dadarya
- **Related:** PLAN.md §4, §12; ADR-0002

## Context

HaltSQL decides whether a SQL string is safe to run on PostgreSQL. If HaltSQL
parses a string differently from the server, an attacker can write SQL that
looks harmless to HaltSQL and does something else in Postgres (a parser
differential). The parser is therefore the foundation of every guarantee.

Options for parsing Postgres SQL from OCaml:

1. A hand-written or generated grammar in OCaml (Menhir).
2. A general-purpose multi-dialect SQL parser.
3. libpg_query, which extracts the actual Postgres parser (`gram.y`, scanner,
   and supporting code) into a C library, through the opam `pg_query` bindings.
4. libpg_query, vendored, through our own thin C stubs.

Facts we found while prototyping:

- The opam `pg_query` bindings bundle an old libpg_query (Postgres 13 grammar)
  that fails to compile on current macOS toolchains, and depend on ctypes and
  libffi.
- libpg_query 17-6.2.5 tracks the Postgres 17.7 grammar and builds cleanly with
  a C compiler and make.
- libpg_query keeps parser state in thread-local memory, so the OCaml runtime
  lock can be released during a parse.

## Decision

- Vendor **libpg_query 17-6.2.5** (Postgres 17.7 grammar) in
  `vendor/libpg_query`, with its `LICENSE` (BSD-3-Clause for libpg_query; the
  PostgreSQL License for the extracted Postgres sources). Test data,
  examples, and temporary directories are removed.
- Bind it with **our own C stubs** in `lib/pgquery` (`pgquery_stubs.c`,
  `pgquery_raw.mli`), exposing only what HaltSQL needs: parse to JSON,
  fingerprint, and the Postgres version.
- The stubs **release the OCaml runtime lock** while parsing, so verification
  scales across OCaml 5 domains and server threads.
- The stubs **reject input containing a NUL byte** before calling C. A C string
  would stop at the NUL, so text after it would be invisible to the parser but
  might still reach the server through a driver that sends the full buffer.
- The JSON parse tree is converted into HaltSQL's typed AST (ADR-0002).
- No ctypes/libffi dependency.

Upgrading libpg_query: replace `vendor/libpg_query` with a new release tarball,
delete its `test/`, `testdata/`, `tmp/`, and `examples/` directories, update
`NOTICE` if needed, and run the full test suite and attack corpus. A new
Postgres major requires a new ADR and a changelog entry.

## Alternatives considered

- **Own grammar in OCaml.** Postgres's grammar is large and changes every
  release. Any divergence is a potential bypass. Rejected.
- **Multi-dialect SQL parser.** Approximates Postgres rather than being
  Postgres; same differential risk. Rejected.
- **opam `pg_query` bindings.** Old grammar, build failures on current macOS,
  extra libffi/ctypes dependency, and no control over the runtime lock or NUL
  handling. Rejected for now; we can revisit if they track current
  libpg_query.
- **libpg_query protobuf output instead of JSON.** Typed and faster, but adds a
  protobuf decoder to the trusted computing base. JSON is simpler to audit. We
  may switch later if parsing cost matters; the AST conversion isolates the
  choice.

## Consequences

- HaltSQL parses with the real Postgres 17 grammar. Running against older
  servers is checked in the lab rather than guaranteed (see the threat model).
- We own a few hundred lines of C, which must be fuzzed and reviewed with
  the same care as the analyzer.
- Building from source needs a C compiler and make, which are present on
  standard CI runners and in the Alpine builder.
- Static Linux binaries are straightforward (musl, no shared libffi).
- libpg_query upgrades are deliberate events with full corpus runs.

## Follow-up

- Fuzz the C stubs and the JSON-to-AST converter.
- Track libpg_query releases and security fixes.
