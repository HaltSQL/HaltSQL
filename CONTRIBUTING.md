# Contributing to HaltSQL

Thanks for helping. HaltSQL is a security control, so we ask for a bit more
rigor than usual: every behavior change comes with tests that show both what is
allowed and what is denied.

**Found a bypass or other vulnerability?** Do not open a public issue. Follow
[SECURITY.md](SECURITY.md).

## Development setup

You need:

- [opam](https://opam.ocaml.org/doc/Install.html) 2.1 or newer
- OCaml 5.x (CI tests 5.2 and 5.4; the minimum is 5.1)
- a C compiler and GNU make, to build the vendored libpg_query
  (`vendor/libpg_query`) and HaltSQL's C stubs (`lib/pgquery`)
  - Debian/Ubuntu: `sudo apt-get install -y build-essential`
  - macOS: `xcode-select --install`
- Docker with Compose v2, only for the enterprise lab (`make lab-up`)

```sh
git clone https://github.com/ardada2468/HaltSQL.git
cd HaltSQL
opam switch create . 5.2.0 --no-install   # local switch in ./_opam
eval $(opam env)
make deps                                  # OCaml deps, test deps, pinned ocamlformat
make build                                 # dune build
make test                                  # dune test
```

Common targets (see the [Makefile](Makefile)):

| Target | What it does |
|---|---|
| `make deps` | Install OCaml dependencies, test dependencies, and `ocamlformat` |
| `make build` | `dune build` |
| `make test` | `dune test` |
| `make fmt` | Format all OCaml and dune files in place |
| `make fmt-check` | Fail if anything is not formatted (CI runs this) |
| `make doc` | Build the API reference with odoc (HTML in `_build/default/_doc/_html/`) |
| `make coverage` | Run tests with bisect_ppx and write an HTML report to `_coverage/` |
| `make bench` | Run benchmarks, if present |
| `make lab-up` / `lab-run` / `lab-down` | Start, run, and stop the enterprise lab (Docker) |
| `make docker` | Build the container image locally |

### Working in a nested checkout

dune uses the outermost directory that contains a `dune-project` (or
`dune-workspace`) as the build root. If your checkout lives inside another dune
project, for example a git worktree under the main clone's `.claude/worktrees/`
or `worktrees/`, dune builds the outer tree instead of yours. Pass `--root .`
and call dune directly (the Makefile targets do not add it):

```sh
dune build --root .
dune test --root .
dune build --root . @fmt
```

## OCaml style and conventions

Reviewers check these. Most of them are ordinary OCaml community practice (the
[OCaml programming guidelines](https://ocaml.org/docs/guidelines), the dune and
odoc docs, and the style used across the opam ecosystem); a few are stricter
because HaltSQL is a security control.

### Interfaces and documentation

- **Every library module with logic has an `.mli`.** The interface is the
  contract: keep helpers out of it, and make a type abstract when callers must
  not build or inspect its values directly. Modules that only declare types,
  and an executable's `main.ml`, may skip it. A module without one gets one the
  next time it changes in a non-trivial way.
- **Document every value and type in an `.mli` with an odoc comment**
  (`(** ... *)`): what it does, what it returns on failure, and whether it can
  raise. Put a short usage example in a library's top-level module comment, as
  in `lib/haltsql/haltsql.mli`. `make doc` (`dune build @doc`) must build
  without warnings.
- Name things the usual way: `snake_case` values and types, `Capitalized`
  modules and constructors, `t` for a module's main type, `of_x` / `to_x` for
  conversions, `_opt` for a function that returns an option, and `_exn` for one
  that raises.

### Errors and failure

- **`Haltsql.verify` never raises.** Every exception inside it becomes an
  `E_INTERNAL` deny. New code on the verify path must keep that property, and
  must deny (`E_UNSUPPORTED`) anything it does not fully understand.
- **Use `result` at boundaries, not exceptions.** Anything that reads files,
  parses untrusted input or talks to the network returns
  `('a, error) result` with a located, human-readable error, as
  `Policy_load.of_file : string -> (Policy.t, Load_error.t list) result` does.
  Exceptions are for broken internal invariants, and are caught at the nearest
  boundary.
- **No partial functions on untrusted input.** SQL text, policy and config
  files, HTTP bodies, wire-protocol messages, JWTs and environment variables are
  all untrusted. Do not call `List.hd`, `List.nth`, `Option.get`,
  `Result.get_ok`, `Hashtbl.find`, `List.assoc`, `int_of_string` or
  `String.sub` / `s.[i]` with an unchecked index on them; use the `_opt`
  variants or match explicitly. `failwith` and `assert false` are for code
  paths that cannot be reached. `Result.get_ok` and friends are fine in tests.
- A catch-all handler (`with _ ->` or `with e ->`) belongs only at a
  fail-closed boundary, and it must deny or fail, never carry on.
- Error messages, logs and metrics never contain secret values, tokens or key
  material. Compare secrets in constant time (`Eqaf.equal`).

### Pattern matching and types

- **No wildcard match arms in analyzer rule code.** Match AST constructors
  explicitly so that a new constructor is a compile error and forces a review.
  Elsewhere, prefer exhaustive matches too.
- Prefer immutable data. Keep mutable state local to a call (the analyzer's
  per-call accumulator in `lib/analyzer/env.ml` is the model). The core
  libraries have no global mutable state, so `verify` is safe to call from
  several domains at once.
- Use labelled arguments when a function takes two or more parameters of the
  same type. An optional argument needs a positional argument after it.
- Do not use `Obj.magic`. Do not use polymorphic comparison (`=`, `compare`,
  `Hashtbl.hash`) on abstract types, functions or cyclic values; use the
  module's own `equal` / `compare`, or `String.equal` and friends.
- Prefer a local open (`Mod.(...)` or `let open Mod in`) or a module alias to a
  top-level `open` of a large module.

### Formatting and warnings

- **ocamlformat 0.29.0** is pinned in `.ocamlformat` (`profile = default`,
  `margin = 90`). Install exactly that version (`make deps` does) and run
  `make fmt` (`dune build @fmt --auto-promote`) before pushing. CI runs
  `dune build @fmt` and fails on any diff.
- **Warnings are errors.** `dune build`, `make build` and CI use dune's default
  `dev` profile, which turns the enabled warnings into errors. Fix the cause
  instead of silencing it. If a local `[@warning "-N"]` is really needed, put it
  on the smallest expression and say why in a comment. Do not add `-w` flags to
  `dune` files to switch warnings off for a whole library. Release builds use
  `--profile release`, which does not fail on warnings, so the CI build is the
  gate.

### Tests

- Unit tests use [alcotest](https://github.com/mirage/alcotest), one directory
  per library under `test/` (for example `test/analyzer/`, `test/load/`).
- Property tests use [QCheck](https://github.com/c-cube/qcheck)
  (`qcheck-core`, run through `qcheck-alcotest`) in `test/property/` and
  `test/load/`.
- Verdict JSON and `explain` output are pinned by golden files in
  `test/golden/`; the attack corpus in `test/corpus/` runs as `kind: TestSuite`
  documents; `test/fuzz/` holds the fuzz harness.
- Every behaviour change has tests for both what is allowed and what is denied.

### Build, test, format and coverage

| Task | Command | Make target |
|---|---|---|
| Build | `dune build` | `make build` |
| Run all tests | `dune test` | `make test` |
| Run one suite | `dune test test/analyzer` | |
| Format in place | `dune build @fmt --auto-promote` | `make fmt` |
| Check formatting | `dune build @fmt` | `make fmt-check` |
| API reference (odoc) | `dune build @doc` | `make doc` |
| Coverage (bisect_ppx) | `dune runtest --instrument-with bisect_ppx --force` | `make coverage` (HTML in `_coverage/`) |

In a [nested checkout](#working-in-a-nested-checkout), add `--root .` to every
`dune` command.

## Making a change

1. For anything bigger than a bug fix, open an issue first so we can agree on
   the approach.
2. If the change touches a stable contract (policy schema, verdict JSON, reason
   codes, HTTP API, CLI flags or exit codes) or makes a significant design
   choice, write an ADR (see below).
3. Write tests:
   - unit tests for the module you changed, with positive and negative cases;
   - an attack-corpus case for any security fix (see below);
   - golden-file updates if the verdict JSON or `explain` output changes.
4. Update the docs in `docs/` and add an entry under **Unreleased** in
   [CHANGELOG.md](CHANGELOG.md).
5. Run `make fmt build test` locally.
6. Open a pull request and fill in the template.

### Rules for analyzer code

- **Fail closed.** If the analyzer does not fully understand a construct, it
  must deny it (`E_UNSUPPORTED`), not ignore it.
- **No wildcard match arms in rule code.** Match AST constructors explicitly
  so that a new constructor causes a compile error and forces a review.
- **Never raise from `verify`.** Exceptions become `E_INTERNAL`.
- **Never rename or reuse a reason code.** New codes can be added in a minor
  release and must be documented in `docs/reason-codes.md`.

## Adding an attack-corpus case

The attack corpus in `test/corpus/` holds known bypass techniques with the
verdict HaltSQL must return. Corpus files use the `kind: TestSuite` format
(see [docs/testing.md](docs/testing.md) and `lib/load/test_suite.mli`). Every
case must pass for a pull request to merge.

1. Pick the file for the attack class (for example tenancy, functions,
   statement smuggling), or create a new suite file that points at a fixture
   policy.
2. Add a case with a descriptive name, the minimal SQL, the expected verdict,
   and the expected reason codes:

   ```yaml
   - name: tenant filter only in outer query does not cover CTE
     sql: >-
       WITH x AS (SELECT id, tenant_id FROM orders)
       SELECT id FROM x WHERE tenant_id = $1 LIMIT 10
     expect: deny
     codes: [E_TENANT_MISSING]
     tags: [tenancy, cte, cve-or-advisory-id-if-any]
   ```

3. Where it helps, add the matching allowed variant too, so the test shows
   exactly what makes the query unsafe.
4. Run `dune test` (or `haltsql test test/corpus/<file>.yaml`) and check that the
   new case fails before your fix and passes after it.

If a case comes from a published technique or another project, credit the
source in a comment.

## Upgrading libpg_query

libpg_query is vendored in `vendor/libpg_query` (currently 17-6.2.5). To
upgrade:

1. Replace `vendor/libpg_query` with the contents of the new release tarball
   from <https://github.com/pganalyze/libpg_query/releases>.
2. Delete its `test/`, `testdata/`, `tmp/`, and `examples/` directories.
3. Check that `vendor/libpg_query/LICENSE` is present and update `NOTICE` if
   the copyright lines changed.
4. Run the full test suite and attack corpus (`make test`), and the lab if the
   Postgres major changed. Review every verdict change.
5. Record the upgrade in `CHANGELOG.md`. A new Postgres major needs an ADR.

## Architecture Decision Records (ADRs)

ADRs live in [docs/adr/](docs/adr/). To propose one:

1. Copy [docs/adr/template.md](docs/adr/template.md) to
   `docs/adr/NNNN-short-title.md`, using the next free number.
2. Set the status to `Proposed` and fill in context, decision, alternatives,
   and consequences.
3. Open a pull request. Discussion happens in the PR. When a maintainer
   approves, change the status to `Accepted` and merge.
4. ADRs are not edited after acceptance except to change their status. To
   change a decision, write a new ADR that supersedes the old one, and mark the
   old one `Superseded by NNNN`.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. Every commit must be signed off:

```sh
git commit -s -m "Describe the change"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line, which certifies
that you wrote the change or otherwise have the right to submit it under the
MIT license. To sign off commits you already made:
`git rebase --signoff main`.

## Commit and pull request style

- One logical change per commit. Keep pure reformatting and file moves in
  their own commits so the real change is easy to review.
- Write the subject in the imperative, prefixed with the area it touches, for
  example `analyzer: deny TABLESAMPLE on tenant tables`, `docs(site): ...` or
  `ci: ...`. Explain *why* in the body.
- Reference issues with `Fixes #123` where relevant.
- Sign off every commit (see [DCO](#developer-certificate-of-origin-dco)).
- Fill in the pull request template. A pull request needs one maintainer
  approval and green CI: formatting, build and tests on Linux and macOS with
  OCaml 5.2 and 5.4, coverage, Postgres integration, the SDK jobs and the
  policy-CI self-test.
- Changes to a stable contract (policy schema, verdict JSON, reason codes,
  HTTP API, CLI flags or exit codes) need an ADR and a `CHANGELOG.md` entry.

## Code of conduct

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
