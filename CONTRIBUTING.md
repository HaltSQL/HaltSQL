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
| `make coverage` | Run tests with bisect_ppx and write an HTML report to `_coverage/` |
| `make bench` | Run benchmarks, if present |
| `make lab-up` / `lab-run` / `lab-down` | Start, run, and stop the enterprise lab (Docker) |
| `make docker` | Build the container image locally |

## Formatting

We use [ocamlformat](https://github.com/ocaml-ppx/ocamlformat) with the version
pinned in `.ocamlformat`. Install that exact version (`make deps` does this)
and run `make fmt` before pushing. CI fails on unformatted code.

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
Apache-2.0 license. To sign off commits you already made:
`git rebase --signoff main`.

## Commit and pull request style

- Keep commits focused; explain *why* in the message body.
- Reference issues with `Fixes #123` where relevant.
- Pull requests need one maintainer approval and green CI.

## Code of conduct

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
