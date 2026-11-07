# Governance

HaltSQL is a small project with a simple model. This document will grow when
the project does.

## Roles

- **Maintainers** review and merge pull requests, triage issues, handle
  security reports, cut releases, and decide on the roadmap.
  Current maintainers:
  - Arnav Dadarya ([@ardada2468](https://github.com/ardada2468)), lead maintainer
- **Contributors** are anyone who opens an issue, reviews a change, or sends a
  pull request.

## Decisions

- Day-to-day changes are decided in pull requests. A change needs approval
  from one maintainer (see [CODEOWNERS](.github/CODEOWNERS)).
- Changes to a stable contract (policy schema, verdict JSON, reason codes, HTTP
  API, CLI exit codes) and significant design changes need an
  [Architecture Decision Record](docs/adr/) merged first.
- Maintainers aim for consensus. If they cannot reach it, the lead maintainer
  decides and records the reasoning in the pull request or ADR.

## Security-sensitive changes

Changes to the analyzer, tenancy proof, parser bridge, or policy loader must
include tests that show both the allowed and the denied behavior, and any fix
for a bypass must add an attack-corpus case. Security fixes may be prepared in
a private fork and merged without public review before disclosure (see
[SECURITY.md](SECURITY.md)).

## Becoming a maintainer

Contributors with a sustained record of high-quality reviews and changes may be
invited by the existing maintainers. New maintainers are added to this file
and to CODEOWNERS in a pull request.

## Releases

Maintainers tag releases (`vX.Y.Z`). The release workflow builds, signs, and
publishes artifacts. Versions follow [Semantic Versioning](https://semver.org/);
see [CHANGELOG.md](CHANGELOG.md).

## Code of conduct

Everyone follows the [Code of Conduct](CODE_OF_CONDUCT.md).
