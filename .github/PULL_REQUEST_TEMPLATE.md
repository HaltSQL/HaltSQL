## Summary

<!-- What does this change do, and why? Link issues with "Fixes #123". -->

## Type of change

- [ ] Bug fix
- [ ] Security fix (bypass or fail-open). Coordinate privately first; see SECURITY.md.
- [ ] New feature
- [ ] Change to a stable contract (policy schema, verdict JSON, reason codes, HTTP API, CLI)
- [ ] Documentation, CI, or tooling only

## Checklist

- [ ] Tests added or updated, with both allowed and denied cases where behavior changed
- [ ] Attack-corpus case added in `test/corpus/` for any security fix
- [ ] The analyzer still fails closed: new or unknown constructs are denied, no wildcard match arms in rule code
- [ ] Docs updated (`docs/`), including `docs/reason-codes.md` for any new reason code
- [ ] ADR added in `docs/adr/` for contract or design changes
- [ ] `CHANGELOG.md` updated under **Unreleased**
- [ ] `make fmt build test` passes locally
- [ ] All commits are signed off (`git commit -s`) per the DCO

## Notes for reviewers

<!-- Anything that needs special attention: risky areas, follow-ups, benchmarks. -->
