# ADR-0002: Convert to a typed AST and fail closed on anything unmapped

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Arnav Dadarya
- **Related:** PLAN.md §4, §6.1; ADR-0001

## Context

libpg_query produces a parse tree with roughly 250 node types. A rule engine
that walks that raw tree generically (for example, "find all `RangeVar` nodes")
is easy to write but easy to fool: a node type the author did not think about
can carry a table reference, a function call, or a subquery that the rules
never inspect. Every such gap is a potential bypass, and new Postgres releases
add node types.

## Decision

- HaltSQL converts the parse tree into its own **typed AST**
  (`lib/core/ast.ml`) that covers exactly the subset of SQL it understands.
- Anything the converter does not map precisely becomes an explicit
  `Unsupported`, `Unsupported_from`, or `Other` constructor carrying the
  original node name. The converter never silently drops a node.
- The analyzer **denies every unsupported node** (`E_UNSUPPORTED`) and every
  statement kind outside the policy (`E_STATEMENT_KIND`).
- Rule code matches AST constructors **exhaustively, without wildcard
  (`_ ->`) arms**, so adding a constructor causes compile errors in every rule
  that must consider it.
- `Haltsql.verify` is **total**: every exception is caught and becomes an
  `E_INTERNAL` denial. Parse errors (`E_PARSE`), empty input (`E_EMPTY`), and
  limit breaches (`E_LIMIT`) are denials, never exceptions.
- Limits on input bytes, tree depth, and node count are enforced before or
  during conversion.

## Alternatives considered

- **Walk the raw JSON tree with generic traversal.** Fast to build, but unknown
  nodes are silently ignored. Rejected.
- **Generate the full typed AST from libpg_query's `srcdata` definitions.**
  Complete coverage and mechanical upgrades, but a much larger surface to
  analyze, most of it irrelevant for agent queries. A curated subset with
  explicit `Unsupported` is easier to reason about and audit. We may generate
  types later, keeping the fail-closed rule.
- **Best-effort analysis with warnings for unknown nodes.** Turns unknowns into
  allows. Rejected: the goal is deny by default.

## Consequences

- Some valid, safe SQL is denied until the AST and rules support it. This is a
  false positive, which is visible and fixable; the alternative is a silent
  false negative.
- Supporting a new construct is an explicit change: AST constructor, converter,
  rules, tests, and docs.
- Postgres upgrades that add syntax produce `E_UNSUPPORTED` rather than
  bypasses.
- `E_INTERNAL` must be alerted on: it indicates a bug, even though it is safe.

## Follow-up

- Track `E_UNSUPPORTED` frequency on benign corpora to prioritize support.
- Fuzz the converter to ensure no input raises past `verify`.
