"""Query generators producing JSONL items ``{id, sql, context, intent, transform}``.

* ``benign``  — realistic analytics queries that SHOULD be allowed
* ``evasion`` — PLAN.md §8.3 transforms applied to benign queries
* ``redteam`` — loader for an externally produced LLM red-team JSONL corpus

Bound tenancy convention: ``$n`` is the n-th key of the policy's
``tenancy.keys`` (saas: ``$1`` = tenant_id; composite: ``$1`` = org_id,
``$2`` = workspace_id; hierarchical: ``$1`` = tenant_ids, compared with
``= ANY($1)``). The generated context has its fields in the same order.
"""
