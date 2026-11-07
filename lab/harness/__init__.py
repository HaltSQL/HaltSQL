"""haltlab harness: scenario runner, oracles and reports (PLAN.md §8.2–8.4).

Why Python here when HaltSQL itself is OCaml: the lab is glue around a live
Postgres (psycopg 3 gives us COPY, server-side ``$n`` parameters, SQLSTATEs
and simple-protocol multi-statement execution with no C stubs), Docker and a
subprocess. Iteration speed matters more than raw speed in the harness, and
keeping it out of the OCaml build means the verifier under test and the
judge share no code. The contract with HaltSQL is only the CLI:
``haltsql verify --policy FILE --batch`` (JSONL in, JSONL verdicts out).
"""
