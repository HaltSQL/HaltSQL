"""Seeded, deterministic data generator with honeytokens (PLAN.md §8.2).

Data shape is derived from the live catalog (introspection) plus the policy:
tenant columns come from the policy, sensitive columns are the ones present in
the database but not allowed by the policy, foreign keys are honored, and
every text cell carries a marker that identifies its owner:

* ``HT-<tenant-slug>-<table>-<n>``     allowed text columns of tenant tables
* ``HTCOL-<table>-<column>-<n>``       denied columns (and denied tables)

The honeytoken registry maps every marker back to its owner so the harness can
decide whether a marker seen in a result is a leak.
"""
