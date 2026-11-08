# Decisions with deliberately wrong shapes, a slow decision and an input echo,
# for test_opa.ml (loaded next to examples/opa into the real OPA container).
package haltsql_fixtures

import rego.v1

string_result := "yes"

extra_keys := {"allow": true, "why": "x"}

allow_not_bool := {"allow": "true"}

reasons_not_strings := {"allow": false, "reasons": [1]}

no_allow := {"reasons": []}

null_result := null

deny_bool := false

deny_obj := {"allow": false}

# The sorted top-level keys of the input, and whether it carries anything that
# must never leave HaltSQL.
echo := {"allow": false, "reasons": [concat(",", sort([k | some k, _ in input]))]}

leaks if input.sql

leaks if input.context

leaks if input.subject

default leaked := false

leaked if leaks

no_leak := {"allow": leaked == false, "reasons": input.context_keys}

# Takes several seconds: for the timeout test.
slow := count([x | some x in numbers.range(1, 30000000)]) > 0
