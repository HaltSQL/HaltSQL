# Base OPA policy of the e2e stack (decision_path: haltsql/e2e/decision).
# Tests that need other rules upload their own module under a unique package
# with PUT /v1/policies/<id> (conftest.opa_put_policy) instead of editing this.
#
# OPA can only turn HaltSQL's allow into a deny (reason E_EXTERNAL_POLICY).

package haltsql.e2e

import rego.v1

blocked_tables := {"app.payroll"}

default allow := false

allow if {
	input.allowed
	count(deny_reasons) == 0
}

deny_reasons contains msg if {
	some t in input.tables
	t in blocked_tables
	msg := sprintf("table %s is blocked by the e2e OPA policy", [t])
}

decision := {"allow": allow, "reasons": sort(deny_reasons)}
