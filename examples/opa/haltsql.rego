# Organisation rules that HaltSQL's OPA hook evaluates after HaltSQL has
# allowed a query (config: opa.decision_path: haltsql/decision, or
# haltsql/allow for a plain boolean).
#
# The input is verdict metadata only (see docs/opa.md):
#   caller {name, type}, policy, policy_version, statement_kind, tables,
#   columns, reasons, shadow_reasons, allowed, sql_sha256, fingerprint,
#   context_keys
# It never contains the SQL text or context values.
#
# OPA can only further deny: HaltSQL ignores an OPA "allow" for a query it
# denied itself, and asks OPA only about queries it allowed.

package haltsql

import rego.v1

# Tables that only workload identities (mTLS) and SSO users (OIDC) may read.
finance_tables := {"app.invoices"}

# Columns no agent may read, whatever a HaltSQL policy allows (defence in
# depth against a policy that is too broad).
blocked_columns := {"app.customers.email", "app.customers.phone"}

# Callers that authenticate with a static bearer token.
static_caller if input.caller.type in {"token", "anonymous"}

default allow := false

allow if {
	input.allowed
	count(deny_reasons) == 0
}

deny_reasons contains msg if {
	some t in input.tables
	t in finance_tables
	static_caller
	msg := sprintf("table %s needs an mTLS or SSO caller, not %s", [t, input.caller.type])
}

deny_reasons contains msg if {
	some c in input.columns
	c in blocked_columns
	msg := sprintf("column %s is blocked organisation-wide", [c])
}

deny_reasons contains msg if {
	input.statement_kind != "select"
	static_caller
	msg := sprintf("%s statements need an mTLS or SSO caller", [input.statement_kind])
}

deny_reasons contains "the policy is in shadow mode and HaltSQL would have denied this query" if {
	count(input.shadow_reasons) > 0
}

# The decision document for opa.decision_path: haltsql/decision.
decision := {"allow": allow, "reasons": sort(deny_reasons)}
