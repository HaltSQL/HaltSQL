package haltsql_test

import rego.v1

import data.haltsql

base := {
	"caller": {"name": "analytics-agent", "type": "token"},
	"policy": "saas-analytics",
	"policy_version": "sha256:0000",
	"statement_kind": "select",
	"tables": ["app.orders"],
	"columns": ["app.orders.id", "app.orders.total_cents"],
	"reasons": [],
	"shadow_reasons": [],
	"allowed": true,
	"sql_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"fingerprint": "abc",
	"context_keys": ["tenant_id"],
}

test_plain_select_allowed if {
	haltsql.allow with input as base
	haltsql.decision == {"allow": true, "reasons": []} with input as base
}

test_finance_table_needs_strong_caller if {
	inp := object.union(base, {"tables": ["app.invoices"], "columns": ["app.invoices.amount_cents"]})
	not haltsql.allow with input as inp
	d := haltsql.decision with input as inp
	d.allow == false
	d.reasons == ["table app.invoices needs an mTLS or SSO caller, not token"]
}

test_finance_table_ok_for_oidc if {
	inp := object.union(base, {"caller": {"name": "oidc:corp", "type": "oidc"}, "tables": ["app.invoices"]})
	haltsql.allow with input as inp
}

test_blocked_column if {
	inp := object.union(base, {"columns": ["app.customers.email"], "caller": {"name": "x", "type": "mtls"}})
	d := haltsql.decision with input as inp
	d == {"allow": false, "reasons": ["column app.customers.email is blocked organisation-wide"]}
}

test_write_needs_strong_caller if {
	inp := object.union(base, {"statement_kind": "update"})
	not haltsql.allow with input as inp
}

test_shadow_reasons_deny if {
	inp := object.union(base, {"shadow_reasons": ["E_LIMIT_REQUIRED"]})
	not haltsql.allow with input as inp
}

test_never_allows_what_haltsql_denied if {
	inp := object.union(base, {"allowed": false, "reasons": ["E_TABLE_DENIED"]})
	not haltsql.allow with input as inp
}

test_reasons_are_sorted_and_all_reported if {
	inp := object.union(base, {"statement_kind": "delete", "tables": ["app.invoices"], "columns": ["app.customers.phone"]})
	d := haltsql.decision with input as inp
	d.allow == false
	count(d.reasons) == 3
	d.reasons == sort(d.reasons)
}
