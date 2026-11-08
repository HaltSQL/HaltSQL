# Unit tests for verify_gate.rego with http.send replaced by canned answers
# (OPA's built-in "with" mocking). test/opa/test_opa.ml runs the same policy
# against a real haltsql-server.
package haltsql.gate_test

import rego.v1

import data.haltsql.gate

allowed_answer := {"status_code": 200, "body": {"allowed": true, "reasons": []}}

denied_answer := {"status_code": 200, "body": {
	"allowed": false,
	"reasons": [{"code": "E_TABLE_DENIED", "message": "relation app.secrets is not allowed", "rule": "tables"}],
}}

unauthorized := {"status_code": 401, "body": {"error": {"code": "UNAUTHORIZED"}}}

transport_error := {"status_code": 0, "error": {"code": "eval_http_send_network_error", "message": "connection refused"}}

mock_send(answer) := answer

test_allowed if {
	gate.allow with input as {"sql": "SELECT 1"} with http.send as mock_send(allowed_answer) with opa.runtime as {"env": {"HALTSQL_TOKEN": "t"}}
}

test_denied_with_codes if {
	d := gate.decision with input as {"sql": "SELECT * FROM app.secrets"}
		with http.send as mock_send(denied_answer)
		with opa.runtime as {"env": {"HALTSQL_TOKEN": "t"}}
	d == {"allow": false, "reasons": ["E_TABLE_DENIED"]}
}

test_unauthorized_fails_closed if {
	not gate.allow with input as {"sql": "SELECT 1"} with http.send as mock_send(unauthorized) with opa.runtime as {"env": {"HALTSQL_TOKEN": "t"}}
	d := gate.decision with input as {"sql": "SELECT 1"} with http.send as mock_send(unauthorized) with opa.runtime as {"env": {"HALTSQL_TOKEN": "t"}}
	d.allow == false
}

test_transport_error_fails_closed if {
	not gate.allow with input as {"sql": "SELECT 1"} with http.send as mock_send(transport_error) with opa.runtime as {"env": {"HALTSQL_TOKEN": "t"}}
}
