# The reverse direction: OPA asks haltsql-server whether a SQL statement is
# allowed, by calling POST /v1/verify with http.send. Use it when OPA is the
# central decision point (an API gateway, Envoy ext_authz, a custom agent
# runtime) and HaltSQL is one of its inputs.
#
# Query: POST /v1/data/haltsql/gate/decision
#   {"input": {"sql": "...", "context": {"tenant_id": "acme"}}}
#
# Configuration (OPA's data or environment):
#   data.haltsql_gate.server   base URL of haltsql-server (default below)
#   HALTSQL_TOKEN              bearer token of a server.auth.tokens entry
#                              (read with opa.runtime(); never put it in data)
#
# Fail closed: a transport error, a non-200 answer or a malformed verdict
# denies.

package haltsql.gate

import rego.v1

default server := "http://127.0.0.1:8080"

server := data.haltsql_gate.server

token := opa.runtime().env.HALTSQL_TOKEN

verify_body := {"sql": input.sql, "context": object.get(input, "context", {})}

response := http.send({
	"method": "POST",
	"url": concat("", [server, "/v1/verify"]),
	"headers": {
		"authorization": concat(" ", ["Bearer", token]),
		"content-type": "application/json",
	},
	"body": verify_body,
	"timeout": "2s",
	"raise_error": false,
	# Every query must be checked against the current policy.
	"cache": false,
	"force_cache": false,
})

verdict := response.body if response.status_code == 200

default allow := false

allow if verdict.allowed == true

reasons := [r.code | some r in verdict.reasons]

default decision := {"allow": false, "reasons": ["haltsql-server did not return a verdict"]}

decision := {"allow": allow, "reasons": reasons} if verdict
