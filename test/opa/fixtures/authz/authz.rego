# OPA's own API authorization for the header test: only requests carrying the
# expected bearer token may query (opa run --authentication=token
# --authorization=basic).
package system.authz

import rego.v1

default allow := false

allow if input.identity == "haltsql-identity-test-token"
