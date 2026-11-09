# Identity providers

`haltsql-server` accepts OIDC access tokens (JWTs) from any provider that
publishes an OpenID Connect discovery document and a JWKS. The token decides
which policy the caller gets and which tenant the verdict is bound to, so an
agent cannot widen its own access by changing the request. This page gives a
setup recipe per provider; the full rules are in
[authentication.md](../authentication.md#oidc--jwt-bearer-tokens).

Providers covered:

- [Generic OIDC](#generic-oidc) (the building blocks every recipe uses)
- [Keycloak](#keycloak)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Okta](#okta)
- [Auth0](#auth0)
- [Testing with a real token](#testing-with-a-real-token)

**What is tested.** HaltSQL's OIDC support is generic: nothing in it is
specific to one vendor.

| Provider | How it is tested |
|---|---|
| Keycloak 26.4.2 | End to end against a real Keycloak: discovery, JWKS fetch, real tokens from the password and client-credentials grants, groups mapped to policies, the tenant from a token claim, and the allowed queries run in PostgreSQL ([`test/e2e/test_identity.py`](../../test/e2e/test_identity.py), [`test/auth/test_keycloak.ml`](../../test/auth/test_keycloak.ml)). |
| Microsoft Entra ID, Okta, Auth0 | Their token shapes (groups claims, Entra ID overage markers, Auth0 namespaced claims, Entra object ids) are covered by unit tests ([`test/auth/test_groups.ml`](../../test/auth/test_groups.ml)). They are not tested against the live services. |
| Any other OIDC provider | Generic OIDC. It works if the provider issues signed JWT access tokens with the checks below. |

Provider console steps on this page are kept high-level, because consoles
change; follow the provider's own documentation for them. The HaltSQL
configuration is exact.

## Generic OIDC

Every recipe is a `server.auth.oidc` entry:

```yaml
server:
  auth:
    oidc:
      - name: corp-idp                       # appears in logs and audit records as oidc:corp-idp
        issuer: https://idp.corp.example/    # must equal the token's iss exactly
        audiences: [haltsql]                 # the token's aud must contain one of these
        algorithms: [RS256]                  # default [RS256, ES256]
        # jwks_uri: discovered from <issuer>/.well-known/openid-configuration
        policy_from_groups:                  # or: policy, or policy_claim + allowed_policies
          claim: groups
          map:
            - { group: haltsql-support, policy: support-bot }
            - { group: haltsql-analysts, policy: saas-analytics }
        context_claims:
          tenant_id: tenant                  # context field <- claim path
```

What you need from the provider:

| Setting | Where it comes from |
|---|---|
| `issuer` | The `issuer` value of the provider's discovery document, character for character (including any trailing `/`). HaltSQL fetches `<issuer>/.well-known/openid-configuration` and refuses a document whose `issuer` differs. |
| `audiences` | The audience your provider puts in `aud` for tokens meant for HaltSQL (an API identifier, a client id, or a custom audience). |
| `jwks_uri` | Normally discovered. Set it only when discovery is not available; it must be `https` and must not point to a loopback host unless the issuer does. |
| `algorithms` | The signing algorithm of the provider's keys. HMAC (`HS*`) and `none` are always rejected, so a provider must sign with an asymmetric key (`RS256`, `RS384`, `RS512`, `PS256`, `ES256`, `ES384` or `EdDSA`). |

**Choosing the policy.** Exactly one of:

- `policy: NAME`: every token from this provider gets one policy. Use it when
  the provider entry serves one agent; pin the agent with `required_claims`
  (for example its client id).
- `policy_claim` + `allowed_policies`: a string claim names the policy, and
  only policies in the allowlist can be selected.
- `policy_from_groups`: the first `map` entry whose `group` the token has
  wins, in the order written, so put the most privileged groups first.
  Groups are compared exactly (case-sensitive). Without `default`, a token
  that matches no entry is rejected (`no_group_policy`), and so is a token
  without the claim (`missing_claim`). See
  [Policies from IdP groups](../authentication.md#policies-from-idp-groups).

**Tenant from claims.** `context_claims` maps a context field (the one your
policy reads as `${ctx.tenant_id}`) to a claim. The path is tried first as
one claim name, so `https://corp.example/tenant` works, then as a dot path
through nested objects (`org.id`). The claim must exist, and must be a
string, an integral number, or a non-empty array of those; otherwise the
token is rejected. A request body cannot override these fields: a body field
not listed in `request_context_fields` is refused with
`403 CONTEXT_NOT_ALLOWED`.

**Restricting tokens further.** `required_claims` checks claims by value: a
string must equal the claim, or be an element of an array claim, or a word
of a space-separated claim such as `scope`; a list requires every value.

**Key rotation and outages.** Keys are cached for `jwks_cache_seconds`
(default 300). A token with an unknown `kid` triggers at most one refresh
every 30 seconds, so key rotation needs no restart. If the provider is
unreachable, cached keys stay usable for at most
`min(jwks_cache_seconds, 3600)` seconds past their expiry; after that, its
tokens get `503 AUTH_UNAVAILABLE` until it is reachable again. See
[Key fetching and caching](../authentication.md#key-fetching-and-caching).

**Network.** The server needs outbound HTTPS to the issuer's discovery
document and JWKS. Responses are limited to 1 MiB and 5 seconds, and
redirects are not followed.

## Keycloak

Tested end to end with Keycloak 26.4.2.

**In Keycloak** (see the Keycloak Server Administration Guide for the exact
screens):

1. In the realm, create a client for the agent (for example
   `haltsql-agent`). For an agent that runs as itself, enable client
   authentication and service accounts (client-credentials grant).
2. Add an **Audience** mapper to the client with the included custom
   audience `haltsql`, added to the access token. Without it, Keycloak's
   access tokens do not carry the audience HaltSQL expects.
3. Add a **Group Membership** mapper with token claim name `groups`, *Full
   group path* off (so groups are `support`, not `/support`), added to the
   access token.
4. For the tenant, add a **User Attribute** mapper from the user attribute
   `tenant` to the claim `haltsql.tenant`, type String, added to the access
   token. Keycloak turns the dot into a nested object:
   `{"haltsql": {"tenant": "acme"}}`.
5. Put users (or the client's service-account user) into the groups.

**HaltSQL config.** This is the configuration the end-to-end test runs, with
`https` instead of the test's local `http` issuer:

```yaml
server:
  auth:
    oidc:
      - name: keycloak
        issuer: https://sso.corp.example/realms/corp
        audiences: [haltsql]
        algorithms: [RS256]
        policy_from_groups:
          claim: groups
          map:
            - { group: support, policy: support-bot }
            - { group: finance, policy: finance-analyst }
        context_claims: { tenant_id: haltsql.tenant }
```

The issuer is `https://<host>/realms/<realm>` (older Keycloak versions add
`/auth` before `/realms`; copy the value from the realm's discovery
document).

**Roles instead of groups.** Realm roles are in `realm_access.roles` and
client roles in `resource_access.<client>.roles`, both in the access token
by default. Use either as the claim:

```yaml
        policy_from_groups:
          claim: realm_access.roles
          map:
            - { group: haltsql-support, policy: support-bot }
```

**Pitfalls.**

- **No groups, no claim.** Keycloak leaves `groups` out for a user in no
  group. HaltSQL rejects that token with `missing_claim` (unless you set a
  `default`), which is the safe result, but it looks like a configuration
  error when you test with a fresh user.
- **A user without the tenant attribute** gets a token without
  `haltsql.tenant`; the token is rejected, so the user cannot query
  unscoped.
- **`allow_insecure_http: true`** is only for local tests against a Keycloak
  in dev mode. Do not use it in production.

## Microsoft Entra ID

Generic OIDC; token shapes are unit tested. A complete worked example, with
the `az` commands for the app registration and app roles, is in
[Entra ID as the OIDC issuer](../deploy-azure.md#entra-id-as-the-oidc-issuer).

**In Entra ID:**

1. Register an application for HaltSQL (the API agents call) and set its
   access token version to 2 (`api.requestedAccessTokenVersion = 2` in the
   manifest).
2. Define app roles for the kinds of caller (for example `SQL.Verify`, or one
   role per policy), and assign them to the agents' identities or to users and
   groups.
3. Optionally, require assignment so that only identities with a role can get
   a token.

**HaltSQL config: one policy per app role.** App roles arrive in the `roles`
claim, are scoped to the application and never overflow:

```yaml
server:
  auth:
    oidc:
      - name: entra
        issuer: https://login.microsoftonline.com/<TENANT_ID>/v2.0
        audiences: [<HALTSQL_APP_CLIENT_ID>]
        algorithms: [RS256]
        policy_from_groups:
          claim: roles
          map:
            - { group: HaltSQL.Support, policy: support-bot }
            - { group: HaltSQL.Analyst, policy: saas-analytics }
```

**HaltSQL config: one pinned agent identity.** For an agent that calls with
its managed identity or service principal, pin the identity with `azp`:

```yaml
      - name: entra-analytics-agent
        issuer: https://login.microsoftonline.com/<TENANT_ID>/v2.0
        audiences: [<HALTSQL_APP_CLIENT_ID>]
        algorithms: [RS256]
        policy: analytics-agent
        required_claims:
          azp: <AGENT_CLIENT_ID>
          roles: SQL.Verify
        request_context_fields: [tenant_id]
```

Several entries can share an issuer; HaltSQL tries them in order and uses
the first one that verifies the token.

**Groups and overage.** You can map security groups instead of app roles
with `claim: groups`. The values are group **object ids**, not names:

```yaml
        policy_from_groups:
          claim: groups
          map:
            - { group: 8b0e5a9c-1c1f-4c55-9d2a-5f1f3c0f2a11, policy: admin-readonly }
```

When a user is in more groups than fit in the token (200 for JWTs), Entra ID
leaves `groups` out and adds `_claim_names`/`_claim_sources` pointing at
Microsoft Graph (or `hasgroups: true` for implicit-flow tokens). HaltSQL
never calls Graph, because a partial group list could select the wrong
policy: it rejects such a token with `groups_overage`, even if a `groups`
claim is present too. To avoid overage, set `groupMembershipClaims` to
`ApplicationGroup` and assign only the relevant groups to the enterprise
application, or use app roles.

**Pitfalls.**

- **v1.0 tokens.** Without access token version 2, Entra ID issues tokens
  whose `iss` is `https://sts.windows.net/<tenant>/`, and they are rejected
  because `iss` must equal `issuer` exactly. If you must accept v1.0 tokens,
  configure that issuer in a separate entry, with the App ID URI as the
  audience and
  `jwks_uri: https://login.microsoftonline.com/<tenant>/discovery/keys`;
  do not mix the two.
- **`tid` is not your tenant.** The `tid` claim is the Entra directory, not
  the customer tenant your tables are keyed by. App-only tokens carry no
  customer tenant at all: list `tenant_id` in `request_context_fields`, or use
  one identity per tenant.
- **`policy_claim` does not work with `roles`.** `policy_claim` needs a
  string claim and `roles` is an array; use `policy_from_groups` with
  `claim: roles`.

## Okta

Generic OIDC; token shapes are unit tested.

**In Okta:**

1. Use a custom authorization server (for example the one named `default`).
   Its issuer looks like `https://corp.okta.com/oauth2/default`; its
   *Audience* setting is the `aud` of its access tokens.
2. Add a `groups` claim to the access token, with a filter (for example
   "starts with `haltsql-`") so the claim stays small.
3. For the tenant, add a custom claim from a user profile attribute (for
   example `tenant` from `user.tenant`).

**HaltSQL config:**

```yaml
server:
  auth:
    oidc:
      - name: corp-okta
        issuer: https://corp.okta.com/oauth2/default
        audiences: [api://haltsql]
        algorithms: [RS256]
        policy_from_groups:
          claim: groups
          map:
            - { group: haltsql-admins, policy: admin-readonly }
            - { group: haltsql-support, policy: support-bot }
        context_claims: { tenant_id: tenant }
        required_claims: { scp: sql.verify }
```

`required_claims: {scp: sql.verify}` only accepts tokens that were granted
that scope; `scp` is an array in Okta access tokens, and the value must be
one of its elements.

**Machine-to-machine tokens.** Client-credentials tokens describe the
application, not a user, so they carry no user groups. Give each agent
application its own provider entry with a pinned `policy` and
`required_claims` on its client id (Okta access tokens carry it in `cid`),
for example `required_claims: {cid: <AGENT_CLIENT_ID>}`.

**Pitfalls.**

- **Use the custom authorization server's issuer**, exactly as its discovery
  document reports it. Tokens from a different authorization server have a
  different `iss` and are not verified by this entry.
- **An unfiltered groups claim** can be large; HaltSQL rejects tokens over
  16 KiB as malformed.

## Auth0

Generic OIDC; token shapes are unit tested.

**In Auth0:**

1. Create an API for HaltSQL. Its *Identifier* is the audience. Use the
   RS256 signing algorithm: HS256 tokens are always rejected.
2. Add custom claims from an Action. Auth0 requires namespaced names for
   custom claims, for example `https://corp.example/groups` and
   `https://corp.example/tenant`. In a post-login Action:

   ```js
   exports.onExecutePostLogin = async (event, api) => {
     api.accessToken.setCustomClaim('https://corp.example/groups', event.authorization?.roles ?? []);
     api.accessToken.setCustomClaim('https://corp.example/tenant', event.user.app_metadata.tenant);
   };
   ```

**HaltSQL config:**

```yaml
server:
  auth:
    oidc:
      - name: auth0
        issuer: https://corp.eu.auth0.com/        # Auth0 issuers end in "/"
        audiences: [https://haltsql.corp.example]
        algorithms: [RS256]
        policy_from_groups:
          claim: https://corp.example/groups
          map:
            - { group: admins, policy: admin-readonly }
            - { group: support, policy: support-bot }
        context_claims: { tenant_id: https://corp.example/tenant }
```

Namespaced claim names contain dots and slashes. HaltSQL looks a path up as
one claim name first, so `https://corp.example/groups` is read as written,
not as a dot path.

**Pitfalls.**

- **The trailing slash.** Auth0's `iss` ends in `/`. Configure `issuer` with
  the slash, or every token fails `wrong_issuer`. (HaltSQL removes the slash
  only to build the discovery URL.)
- **Missing tenant metadata.** If a user has no tenant, the Action sets an
  empty claim or none, and the token is rejected. That is the safe result;
  fix the user's metadata.
- **Machine-to-machine tokens** do not run post-login Actions. Use a pinned
  `policy` per application, or set the claims in a credentials-exchange
  Action.

## Testing with a real token

Do this once per provider before agents depend on it.

1. **Get a token** the way the agent will. For a Keycloak client with a
   service account:

   ```sh
   TOKEN=$(curl -s https://sso.corp.example/realms/corp/protocol/openid-connect/token \
     -d grant_type=client_credentials -d client_id=haltsql-agent \
     -d client_secret="$CLIENT_SECRET" | jq -r .access_token)
   ```

   Other providers have an equivalent token endpoint; see their docs.

2. **Read its claims** and compare them with your config (`iss`, `aud`,
   `exp`, the groups claim, the tenant claim):

   ```sh
   python3 -c 'import base64,json,sys; p=sys.argv[1].split(".")[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))),indent=2))' "$TOKEN"
   ```

3. **Ask HaltSQL which policy the token selects.** `GET /v1/policies`
   returns only the caller's pinned policy:

   ```sh
   curl -s -H "Authorization: Bearer $TOKEN" https://haltsql.internal:8443/v1/policies
   # {"policies":[{"name":"support-bot","version":"sha256:...","mode":"enforce"}]}
   ```

4. **Verify a query** and check that `bind_params` carries the tenant from
   the token:

   ```sh
   curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     https://haltsql.internal:8443/v1/verify \
     -d '{"sql":"SELECT id, subject FROM app.tickets WHERE tenant_id = $1 LIMIT 10"}'
   ```

5. **Check the negative cases.** A body `context` with another tenant must
   get `403 CONTEXT_NOT_ALLOWED`; a token from a user in no mapped group must
   get `401`.

When a token is rejected, the response says why, and the server logs
`oidc token rejected` at `info` with a stable `reason` field: `expired`,
`wrong_issuer`, `wrong_audience`, `bad_signature`, `unknown_kid`,
`alg_not_allowed`, `missing_claim`, `claim_mismatch`, `bad_claim`,
`groups_overage`, `no_group_policy` and others. JWKS fetch failures are
logged at `warn` as `oidc signing keys unavailable`. The metric
`haltsql_auth_total{method="oidc",result="ok|rejected|unavailable"}` counts
the outcomes. Audit records of OIDC callers have `caller: "oidc:<name>"`,
`caller_type: "oidc"` and the token's `sub` as `subject`; the token itself
is never logged.

## Related

- [Authentication and TLS](../authentication.md): the request pipeline, all
  checks, mTLS and static tokens.
- [Config reference: server.auth.oidc](../config-reference.md#serverauthoidc)
  and [policy_from_groups](../config-reference.md#policy_from_groups).
- [Tenancy](../tenancy.md): how `${ctx.*}` values bind tenant predicates.
- [HTTP API](../http-api.md): `/v1/verify`, `/v1/policies` and error codes.
- [Deploying on Azure](../deploy-azure.md#entra-id-as-the-oidc-issuer).
