# HaltSQL Console: configuration

`haltsql-console --config console.yaml` (or `HALTSQL_CONSOLE_CONFIG`). YAML or
JSON. A complete example is
[deploy/console/console.example.yaml](../../deploy/console/console.example.yaml).
Unknown keys are errors.

**Secrets.** Any string can contain `${env:NAME}`, `${vault:...}`,
`${aws-sm:...}` or `${gcp-sm:...}`. Provider placeholders need a `secrets:`
section with the same shape as the server's ([secrets.md](../secrets.md)).
`$${` writes a literal `${`. Resolved values are never logged or returned by
the API.

When placeholders are resolved depends on the section:

- **At load:** the sections the console reads at startup (`listen`,
  `environment`, `state_dir`, `frontend_dir`, `auth`, `verifiers`, `fleet`,
  `audit`, `policies`, `catalogs`, `data`, `agents`). A placeholder that cannot
  be resolved is a startup error.
- **On demand:** `opa`, `integrations` and `signals`. At load each placeholder
  is only checked: valid syntax, a known scheme, the provider configured in
  `secrets:`, and for `${env:...}` the variable set. Errors stop startup. The
  value is fetched only when a feature needs it (for example when it posts to
  Slack). Provider values are cached for at most 5 minutes, so a rotated secret
  is picked up without a restart, and the console does not keep these secrets
  in memory between uses.

The configuration document the console keeps for feature-specific keys is the
file as written, with its placeholders unresolved.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8090` | `host:port` to serve on. `--listen` overrides. |
| `public_url` | none | The URL browsers use to reach the console, for example `https://console.example.com`: `http` or `https`, a host, an optional port, no path. Its origin is added to `allowed_origins`. |
| `allowed_origins` | `[]` | More browser origins (`scheme://host[:port]`) allowed to send state-changing requests, for example a frontend dev server. See [Origins](#origins). |
| `environment.org`, `.name`, `.region` | `HaltSQL`, `Default`, none | Shown in the environment switcher. |
| `state_dir` | `./console-state` | Durable state (cases, activity log, signal workflow, evidence packs). Must be writable; `/readyz` is 503 otherwise. Put it on a persistent volume. |
| `frontend_dir` | none | Directory with the built web frontend, served at `/`. |

## `auth`

At least one of `oidc`, `proxy`, `tokens`, `dev`. `dev` cannot be combined
with the others.

| Key | Meaning |
|---|---|
| `oidc[]` | `name`, `issuer`, `audience` (or `audiences`), optional `jwks_uri`, `groups_claim` (default `groups`), `group_prefix` (default `<name>:`), `leeway_seconds`, `allow_insecure_http` (tests only). Tokens are verified like the server verifies callers (JWKS, `iss`, `aud`, expiry; RS256, ES256, PS256, EdDSA), and the sign-in must be recent enough for `session_hours`. |
| `proxy` | Trusts identity headers set by an identity-aware proxy. See [`auth.proxy`](#authproxy). |
| `tokens[]` | `name`, `sha256` (hex SHA-256 of the token), `role`. For automation. |
| `dev` | `true`, or `{ user, role }`. The role defaults to `dev`. Every request without credentials is that user. Development only: see [Dev mode](#dev-mode). `--dev ROLE` does the same. |
| `roles` | `{ admin: [groups], owner: [...], analyst: [...], audit: [...], dev: [...] }`. A user gets every role one of their groups maps to, and their permissions are the union of those roles. The most privileged role (`admin`, then `owner`, `audit`, `analyst`, `dev`) is shown as their primary role. A user whose groups map to no role is refused. |
| `session_hours` | 1 to 720, default 8. An OIDC token is refused with `session expired; sign in again` when its `auth_time` claim (or `iat` when there is no `auth_time`) is more than `session_hours` old. A token with neither claim is accepted until it expires, unless `require_auth_time` is set. Not applied to proxy headers or service tokens: set the session length on the proxy. |
| `require_auth_time` | Default `false`. When `true`, an OIDC token without an `auth_time` claim is refused (`session expired; sign in again`), so `session_hours` is measured from the actual sign-in. Check that your provider sets `auth_time` (some only do when the client asks for it, for example with `max_age`). The Access page shows the *Sessions* safeguard as verified only when OIDC is the only auth method and this is `true`. |

### `auth.proxy`

| Key | Meaning |
|---|---|
| `user_header` | Required. Header with the user's id (for example `X-Auth-Request-Email`). |
| `name_header` | Optional display-name header. |
| `groups_header` | Optional header with comma-separated groups. |
| `group_prefix` | Prepended to each proxy group before role mapping. Default `""`. Set it (for example `proxy:`) when OIDC is also configured, so a proxy group can't collide with an OIDC group. |
| `label` | Shown as the auth method, `proxy:<label>`. Default `proxy`. |
| `trusted_proxies` | IPs or CIDRs (IPv4 or IPv6) of the proxy, for example `[10.0.0.0/8, "fd00::/8"]`. The TCP peer of the request must be in one of them. |
| `secret_header`, `secret_sha256` | A header the proxy adds with a shared secret, and the hex SHA-256 of that secret. The header must hash to `secret_sha256`. The comparison is constant-time. |

You must set `trusted_proxies`, the shared secret, or both. When both are
set, both checks must pass. A request that carries `user_header` but fails a
check gets `401` (`proxy identity headers from an untrusted source`). It is
not treated as anonymous. Still make sure the console can only be reached
through the proxy, and that the proxy strips these headers from client
requests.

### Dev mode

`auth.dev` is refused at startup unless:

- it is the only auth method: no `oidc`, `proxy` or `tokens`, and
- `listen` is a loopback address: `127.0.0.0/8`, `::1` (`[::1]:port`) or
  `localhost`. An empty host or `*` means `0.0.0.0`, which is not loopback.

These rules also apply after `--listen` and `--dev` overrides (either one
alone or both), and the server checks them again before it binds. When dev
mode is not configured, a request without credentials is always `401`.

In dev mode, every `/api/` request must also be addressed to a loopback host:
its `Host` header must be `localhost`, an address in `127.0.0.0/8` or `[::1]`
(any port), else `403 HOST_NOT_ALLOWED`. This blocks DNS rebinding, where a
web page on another site resolves its own name to `127.0.0.1` and calls the
console from the browser.

## Origins

State-changing `/api/` requests (anything but `GET`, `HEAD`, `OPTIONS`) are
checked against cross-site request forgery. A request without an `Origin`
header (curl, scripts) passes. A request with one passes when:

- `public_url` or `allowed_origins` is set: the Origin's scheme, host and port
  are one of the configured origins (a missing port is the scheme's default).
  The `Host` header is not used, so this works behind a reverse proxy or load
  balancer that rewrites `Host`.
- neither is set: the Origin names the same host and port as the `Host`
  header. A proxy in front must then pass `Host` through unchanged.

`Sec-Fetch-Site: cross-site` is refused in both cases.

## `verifiers[]`

| Key | Meaning |
|---|---|
| `name` | Unique; matches the `verifier` of audit sources. |
| `url` | Base URL of the verifier's HTTP API. |
| `kind` | `server` (default), `proxy`, `mcp`. |
| `location` | Free text shown in Fleet. |
| `token` | Admin bearer token; the verifier must list it in `server.admin.callers`. |
| `metrics_url` | Default `<url>/metrics`. |
| `workload` | Kubernetes workload to restart, e.g. `deployment/haltsql-1`. |

## `fleet`

<!-- Documented by the fleet PR (console/03-fleet). -->

## `audit`

<!-- Documented by the records PR (console/02-records). -->

## `policies` and `opa`

<!-- Documented by the build PR (console/05-build). -->

## `signals`

<!-- Documented by the signals PR (console/04-signals). -->

## `agents`

<!-- Documented by the build PR (console/05-build). -->

## `catalogs` and `data`

<!-- Documented by the comply PR (console/06-comply). -->

## `integrations`

<!-- Documented by the PRs that use each integration. -->
