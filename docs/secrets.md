# Secrets

Configuration values never need to contain secrets. Any string in a Config
document, outside inline policies, may use placeholders:

| Placeholder | Source |
|---|---|
| `${env:NAME}` | environment variable |
| `${file:/path}` | file contents, minus one trailing newline |
| `${vault:<path>#<field>}` | HashiCorp Vault KV v2 |
| `${aws-sm:<secret-id>[#<json-key>]}` | AWS Secrets Manager |
| `${gcp-sm:<name>[#<json-key>]}` | Google Secret Manager |
| `$${` | a literal `${` |

The three provider schemes are configured in the `secrets` section. That
section may itself use only `${env:..}` and `${file:..}`.

```yaml
secrets:
  vault:
    address: https://vault.corp.example:8200
    namespace: platform            # Vault Enterprise, optional
    ca_file: /etc/haltsql/vault-ca.pem
    auth: { method: kubernetes, role: haltsql }
  aws:
    region: eu-west-1
  gcp:
    project: corp-prod
telemetry:
  otlp:
    endpoint: https://otel.corp.example:4318
    headers:
      authorization: "Bearer ${vault:secret/data/haltsql/otel#token}"
audit:
  sinks:
    - type: s3
      bucket: corp-haltsql-audit
      region: eu-west-1
      credentials:
        source: static
        access_key_id: "${aws-sm:prod/haltsql/s3#access_key_id}"
        secret_access_key: "${aws-sm:prod/haltsql/s3#secret_access_key}"
```

## How loading works

The library is `haltsql.cloud`, module `Secrets`. The CLI and the server load
a config in two passes:

1. `Config.secrets_of_file` decodes only the `secrets` section.
2. A resolver is built from it. The resolver finds every provider
   placeholder in the file text and fetches them concurrently. Each distinct
   reference is fetched once per load; Vault logs in at most once per load.
3. `Config.of_file ~resolve` decodes the whole document, taking each
   placeholder's value from the resolver.

A failure is a located load error, for example:

```
haltsql.yaml:12:22: ${vault:secret/haltsql/otel#token}: vault: read secret/haltsql/otel failed: HTTP 403: permission denied
```

The CLI exits with code 2 and the server refuses to start or reload. **Error
messages and logs never contain secret values, tokens or key material.**

A reload (SIGHUP or file watch) builds a fresh resolver, so rotated secrets
are picked up on the next reload.

## Vault

**Reads.** `${vault:<mount>/<path>#<field>}` reads
`GET /v1/<mount>/data/<path>` (KV v2) and returns `data.data.<field>`. If the
path already contains `data` as its second segment, as in
`secret/data/haltsql/otel`, it is used as written. Write mounts that have
several segments in that explicit form, for example
`team/kv/data/app#token`. Numbers and booleans are returned in their JSON
spelling. Objects and arrays are errors.

| `auth.method` | Login |
|---|---|
| `token` | `X-Vault-Token: <token>` (use `${env:VAULT_TOKEN}` or `${file:..}`). |
| `kubernetes` | `POST /v1/auth/<mount>/login` with `{role, jwt}`. The JWT is read from `jwt_path` (default: the pod's service-account token). |
| `approle` | `POST /v1/auth/<mount>/login` with `{role_id, secret_id}`. |

**Tokens.** The login token is reused until 30 s before its lease ends. A
`403` on a read triggers one re-login.

**Headers and TLS.** `namespace` is sent as `X-Vault-Namespace`. `ca_file`
replaces the system trust store; a missing or invalid file fails the load.
Plain `http` is accepted only for loopback addresses, such as a local Vault
agent.

## AWS Secrets Manager

**Call.** `${aws-sm:<secret-id>[#<json-key>]}` calls `GetSecretValue` (JSON
1.1 protocol, SigV4 service `secretsmanager`). The endpoint is
`https://secretsmanager.<region>.amazonaws.com`, or `secrets.aws.endpoint`.

**Value.** The result is `SecretString`, or the decoded `SecretBinary`. With
`#key`, the value is parsed as a JSON object and that key's scalar is
returned.

**Credentials.** These come from the standard chain: environment variables,
then web identity (IRSA), then container credentials (the ECS task role or
EKS Pod Identity), then the EC2 instance profile (IMDSv2). See
[audit-sinks.md](audit-sinks.md#s3) for details. On an expired-credential
error the credentials are refreshed and the call is retried once.

Required IAM permission: `secretsmanager:GetSecretValue` on the secret ARNs
(plus `kms:Decrypt` for customer-managed keys).

## Google Secret Manager

**Names.** `<name>` is one of:

- `projects/P/secrets/S/versions/V`;
- `projects/P/secrets/S` (the latest version);
- a short `S` or `S/versions/V`, in `secrets.gcp.project`.

**Call and value.** The resolver calls `GET /v1/<name>:access` on
`https://secretmanager.googleapis.com`, or `secrets.gcp.endpoint`. It
base64-decodes `payload.data` and verifies `payload.dataCrc32c` (CRC-32C).
With `#key`, the value is parsed as JSON and that key's scalar is returned.

**Credentials.** The service-account key in `GOOGLE_APPLICATION_CREDENTIALS`
when that variable is set; otherwise the metadata server (Workload Identity).
A `401` refreshes the token once.

Required role: `roles/secretmanager.secretAccessor` on the secrets.

## Library use

```ocaml
(* CLI: outside any Lwt loop *)
match Haltsql_cloud.Secrets.load_config_blocking path with
| Ok cfg -> run cfg
| Error errs -> report errs; exit 2

(* Server: inside Lwt (startup or reload) *)
Haltsql_cloud.Secrets.load_config path >>= function
| Ok cfg -> swap cfg
| Error errs -> keep_old_config errs
```

**Lower-level API.**

- `Secrets.create` takes `Config.secrets`.
- `Secrets.prefetch` fetches placeholders concurrently.
- `Secrets.cached_resolver` returns a `Config.resolver` that serves only
  values already fetched, so it is safe inside Lwt.
- `Secrets.blocking_resolver` fetches missing values with `Lwt_main.run`. Use
  it only outside Lwt.
