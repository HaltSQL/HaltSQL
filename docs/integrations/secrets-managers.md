# Secrets managers

`haltsql-server` and the `haltsql` CLI can read secrets in their Config
document straight from HashiCorp Vault, AWS Secrets Manager or Google Secret
Manager, so the file holds only references. This page gives one recipe per
secrets manager: how HaltSQL authenticates, what it needs to be allowed,
the placeholder syntax, and what happens on rotation and failure. The
reference is [secrets.md](../secrets.md).

Secrets managers covered:

- [HashiCorp Vault](#hashicorp-vault) (KV version 2)
- [AWS Secrets Manager](#aws-secrets-manager)
- [Google Secret Manager](#google-secret-manager)
- [Azure Key Vault](#azure-key-vault-not-supported) (not supported; workaround)

## How placeholders work

A placeholder can stand for any string in a `kind: Config` document, for
example an audit sink password, an OTLP header or an S3 key:

| Placeholder | Source |
|---|---|
| `${env:NAME}` | environment variable |
| `${file:/path}` | file contents, minus one trailing newline |
| `${vault:<path>#<field>}` | HashiCorp Vault KV v2 |
| `${aws-sm:<secret-id>[#<json-key>]}` | AWS Secrets Manager |
| `${gcp-sm:<name>[#<json-key>]}` | Google Secret Manager |
| `$${` | a literal `${` |

The `vault`, `aws-sm` and `gcp-sm` providers are configured in the `secrets`
section, which may itself only use `${env:...}` and `${file:...}`.

Behaviour shared by all three providers:

- **When secrets are read.** At startup and on every reload (`SIGHUP`, or a
  watched config or policy file changing). Each load fetches every distinct
  reference once, concurrently, before the rest of the config is decoded.
  There is no background refresh between loads.
- **Rotation.** A rotated secret is picked up on the next reload. HaltSQL
  does not watch the secrets manager, so trigger a reload (or a restart)
  after rotating. Values used by **audit sinks** (for example a Kafka SASL
  password or an Elasticsearch API key) only change on a **restart**,
  because audit sinks are not replaced on reload
  ([reload rules](../config-reference.md#reload)).
- **Failure.** A placeholder that cannot be resolved is a load error that
  names the file position, the reference and the provider's error, never the
  secret. HaltSQL never substitutes an empty string. At startup the server
  exits with code 2; on reload it keeps the last good configuration and
  counts the failure in `haltsql_policy_reload_total{result="error"}`. The
  CLI (`haltsql config show`, `haltsql validate`) exits 2.
- **Timeouts.** Each HTTP request to a secrets manager times out after 10
  seconds.
- **Redaction.** Resolved values are never logged. `haltsql config show`
  prints them as `"<redacted>"`.
- **Where they work.** In `kind: Config` documents read by `haltsql-server`
  and the `haltsql` CLI. Policies never accept placeholders (only
  `${ctx.*}`). `haltsql-proxy` configs accept only `${env:...}` and
  `${file:...}` ([proxy.md](../proxy.md)).

Check a config before deploying it: `haltsql config show --config
haltsql.yaml` resolves every placeholder with the same credentials the
server would use, and prints the result with secrets redacted.

## HashiCorp Vault

**Placeholder.** `${vault:<mount>/<path>#<field>}` reads
`GET /v1/<mount>/data/<path>` and returns `data.data.<field>`. Only KV
version 2 is supported. If the path already has `data` as its second
segment (`secret/data/haltsql/otel#token`), it is used as written; write
mounts with several segments in that explicit form
(`team/kv/data/app#token`). Numbers and booleans come back in their JSON
spelling; objects and arrays are errors.

**Auth methods.**

| `auth.method` | Keys | Login |
|---|---|---|
| `token` | `token` | The token is sent as `X-Vault-Token`. Supply it with `${env:VAULT_TOKEN}` or `${file:...}`. |
| `kubernetes` | `role`; `jwt_path` (default `/var/run/secrets/kubernetes.io/serviceaccount/token`); `mount` (default `kubernetes`) | `POST /v1/auth/<mount>/login` with `{role, jwt}`. |
| `approle` | `role_id`, `secret_id`; `mount` (default `approle`) | `POST /v1/auth/<mount>/login` with `{role_id, secret_id}`. |

Keys that belong to another method are errors. Other Vault auth methods
(AWS, Azure, GCP, JWT/OIDC, ...) are not supported.

**Config (Kubernetes).**

```yaml
secrets:
  vault:
    address: https://vault.corp.example:8200
    namespace: platform                  # Vault Enterprise, optional
    ca_file: /etc/haltsql/vault-ca.pem   # optional; replaces the system trust store
    auth: { method: kubernetes, role: haltsql }
audit:
  sinks:
    - type: elasticsearch
      url: https://es.corp.example:9200
      data_stream: logs-haltsql-prod
      auth: { api_key: "${vault:secret/data/haltsql/es#api_key}" }
```

**Config (AppRole).** The AppRole credentials themselves come from the
environment or a file, never from Vault:

```yaml
secrets:
  vault:
    address: https://vault.corp.example:8200
    auth:
      method: approle
      role_id: "${env:VAULT_ROLE_ID}"
      secret_id: "${file:/var/run/secrets/vault/secret-id}"
```

**Vault policy.** HaltSQL only reads. For the example above:

```hcl
path "secret/data/haltsql/*" {
  capabilities = ["read"]
}
```

Bind it to the auth role (for Kubernetes, a role bound to HaltSQL's service
account and namespace). See Vault's documentation for the
[Kubernetes](https://developer.hashicorp.com/vault/docs/auth/kubernetes) and
[AppRole](https://developer.hashicorp.com/vault/docs/auth/approle) auth
methods.

**Caching and refresh.** Every load (startup or reload) logs in again, at
most once. Within a load the login token is reused until 30 seconds before
its lease ends, and a `403` on a read triggers one re-login.

**Pitfalls.**

- **`address`** must be `https`, or `http` for loopback addresses only (a
  local Vault agent).
- **KV v1 mounts** are not supported: the reader always uses the KV v2
  `data/` path.
- **Short-lived secret ids.** An AppRole `secret_id` with a use limit or
  TTL can be exhausted by reloads. Size it for the number of reloads and
  restarts you expect, or use the Kubernetes method.

## AWS Secrets Manager

**Placeholder.** `${aws-sm:<secret-id>[#<json-key>]}` calls `GetSecretValue`
with the secret's name or ARN. The value is `SecretString`, or the decoded
`SecretBinary`. With `#key`, the value is parsed as a JSON object and that
key's scalar is returned.

```yaml
secrets:
  aws:
    region: eu-west-1
audit:
  sinks:
    - type: kafka
      brokers: [b-1.kafka.corp.example:9096]
      topic: haltsql.audit
      tls: { enabled: true }             # system CA roots
      sasl:
        mechanism: scram-sha-512
        username: haltsql
        password: "${aws-sm:prod/haltsql/kafka#password}"
```

`secrets.aws.region` is required. The endpoint is
`https://secretsmanager.<region>.amazonaws.com`, or `secrets.aws.endpoint`
(for tests).

**Credentials.** HaltSQL uses the first source in this chain that yields
credentials:

1. environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
   optional `AWS_SESSION_TOKEN`);
2. web identity (EKS IRSA): `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`,
   exchanged with STS `AssumeRoleWithWebIdentity`;
3. container credentials (ECS task roles, EKS Pod Identity):
   `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or
   `AWS_CONTAINER_CREDENTIALS_FULL_URI`;
4. the EC2 instance profile, through IMDSv2.

Temporary credentials are cached and refreshed 5 minutes before they expire.
On an expired-credential error, the credentials are refreshed and the call is
retried once.

**IAM policy.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow",
     "Action": "secretsmanager:GetSecretValue",
     "Resource": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/haltsql/*"}
  ]
}
```

Add `kms:Decrypt` on the key when the secrets are encrypted with a
customer-managed KMS key.

**Pitfalls.**

- **Versions and staging labels** cannot be selected: HaltSQL always reads
  the current version (`AWSCURRENT`). Rotate by updating the secret, then
  reload.
- **`#key` needs a JSON object.** A plain-string secret with `#key` is an
  error; use the placeholder without `#key`.
- **Region.** One `secrets.aws.region` serves all `aws-sm` placeholders in
  the file.

## Google Secret Manager

**Placeholder.** `${gcp-sm:<name>[#<json-key>]}`, where `<name>` is one of:

- `projects/P/secrets/S/versions/V`;
- `projects/P/secrets/S` (the latest version);
- `S` or `S/versions/V`, in the project `secrets.gcp.project`.

HaltSQL calls `GET /v1/<name>:access` on
`https://secretmanager.googleapis.com` (or `secrets.gcp.endpoint`, for
tests), base64-decodes the payload and checks its CRC-32C checksum when the
response carries one. With
`#key`, the value is parsed as JSON and that key's scalar is returned.

```yaml
secrets:
  gcp:
    project: corp-prod                  # only needed for short names
telemetry:
  otlp:
    endpoint: https://otel.corp.example:4318
    headers:
      authorization: "Bearer ${gcp-sm:haltsql-otel-token}"
```

The `secrets.gcp` section is optional when every placeholder uses a full
`projects/...` name.

**Credentials.** The service-account key file named by
`GOOGLE_APPLICATION_CREDENTIALS` when that variable is set; otherwise the
metadata server (GKE Workload Identity, Cloud Run, GCE). Tokens from a key
file are requested with the `cloud-platform` scope. A `401` refreshes the
token once.

**IAM.** Grant HaltSQL's service account `roles/secretmanager.secretAccessor`
on each secret (or on the project):

```sh
gcloud secrets add-iam-policy-binding haltsql-otel-token \
  --member="serviceAccount:haltsql@corp-prod.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

**Pitfalls.**

- **Pin versions for reproducible reloads.** `projects/P/secrets/S` and a
  short `S` read the latest version at each load, so a new version reaches
  HaltSQL at the next reload whether or not you meant it to. Name the
  version (`S/versions/3`) if you want rotation to be an explicit config
  change.
- **Name segments** may only contain letters, digits, `_` and `-`.

## Azure Key Vault (not supported)

HaltSQL cannot read Azure Key Vault directly: there is no `${azure-kv:...}`
placeholder, and HaltSQL has no Azure managed-identity credential support.
Use the platform to put Key Vault secrets on disk and read them with
`${file:...}`:

- **AKS:** the Key Vault Secrets Store CSI driver mounts secrets as files.
- **Azure Container Apps:** Key Vault secret references, mounted as files.
- Or HashiCorp Vault with its Azure auth method in front of HaltSQL's Vault
  support.

Remember that `${file:...}` values are read at startup and on reload; a
changed file alone does not trigger a reload. The full pattern, including
token rotation, is in [Deploying on Azure](../deploy-azure.md) (see
[Current limitations on Azure](../deploy-azure.md#current-limitations-on-azure)).

## Related

- [Secrets](../secrets.md): loading order, provider details and the library
  API.
- [Config reference: secrets](../config-reference.md#secrets) and
  [placeholders](../config-reference.md#secrets-placeholders).
- [Config reference: reload](../config-reference.md#reload): what a reload
  applies and what needs a restart.
- [Deploying on AWS](../deploy-aws.md), [Google Cloud](../deploy-gcp.md) and
  [Azure](../deploy-azure.md).
