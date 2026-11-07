# Signed policy bundles

A policy bundle packages validated policies (and, optionally, catalog snapshots)
into one file that a HaltSQL server can trust without trusting the file system
or the delivery channel it came through. CI builds and signs the bundle once.
Every server verifies the signature before it reads a single policy.

```
policies/*.yaml ──haltsql bundle build──▶ prod.haltsqlbundle ──haltsql bundle sign──▶ prod.haltsqlbundle.sig
                                                   │                                     │
                                                   └──────────── copy, OCI, S3, ... ─────┘
                                                                        ▼
                            haltsql-server: verify signature ▶ digest ▶ structure ▶ compile policies
```

## Quick start

```sh
# once: create a signing key pair (keep the private key in a secret store)
haltsql bundle keygen -o policy-signing.key          # writes policy-signing.key (0600) + .pub

# in CI: build, sign, verify
haltsql bundle build policies/*.yaml --catalog catalog/saas.snapshot.json \
    --name prod-policies --bundle-version 1.4.0 \
    --source-url https://github.com/acme/policies --source-commit "$GITHUB_SHA" \
    -o dist/prod.haltsqlbundle
haltsql bundle sign dist/prod.haltsqlbundle --key policy-signing.key
haltsql bundle verify dist/prod.haltsqlbundle --public-key policy-signing.key.pub

# anywhere: look inside (add --public-key to also check the signature)
haltsql bundle inspect dist/prod.haltsqlbundle
```

The server loads the bundle from its config:

```yaml
policies:
  - bundle: /etc/haltsql/bundles/prod.haltsqlbundle   # signature: prod.haltsqlbundle.sig
    public_keys:
      - /etc/haltsql/keys/policy-signing.pub
    name_prefix: prod.                               # optional
```

See [config-reference.md](config-reference.md#policies) for the config keys.

## Commands

| Command | What it does | Exit codes |
|---|---|---|
| `haltsql bundle keygen -o FILE [--force]` | Writes an Ed25519 private key to `FILE` (PKCS#8 PEM, mode 0600, never overwritten without `--force`) and the public key to `FILE.pub`. Prints the key id. | 0, 2 |
| `haltsql bundle build POLICY... --name N --bundle-version V -o OUT [--catalog [NAME=]FILE]... [--created-by T] [--source-url U] [--source-commit SHA]` | Loads and validates every policy and catalog, then writes the canonical bundle. | 0, 2 |
| `haltsql bundle sign BUNDLE (--key FILE \| --key-env VAR) [--signature FILE] [--append]` | Validates the bundle (it refuses to sign one that does not load), then writes `BUNDLE.sig`. With `--append` the new signature is added next to the existing ones. | 0, 1, 2 |
| `haltsql bundle verify BUNDLE --public-key KEY... [--signature FILE] [--name-prefix P]` | Full verification, the same checks the server runs. | 0, 1, 2 |
| `haltsql bundle inspect BUNDLE [--public-key KEY...]` | Shows metadata, digest, policies (name, version, mode, tables), catalogs and signer key ids. Without keys it does **not** check the signature and says `UNVERIFIED`. | 0, 1, 2 |

The exit codes follow the CLI conventions. 0 means success. 1 means a bundle or
signature failed verification or validation (verify fails with 1 on any such
problem, including a missing bundle). 2 means a usage error or an input that
cannot be loaded, such as a missing policy file or an unreadable or
group-readable private key. Every command accepts `--json`.

`--public-key` takes a PEM file or the base64 of the 32 raw key bytes. `--key`
refuses a private key file that group or others can read (`chmod 600`).
`--key-env VAR` reads the PEM key from an environment variable, which suits CI
secrets. Keys made with `openssl genpkey -algorithm ed25519` work too.

## File format

### Bundle (`*.haltsqlbundle`)

A bundle is one JSON document in **canonical form**. Object members are sorted
by key in byte order. There is no insignificant whitespace, and the document
ends with exactly one newline. Floats, out-of-range integers, duplicate keys
and alternative string escapes are not allowed. Any other encoding of the same
JSON is rejected, so a given bundle has exactly one valid byte sequence.

```json
{"apiVersion":"haltsql.dev/v1",
 "catalogs":{"saas":{"tables":{...}}},
 "digest":"sha256:50f7bf7a...",
 "kind":"PolicyBundle",
 "metadata":{"created_by":"haltsql/0.2.0","name":"prod-policies",
             "source":{"commit":"4f0c2a91...","url":"https://github.com/acme/policies"},
             "version":"1.4.0"},
 "policies":[{"document":{...normalized policy...},"name":"saas-analytics"}]}
```

(The example is wrapped for reading. The real file is a single line.)

| Member | Meaning |
|---|---|
| `apiVersion` | `haltsql.dev/v1` |
| `kind` | `PolicyBundle` |
| `metadata.name` | 1–128 characters: letters, digits, `_ - .`, starting with a letter or digit. |
| `metadata.version` | 1–64 printable characters, no spaces (for example a semver, a date or a CI run number). |
| `metadata.created_by` | Optional; the default is `haltsql/<version>`. |
| `metadata.source.url`, `.commit` | Optional provenance: an http(s) URL and a 7–64 character lower-case hex commit. |
| `policies[]` | 1–1000 entries `{name, document}`. `document` is the normalized policy JSON (the form `Policy.version` hashes, with presets expanded and the catalog inline). `document.metadata.name` must equal `name`. A catalog given as a path is rejected: bundles are self-contained. |
| `catalogs` | Catalog snapshots by name (may be `{}`). |
| `digest` | `sha256:` + hex SHA-256 of the canonical serialization of the document **without** `digest`. |

Builds are deterministic: the same policies, catalogs and metadata always give
byte-identical bundles. There are no timestamps. A policy written in YAML or in
JSON produces the same bundle. Rebuild in CI and compare digests to check that a
deployed bundle matches its source commit.

### Signature (`*.haltsqlbundle.sig`)

A signature file is also canonical JSON. With one signature it looks like this:

```json
{"algorithm":"ed25519","keyid":"sha256:c380011f...","signature":"8pyF25qk...=="}
```

With several signatures (`sign --append`, used while rotating keys) it looks like this:

```json
{"signatures":[{"algorithm":"ed25519","keyid":"sha256:...","signature":"..."},{"algorithm":"ed25519","keyid":"sha256:...","signature":"..."}]}
```

- `keyid` is `sha256:` + the hex SHA-256 of the 32 raw public-key bytes. It is
  only a lookup hint. It never replaces verification.
- `signature` is the base64 of the 64-byte Ed25519 signature (RFC 8032). It is
  computed over the ASCII domain separator `haltsql.dev/v1 PolicyBundle
  signature\n` followed by the **exact bundle bytes**.
- A file holds 1–16 signatures and is at most 64 KiB.

Because the message is plain bytes, you can check a signature with standard tools:

```sh
jq -r .signature prod.haltsqlbundle.sig | base64 -d > sig.bin
{ printf 'haltsql.dev/v1 PolicyBundle signature\n'; cat prod.haltsqlbundle; } > msg.bin
openssl pkeyutl -verify -pubin -inkey policy-signing.key.pub -rawin -in msg.bin -sigfile sig.bin
```

## Verification order (fail closed)

`haltsql bundle verify` and the server's loader (`Haltsql_bundle.load_verified`)
run the same steps, in this order, and stop at the first failure:

1. **Size.** The bundle must be a regular file of at most 16 MiB (configurable
   in the library), and the signature file at most 64 KiB. Reads are bounded,
   so a file that grows while it is read is still rejected.
2. **Signature.** At least one signature must verify against one of the
   trusted keys. Signatures whose `keyid` matches no trusted key are skipped.
   Nothing in the bundle is parsed before this step succeeds.
3. **Canonical form.** The bytes must be the canonical serialization of the
   parsed JSON.
4. **Digest.** The recorded digest must equal the recomputed one.
5. **Structure.** `apiVersion` and `kind` must be correct, and unknown members
   are errors at every level. Names, versions, provenance and limits are all
   checked.
6. **Policies and catalogs.** Each one is compiled with the normal loaders
   (unknown policy keys are errors). The `name_prefix` is applied before
   compiling, so `Policy.version` reflects the final name.

The tests in `test/bundle/` cover each step. They include a flipped payload
byte, a flipped signature bit, a wrong key, a forged key id, truncated bundle
and signature files, unknown members (in the top level, metadata, policy
entries and policy documents), a non-canonical encoding, a digest mismatch,
duplicate keys, oversized files and catalog path references.

## Key management and rotation

- Generate keys with `haltsql bundle keygen` or `openssl genpkey -algorithm ed25519`.
  Store the private key as a CI secret, such as `HALTSQL_SIGNING_KEY` in a
  protected GitHub environment or a masked, protected GitLab variable. Never
  commit it.
- Distribute only the `.pub` file. It is safe to commit (for example
  `keys/policy-signing.pub`) and to bake into server images or ConfigMaps.
- **Rotation:**
  1. Generate the new key and add its public key to every server's
     `public_keys` list next to the old one. Any listed key may verify.
  2. Optionally, while both keys are in use, dual-sign:
     `haltsql bundle sign B --key old.key` and then
     `haltsql bundle sign B --key new.key --append`.
  3. Switch CI to the new key.
  4. Once no bundle signed only by the old key is in circulation, remove the
     old public key from the servers.
- **Compromise:** remove the key from `public_keys` and reload. Bundles signed
  only by that key stop loading at once. The server keeps the last good policy
  set if a reload fails.

## Distribution with OCI registries (optional)

A bundle and its signature are ordinary files, so any artifact store works. To
use an OCI registry, push both files as one artifact with
[oras](https://oras.land):

```sh
oras push ghcr.io/acme/haltsql-policies:1.4.0 \
  --artifact-type application/vnd.haltsql.bundle.v1 \
  prod.haltsqlbundle:application/vnd.haltsql.bundle.v1+json \
  prod.haltsqlbundle.sig:application/vnd.haltsql.bundle.signature.v1+json

# on the server host / in an init container
oras pull ghcr.io/acme/haltsql-policies:1.4.0 -o /etc/haltsql/bundles/
haltsql bundle verify /etc/haltsql/bundles/prod.haltsqlbundle \
  --public-key /etc/haltsql/keys/policy-signing.pub
```

As an optional extra layer, you can also sign the OCI artifact with
[cosign](https://github.com/sigstore/cosign), for example keyless in GitHub
Actions. Registry policies (Kyverno, Sigstore policy-controller) can then
require it:

```sh
cosign sign --yes ghcr.io/acme/haltsql-policies@sha256:<digest>
cosign verify ghcr.io/acme/haltsql-policies@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/acme/policies/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The cosign signature protects the transport and registry. The HaltSQL Ed25519
signature is what the server enforces, and it is required whatever the
transport.

These commands are documentation. HaltSQL does not run oras or cosign itself.

## Library API (for embedding)

```ocaml
(* haltsql.bundle *)
let keys = List.map (fun f -> Result.get_ok (Haltsql_bundle.Key.public_of_file f)) key_files in
match Haltsql_bundle.load_verified ~name_prefix:"prod." "/etc/haltsql/prod.haltsqlbundle" keys with
| Ok policies -> (* Policy.t list, ready for Haltsql.verify *)
| Error e -> prerr_endline (Haltsql_bundle.error_to_string e)  (* refuse to start *)
```

`Haltsql_bundle.load_config_ref` does the same for a `Config.bundle_ref` from
the runtime config. It decodes the entry's `public_keys` and applies its
`name_prefix`. See `lib/bundle/haltsql_bundle.mli`.
