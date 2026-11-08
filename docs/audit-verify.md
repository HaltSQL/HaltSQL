# Verifying audit chains

`haltsql audit verify` checks the hash chain of HaltSQL audit records: the
file and stdout sinks of `haltsql-server` and `haltsql-proxy`, logs that mix
audit records with other lines, and the objects written by the S3 and GCS
sinks, either downloaded to a directory or read straight from S3 (or an
S3-compatible store such as MinIO).

```bash
haltsql audit verify /var/log/haltsql/audit.jsonl
# /var/log/haltsql/audit.jsonl: OK, 18234 records, 1 chain
#   head /var/log/haltsql/audit.jsonl: 9f2c...
```

## What is checked

Every record is one JSON line ending in `"prev_hash":"<64 hex>","hash":"<64 hex>"`,
where `hash = sha256_hex(prev_hash ^ L)` and `L` is the compact JSON of the
record without its `hash` member (see [audit-sinks.md](audit-sinks.md)). For
each input the command checks:

- **Record hashes.** Each record's content matches its `hash`. An edited
  field is reported at its line (`bad_hash`).
- **Links.** Each record's `prev_hash` is the previous record's `hash`. A
  deleted, inserted or rewritten record breaks the next link
  (`broken_link`). When a record links to an earlier record instead, the
  message says the records were reordered and points to that record. An exact
  copy of an earlier record is reported as `duplicate_record`. With
  `--allow-redelivery` (exports of at-least-once sinks such as Kafka, where a
  retried produce request can store a whole batch twice) such copies are
  warnings and skipped; a copy whose content does not match its hash is still
  `bad_hash`.
- **Start.** The first record must link to genesis (64 zeros), unless
  `--any-start` or `--initial-prev HASH` is given (`mid_chain_start`,
  `start_mismatch`).
- **Restarts.** A record whose `prev_hash` is genesis in the middle of a
  stream starts a new chain (a stdout sink after a restart, for example). This
  is a warning (`chain_restart`), and an error with `--strict`.
- **Truncation.** An incomplete last line (`truncated`). Whole lines missing
  at the end cannot be seen in the records themselves: compare against a head
  you recorded elsewhere with `--expect-head HASH` (`head_mismatch`), or, for
  object sinks, against the spool (`--spool`).
- **Malformed lines.** Lines that are not JSON, or JSON without valid
  `prev_hash`/`hash` (`invalid_record`). JSON objects without either field
  are log lines (`not_audit_record`); `--mixed` skips them, along with any
  non-JSON line and container log prefixes before the `{`.

Messages never quote record contents (records may carry SQL).

## Object-sink outputs

Point the command at a directory of downloaded objects (searched
recursively, symlinks are not followed), or at `s3://BUCKET/PREFIX`. Objects
are named `<prefix>YYYY/MM/DD/HH/<host>-<run>-<seq>-<sha256>.jsonl`. Every
`.jsonl` file under the directory must have such a name
(`unrecognized_name`); other files are ignored.

| Check | Problem |
|---|---|
| The body's SHA-256 equals the one in the name | `body_mismatch` (modified or truncated object) |
| Every body ends with a newline and holds at least one record | `truncated`, `empty_object` |
| The same body is stored only once | `duplicate_object` |
| No two objects claim the same host, run and sequence number | `conflicting_objects` |
| Within a run, sequence numbers have no holes | `seq_gap` |
| Within a run, the objects form one chain in sequence order | `broken_link` (with a reordering diagnosis when an object continues another one) |
| A run starting at genesis starts at sequence 0 | `seq_gap` |
| A run that does not start at genesis continues another run of the same host (spool continuity across restarts), at the next sequence number | `broken_link`, `seq_gap` |
| A run continues a run that started earlier | `run_order` |
| No two runs continue the same run | `fork` |

Each host has its own chains. A run that starts at genesis while the host has
earlier runs is a new chain (a sink without a spool directory restarts its
chain): a warning, or an error with `--strict`. The earliest run of a host
must start at genesis unless `--any-start` or `--initial-prev` is given (for
example when you verify one day of objects).

### Spool head continuity

With `--spool DIR` (the sink's `spool_dir`, for the objects of one host; use
`--host` when the directory holds several), the command also checks:

- the spooled batches that are not uploaded yet (`batch-<seq>.jsonl`) and
  `current.jsonl` continue the chain of the newest run, at the next sequence
  numbers (a spooled batch whose body was already uploaded is skipped);
- `head.json` names the last sealed record: its `seq` is the newest sealed
  sequence number plus one and its `prev` is that record's hash
  (`spool_head_mismatch`). This detects objects deleted from the end of the
  bucket, which the chain alone cannot.

### Reading straight from S3

```bash
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
  haltsql audit verify s3://corp-haltsql-audit/haltsql/audit/2026/11/07/ --any-start

# MinIO or another S3-compatible store (path-style requests)
haltsql audit verify --endpoint http://127.0.0.1:9000 s3://audit/haltsql/audit/
```

The command lists the prefix with `ListObjectsV2` (all pages) and downloads
every `.jsonl` object with SigV4-signed `GET` requests, using the same client
and credential providers as the S3 sink: `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` (optional `AWS_SESSION_TOKEN`), then web identity,
then the EC2 instance profile. The signing region is `--region`, else
`AWS_REGION`, else `us-east-1`. `--endpoint` must be `https`, or `http` on a
loopback address. The identity needs `s3:ListBucket` and `s3:GetObject` on
the prefix. GCS is not read directly: download the objects
(`gcloud storage cp -r gs://bucket/prefix ./audit/`) and verify the
directory.

## Inputs and options

```
haltsql audit verify [OPTION]... INPUT...
```

| Input | Meaning |
|---|---|
| `FILE` | JSON lines from a file or stdout sink (server or proxy), or a log with `--mixed`. |
| `DIR` | Downloaded S3/GCS objects. |
| `-` | Standard input. |
| `s3://BUCKET/PREFIX` | Objects read directly from S3. |

Inputs are verified independently; the command fails if any of them fails.

| Option | Effect |
|---|---|
| `--concat` | Treat the file inputs (and `-`), in the order given, as one chain, e.g. a rotated `audit.jsonl.1` followed by `audit.jsonl`. |
| `--any-start` | Accept a first record that does not link to genesis. |
| `--initial-prev HASH` | The first record must link to `HASH` (the head of the previous segment). |
| `--expect-head HASH` | The last record must be `HASH` (detects records missing at the end). |
| `--strict` | A new chain starting mid-stream is an error. |
| `--mixed` | Skip lines that are not audit records (logs, container log prefixes). |
| `--spool DIR` | Check the objects against the sink's spool (one host). |
| `--host HOST` | Only verify the objects written by `HOST`. |
| `--endpoint URL`, `--region R` | For `s3://` inputs. |
| `--json` | Machine-readable output. |

Exit codes: **0** every chain verifies, **1** a chain is broken (any
problem with severity `error`), **2** usage error or an input that cannot be
read (missing file, empty object directory, S3 access denied or
unreachable).

## Examples

```bash
# the proxy's file sink
haltsql audit verify /var/log/haltsql/proxy-audit.jsonl

# stdout records in container logs (operational log lines are skipped)
kubectl logs deploy/haltsql-proxy | haltsql audit verify --mixed -
docker logs haltsql 2>&1 | haltsql audit verify --mixed -

# rotated files, oldest first
haltsql audit verify --concat audit.jsonl.2 audit.jsonl.1 audit.jsonl

# objects downloaded from the bucket, checked against the live spool
aws s3 cp --recursive s3://corp-haltsql-audit/haltsql/audit/ ./audit/
haltsql audit verify --spool /var/lib/haltsql/spool --host haltsql-7f9c ./audit/

# anchor a daily check on yesterday's head
haltsql audit verify --json --expect-head "$(cat last-head)" audit.jsonl | jq .ok
```

Text output lists, per input, the record and chain counts, each chain's head
hash, every problem with its location (`file:line`, or the object key) and
finally the first broken link:

```
broken.jsonl: BROKEN, 4 records, 1 chain
  head broken.jsonl: 4dc0...
  error broken_link at broken.jsonl:2: prev_hash does not match the previous record's hash; records before this one were deleted, inserted, reordered or rewritten
  error broken_link at broken.jsonl:3: prev_hash does not match the previous record's hash; it continues the record at broken.jsonl:1 instead: records were reordered
  error truncated at broken.jsonl:5: the last line is incomplete (truncated write)
first broken link: broken.jsonl:2: prev_hash does not match the previous record's hash; ...
```

`--json` prints one object:

```json
{"ok": false, "records": 4,
 "inputs": [{"source": "broken.jsonl", "kind": "file", "ok": false, "records": 4,
             "objects": 0, "chains": 1, "skipped_lines": 0,
             "heads": [{"chain": "broken.jsonl", "hash": "4dc0..."}],
             "problems": [{"severity": "error", "kind": "broken_link",
                           "source": "broken.jsonl", "line": 2, "message": "..."}]}],
 "first_broken": {"severity": "error", "kind": "broken_link", "source": "broken.jsonl",
                  "line": 2, "message": "..."}}
```

`kind` values are stable: `bad_hash`, `broken_link`, `duplicate_record`,
`invalid_record`, `not_audit_record`, `truncated`, `mid_chain_start`,
`start_mismatch`, `chain_restart`, `head_mismatch`, `body_mismatch`,
`unrecognized_name`, `duplicate_object`, `conflicting_objects`,
`empty_object`, `seq_gap`, `run_order`, `fork`, `spool_corrupt`,
`spool_head_mismatch`.

## What a chain does not prove

A hash chain shows that records were not changed, removed or reordered
*relative to each other*. Someone who can rewrite the whole file can rebuild
a valid chain. To make that detectable, keep an independent copy of the head
hash (`--expect-head`), ship records to a second sink, or store objects in a
WORM bucket (S3 Object Lock, GCS retention). Without a spool directory, a
sink restarts its chain at every process start, so deleting all objects of an
earlier run is not detected.

## Testing

```bash
dune test test/audit
```

`test/audit/test_audit.ml` builds chains with the real sealing code
(`Audit_chain.seal`, `Object_sink` uploading into a directory) and tampers
with them: an edited field (with and without a recomputed hash), deleted,
swapped and duplicated lines, a truncated last line, a cut tail against
`--expect-head`, mid-chain starts, restarts, mixed logs; objects deleted,
duplicated, modified, truncated, reordered and conflicting, runs in the
wrong order, an earlier run deleted, and a spool whose head shows missing
objects. It runs the command-line binary for exit codes, `--json`, stdin,
`--concat` and usage errors. `test/audit/test_audit_minio.ml` starts a real
MinIO server in Docker (host port 16000), writes objects with the S3 sink,
verifies them through `s3://` and then tampers through the S3 API (a deleted
object, a forged object, wrong credentials, a missing bucket). It skips when
Docker or a MinIO image is unavailable (`HALTSQL_MINIO_IMAGE` selects the
image; nothing is pulled).
