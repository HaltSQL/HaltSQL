#!/usr/bin/env python3
"""Verify HaltSQL audit hash chains exported from Kafka or Elasticsearch/OpenSearch.

  verify_chain.py kafka [--any-start] FILE
      FILE: kafka-console-consumer output with --property print.key=true
      --property key.separator=<TAB> (one "<chain id>\t<record>" line per
      message, offset order)
  verify_chain.py es [--any-start] FILE
      FILE: a _search response (or a JSON list of hits) of the index / data
      stream, or JSON lines of _source documents

hash = sha256_hex(prev_hash + L), L = the record's compact JSON without "hash".
Kafka values are the exact bytes HaltSQL hashed. Elasticsearch documents carry
them in event.original (their other fields must equal it). Each process run
writes its own chain from genesis (64 zeros): Kafka keeps one key per chain;
in Elasticsearch several chains (restarts, replicas) share the index and are
told apart by following prev_hash from each genesis record.

Delivery is at least once: an exact copy of a record already seen (same hash,
content verified) is a retry and is skipped, so a whole batch sent twice
verifies. A chain that does not start at genesis means records before it are
missing (deleted, or removed by retention): that is a failure unless
--any-start is given. Exit status 1 on the first problem, 0 when every record
verifies.
"""
import hashlib
import json
import sys

GENESIS = "0" * 64


def check_raw(line):
    """(prev_hash, hash) of an exact record line; raises on tampering."""
    i = line.rindex(',"hash":"')
    body, claimed = line[:i] + "}", json.loads(line)["hash"]
    prev = json.loads(body)["prev_hash"]
    if hashlib.sha256((prev + body).encode()).hexdigest() != claimed:
        raise ValueError("hash mismatch (record was modified)")
    return prev, claimed


def normalize(v):
    """Synthetic _source may sort and de-duplicate arrays and unwrap 1-element ones."""
    if isinstance(v, dict):
        return {k: normalize(x) for k, x in v.items()}
    if isinstance(v, list):
        items = sorted({json.dumps(normalize(x), sort_keys=True) for x in v})
        items = [json.loads(x) for x in items]
        return items[0] if len(items) == 1 else items
    return v


def check_doc(doc):
    """A document's exact record is event.original; its searchable fields must match."""
    original = doc["event"]["original"]
    prev, h = check_raw(original)
    fields = {k: v for k, v in doc.items() if k != "event"}
    if normalize(fields) != normalize(json.loads(original)):
        raise ValueError("searchable fields differ from event.original")
    return prev, h


def kafka(path, any_start=False):
    chains = {}
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.rstrip("\n")
        if "\t" not in line:
            continue  # consumer status lines
        key, value = line.split("\t", 1)
        try:
            prev, h = check_raw(value)
        except (ValueError, KeyError) as e:
            sys.exit(f"line {n} (chain {key}): {e}")
        c = chains.setdefault(
            key, {"head": None, "count": 0, "start": prev, "seen": set()}
        )
        if h in c["seen"]:
            continue  # an exact re-delivery (retried produce request): skipped
        if c["head"] is not None and prev != c["head"]:
            sys.exit(f"line {n} (chain {key}): prev_hash does not match the previous record")
        c["head"], c["count"] = h, c["count"] + 1
        c["seen"].add(h)
    total = 0
    for key, c in chains.items():
        where = "genesis" if c["start"] == GENESIS else "mid-stream"
        print(f"chain {key}: {c['count']} records from {where}, head {c['head']}")
        total += c["count"]
    mid = [k for k, c in chains.items() if c["start"] != GENESIS]
    if mid and not any_start:
        sys.exit(
            f"chain {mid[0]} starts mid-stream: the records before it are missing "
            "(deleted or removed by retention); --any-start verifies from there"
        )
    print(f"OK: {total} records in {len(chains)} chain(s)")


def es_docs(path):
    text = open(path, encoding="utf-8").read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [(None, json.loads(l)) for l in text.splitlines() if l.strip()]
    hits = data["hits"]["hits"] if isinstance(data, dict) else data
    return [(h.get("_id"), h["_source"]) for h in hits]


def es(path, any_start=False):
    # every chain of every run starts at genesis; any other prev_hash may be
    # claimed by one record only (two would be a fork)
    genesis_heads, by_prev, seen = [], {}, set()
    for _id, doc in es_docs(path):
        try:
            prev, h = check_doc(doc)
        except (ValueError, KeyError) as e:
            sys.exit(f"document {_id}: {e}")
        if _id is not None and _id != h:
            sys.exit(f"document {_id}: _id is not the record hash")
        if h in seen:
            continue  # the same record stored twice (a retry across a rollover)
        seen.add(h)
        if prev == GENESIS:
            genesis_heads.append(h)
            continue
        if prev in by_prev:
            sys.exit(f"document {_id}: two records claim the same prev_hash (fork)")
        by_prev[prev] = h
    starts = [(GENESIS, h) for h in genesis_heads] + [
        (p, h) for p, h in by_prev.items() if p not in seen
    ]
    total = 0
    for start, first in starts:
        n, h = 1, first
        while h in by_prev:
            h = by_prev[h]
            n += 1
        where = "genesis" if start == GENESIS else f"a missing record {start[:16]}"
        print(f"chain from {where}: {n} records, head {h}")
        total += n
    if total != len(seen):
        sys.exit("records that are not reachable from any chain start (a cycle)")
    missing = [s for s, _ in starts if s != GENESIS]
    if missing and not any_start:
        sys.exit(
            f"a chain follows the missing record {missing[0]}: a document was deleted "
            "(or the export starts mid-chain; --any-start verifies from there)"
        )
    print(f"OK: {total} records in {len(starts)} chain(s)")


if __name__ == "__main__":
    args = sys.argv[1:]
    any_start = "--any-start" in args
    args = [a for a in args if a != "--any-start"]
    if len(args) != 2 or args[0] not in ("kafka", "es"):
        sys.exit(__doc__)
    {"kafka": kafka, "es": es}[args[0]](args[1], any_start=any_start)
