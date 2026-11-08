#!/usr/bin/env python3
"""Verify HaltSQL audit hash chains exported from Kafka or Elasticsearch/OpenSearch.

  verify_chain.py kafka FILE   FILE: kafka-console-consumer output with
                               --property print.key=true --property key.separator=<TAB>
                               (one "<chain id>\t<record>" line per message, offset order)
  verify_chain.py es FILE      FILE: a _search response (or a JSON list of hits) of the
                               index / data stream, or JSON lines of _source documents

hash = sha256_hex(prev_hash + L), L = the record's compact JSON without "hash".
Kafka values are the exact bytes HaltSQL hashed. Elasticsearch documents carry
them in event.original (their other fields must equal it). Each process writes its own chain
(Kafka: one key per chain; Elasticsearch: chains are linked by prev_hash from
64 zeros). A record whose hash equals the previous one is an at-least-once
retry and is skipped. Exit status 1 on the first problem.
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


def kafka(path):
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
        c = chains.setdefault(key, {"head": None, "count": 0, "start": prev})
        if c["head"] == h:
            continue  # duplicate from a retried request
        if c["head"] is not None and prev != c["head"]:
            sys.exit(f"line {n} (chain {key}): prev_hash does not match the previous record")
        c["head"], c["count"] = h, c["count"] + 1
    total = 0
    for key, c in chains.items():
        where = "genesis" if c["start"] == GENESIS else "mid-stream"
        print(f"chain {key}: {c['count']} records from {where}, head {c['head']}")
        total += c["count"]
    print(f"OK: {total} records in {len(chains)} chain(s)")


def es_docs(path):
    text = open(path, encoding="utf-8").read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [(None, json.loads(l)) for l in text.splitlines() if l.strip()]
    hits = data["hits"]["hits"] if isinstance(data, dict) else data
    return [(h.get("_id"), h["_source"]) for h in hits]


def es(path):
    by_prev, seen = {}, set()
    for _id, doc in es_docs(path):
        try:
            prev, h = check_doc(doc)
        except (ValueError, KeyError) as e:
            sys.exit(f"document {_id}: {e}")
        if _id is not None and _id != h:
            sys.exit(f"document {_id}: _id is not the record hash")
        if h in seen:
            continue
        seen.add(h)
        if prev in by_prev:
            sys.exit(f"document {_id}: two records claim the same prev_hash (fork)")
        by_prev[prev] = h
    hashes = set(by_prev.values())
    starts = [p for p in by_prev if p not in hashes]
    total = 0
    for start in starts:
        n, h = 0, start
        while h in by_prev:
            h = by_prev[h]
            n += 1
        where = "genesis" if start == GENESIS else f"a missing record {start[:16]}"
        print(f"chain from {where}: {n} records, head {h}")
        total += n
    print(f"OK: {total} records in {len(starts)} chain(s)")
    if any(s != GENESIS for s in starts):
        print("note: a chain that does not start at genesis follows a record that is not here")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("kafka", "es"):
        sys.exit(__doc__)
    {"kafka": kafka, "es": es}[sys.argv[1]](sys.argv[2])
