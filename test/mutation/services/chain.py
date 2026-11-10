AC = "lib/cloud/audit_chain.ml"
AD = "bin/server/lib/audit.ml"
BUILD = "opam exec -- dune build test/audit test/cloud test/siem test/server test/proxy bin/server bin/haltsql"

MUTANTS = [
    ("chain: prev hash not part of the sealed hash", AC,
     "let hash = sha256_hex (prev ^ unsealed) in", "let hash = sha256_hex unsealed in"),
    ("chain: prev_hash field not written from prev", AC,
     'let body = fields @ [ ("prev_hash", `String prev) ] in', 'let body = fields @ [ ("prev_hash", `String genesis) ] in'),
    ("chain: verify ignores prev linkage", AC,
     "if match prev with None -> false | Some e -> e <> p then", "if match prev with None -> false | Some e -> e <> p && false then"),
    ("chain: verify ignores record hash", AC,
     "else if sha256_hex (p ^ Yojson.Safe.to_string (`Assoc body)) <> h then", "else if sha256_hex (p ^ Yojson.Safe.to_string (`Assoc body)) <> h && false then"),
    ("chain: verify does not carry the hash forward", AC,
     "else go (n + 1) (count + 1) (Some h) rest", "else go (n + 1) (count + 1) prev rest"),
    ("chain: verify default start is not genesis", AC,
     "let verify_lines ?(initial_prev = Some genesis) lines =", "let verify_lines ?(initial_prev = None) lines ="),
    ("chain: record without prev_hash accepted", AC,
     '| _ -> err "missing prev_hash")', "| _ -> go (n + 1) (count + 1) prev rest)"),
    ("chain: record without trailing hash accepted", AC,
     '| _ -> err "missing trailing \\"hash\\" field")', "| _ -> go (n + 1) (count + 1) prev rest)"),
    ("chain: non-object line skipped", AC,
     '| _ -> err "record is not a JSON object")', "| _ -> go (n + 1) count prev rest)"),
    ("chain: invalid JSON line skipped", AC,
     '| exception Yojson.Json_error e -> err ("invalid JSON: " ^ e)', "| exception Yojson.Json_error _ -> go (n + 1) count prev rest"),
    ("chain: hash_of_line returns prev_hash", AC,
     'match List.assoc_opt "hash" kv with Some (`String h) -> Some h | _ -> None)', 'match List.assoc_opt "prev_hash" kv with Some (`String h) -> Some h | _ -> None)'),
    ("server chain: prev hash not part of the sealed hash", AD,
     "let hash = sha256_hex (prev ^ unsealed) in", "let hash = sha256_hex unsealed in"),
    ("server chain: verify ignores prev linkage", AD,
     "match prev with None -> true | Some e -> e = p", "match prev with None -> true | Some e -> e = p || true"),
    ("server chain: verify ignores record hash", AD,
     'if computed <> h then err "hash mismatch (record was modified)"', 'if computed <> h && false then err "hash mismatch (record was modified)"'),
    ("server chain: verify does not carry the hash forward", AD,
     "go (n + 1) (Some h) rest)", "go (n + 1) prev rest)"),
    ("server chain: verify default start is not genesis", AD,
     "let verify_lines ?(initial_prev = Some genesis) (lines : string list) :", "let verify_lines ?(initial_prev = None) (lines : string list) :"),
    ("server chain: record without trailing hash accepted", AD,
     '| _ -> err "missing trailing \\"hash\\" field")', "| _ -> go (n + 1) prev rest)"),
]

# Mutants that change nothing a test can observe, with the reason.
EQUIVALENT = {}
