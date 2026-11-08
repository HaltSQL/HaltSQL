let genesis = String.make 64 '0'
let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let seal ~prev fields =
  let body = fields @ [ ("prev_hash", `String prev) ] in
  let unsealed = Yojson.Safe.to_string (`Assoc body) in
  let hash = sha256_hex (prev ^ unsealed) in
  (Yojson.Safe.to_string (`Assoc (body @ [ ("hash", `String hash) ])), hash)

let hash_of_line line =
  match Yojson.Safe.from_string line with
  | `Assoc kv -> (
      match List.assoc_opt "hash" kv with Some (`String h) -> Some h | _ -> None)
  | _ -> None
  | exception _ -> None

let verify_lines ?(initial_prev = Some genesis) lines =
  let rec go n count prev = function
    | [] -> Ok count
    | l :: rest when String.trim l = "" -> go (n + 1) count prev rest
    | l :: rest -> (
        let err m = Error (n, m) in
        match Yojson.Safe.from_string l with
        | exception Yojson.Json_error e -> err ("invalid JSON: " ^ e)
        | `Assoc kv -> (
            match List.rev kv with
            | ("hash", `String h) :: rev_body -> (
                let body = List.rev rev_body in
                match List.assoc_opt "prev_hash" body with
                | Some (`String p) ->
                    if match prev with None -> false | Some e -> e <> p then
                      err "prev_hash does not match the previous record's hash"
                    else if sha256_hex (p ^ Yojson.Safe.to_string (`Assoc body)) <> h then
                      err "hash mismatch (record was modified)"
                    else go (n + 1) (count + 1) (Some h) rest
                | _ -> err "missing prev_hash")
            | _ -> err "missing trailing \"hash\" field")
        | _ -> err "record is not a JSON object")
  in
  go 1 0 initial_prev lines
