(** SCRAM-SHA-256 client (see scram.mli). *)

let hmac ~key msg = Digestif.SHA256.(to_raw_string (hmac_string ~key msg))
let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))

let xor a b =
  String.init (String.length a) (fun i -> Char.chr (Char.code a.[i] lxor Char.code b.[i]))

let equal_ct a b =
  String.length a = String.length b
  &&
  let acc = ref 0 in
  String.iteri (fun i c -> acc := !acc lor (Char.code c lxor Char.code b.[i])) a;
  !acc = 0

let pbkdf2_sha256 ~password ~salt ~iterations =
  Pbkdf.pbkdf2 ~prf:`SHA256 ~password ~salt ~count:(max 1 iterations) ~dk_len:32l

type client_first = { message : string; bare : string }

(* RFC 5802 saslname: '=' -> "=3D", ',' -> "=2C". *)
let saslname s =
  let b = Buffer.create (String.length s) in
  String.iter
    (function
      | '=' -> Buffer.add_string b "=3D"
      | ',' -> Buffer.add_string b "=2C"
      | c -> Buffer.add_char b c)
    s;
  Buffer.contents b

let client_first ~user ~nonce =
  let bare = "n=" ^ saslname user ^ ",r=" ^ nonce in
  { message = "n,," ^ bare; bare }

type client_final = { final_message : string; expected_server_signature : string }

let attrs s =
  String.split_on_char ',' s
  |> List.filter_map (fun kv ->
      if String.length kv >= 2 && kv.[1] = '=' then
        Some (kv.[0], String.sub kv 2 (String.length kv - 2))
      else None)

let ( let* ) = Result.bind

let b64d what s =
  match Base64.decode s with
  | Ok v -> Ok v
  | Error _ -> Error (Printf.sprintf "SCRAM: invalid base64 in %s" what)

let client_final ~password ~client_first ~client_nonce ~server_first =
  let a = attrs server_first in
  let* () =
    if List.mem_assoc 'm' a then Error "SCRAM: unsupported mandatory extension" else Ok ()
  in
  let* nonce =
    match List.assoc_opt 'r' a with
    | Some r
      when String.length r > String.length client_nonce
           && String.starts_with ~prefix:client_nonce r ->
        Ok r
    | _ -> Error "SCRAM: server nonce does not extend the client nonce"
  in
  let* salt =
    match List.assoc_opt 's' a with
    | Some s -> b64d "salt" s
    | None -> Error "SCRAM: server-first message has no salt"
  in
  let* iterations =
    match Option.bind (List.assoc_opt 'i' a) int_of_string_opt with
    | Some i when i >= 1 && i <= 10_000_000 -> Ok i
    | _ -> Error "SCRAM: invalid iteration count"
  in
  let salted = pbkdf2_sha256 ~password ~salt ~iterations in
  let client_key = hmac ~key:salted "Client Key" in
  let stored_key = sha256 client_key in
  let without_proof = "c=" ^ Base64.encode_string "n,," ^ ",r=" ^ nonce in
  let auth_message = client_first.bare ^ "," ^ server_first ^ "," ^ without_proof in
  let client_sig = hmac ~key:stored_key auth_message in
  let proof = xor client_key client_sig in
  let server_key = hmac ~key:salted "Server Key" in
  Ok
    {
      final_message = without_proof ^ ",p=" ^ Base64.encode_string proof;
      expected_server_signature = hmac ~key:server_key auth_message;
    }

let verify_server_final cf msg =
  let a = attrs msg in
  match (List.assoc_opt 'e' a, List.assoc_opt 'v' a) with
  | Some e, _ -> Error ("SCRAM: server reported an error: " ^ e)
  | None, Some v ->
      let* sig_ = b64d "server signature" v in
      if equal_ct sig_ cf.expected_server_signature then Ok ()
      else
        Error
          "SCRAM: server signature mismatch (the server did not prove it knows the \
           password)"
  | None, None -> Error "SCRAM: malformed server-final message"
