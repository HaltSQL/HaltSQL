(** SCRAM-SHA-256; see scram.mli. *)

let mechanism = "SCRAM-SHA-256"
let ( let* ) = Result.bind

let pbkdf2_sha256 ~password ~salt ~iterations =
  let hmac = Sec.hmac_sha256 ~key:password in
  let u1 = hmac (salt ^ "\000\000\000\001") in
  let acc = Bytes.of_string u1 in
  let u = ref u1 in
  for _ = 2 to iterations do
    u := hmac !u;
    let s = !u in
    for j = 0 to 31 do
      Bytes.set acc j (Char.chr (Char.code (Bytes.get acc j) lxor Char.code s.[j]))
    done
  done;
  Bytes.to_string acc

type verifier = {
  iterations : int;
  salt : string;
  stored_key : string;
  server_key : string;
}

let split_on c s = String.split_on_char c s

let parse_verifier s =
  match split_on '$' s with
  | [ "SCRAM-SHA-256"; iter_salt; keys ] -> (
      match (split_on ':' iter_salt, split_on ':' keys) with
      | [ it; salt ], [ sk; svk ] -> (
          let iterations =
            if
              it <> ""
              && String.for_all (function '0' .. '9' -> true | _ -> false) it
              && String.length it <= 9
            then int_of_string it
            else 0
          in
          match (Sec.b64_decode salt, Sec.b64_decode sk, Sec.b64_decode svk) with
          | Some salt, Some stored_key, Some server_key
            when iterations >= 1 && salt <> ""
                 && String.length stored_key = 32
                 && String.length server_key = 32 ->
              Ok { iterations; salt; stored_key; server_key }
          | _ ->
              Error "invalid SCRAM verifier (bad iteration count, base64 or key length)")
      | _ -> Error "invalid SCRAM verifier (expected <iter>:<salt>$<stored>:<server>)")
  | _ ->
      Error
        "invalid SCRAM verifier (expected \
         SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>)"

let verifier_to_string v =
  Printf.sprintf "SCRAM-SHA-256$%d:%s$%s:%s" v.iterations (Sec.b64_encode v.salt)
    (Sec.b64_encode v.stored_key) (Sec.b64_encode v.server_key)

let keys_of_salted salted =
  let client_key = Sec.hmac_sha256 ~key:salted "Client Key" in
  let server_key = Sec.hmac_sha256 ~key:salted "Server Key" in
  (client_key, Sec.sha256 client_key, server_key)

let make_verifier ?(iterations = 4096) ?salt password =
  let salt = match salt with Some s -> s | None -> Sec.random 16 in
  let salted = pbkdf2_sha256 ~password ~salt ~iterations in
  let _, stored_key, server_key = keys_of_salted salted in
  { iterations; salt; stored_key; server_key }

(* "k=v" attribute list. Values may contain '=' (base64), so split at the first. *)
let attrs s =
  List.map
    (fun part ->
      if String.length part >= 2 && part.[1] = '=' then
        Some (part.[0], String.sub part 2 (String.length part - 2))
      else None)
    (split_on ',' s)

let valid_nonce n =
  n <> "" && String.for_all (fun c -> c >= '\x21' && c <= '\x7e' && c <> ',') n

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

module Server = struct
  type t = {
    verifier : verifier;
    real : bool;
    client_first_bare : string;
    server_first : string;
    gs2_header : string;
    nonce : string;
  }

  let start ~verifier ~mock_secret ~user ~server_nonce client_first =
    (* gs2-header: ("n" | "y") "," [authzid] "," *)
    let* gs2_flag, rest =
      match String.index_opt client_first ',' with
      | Some 1 ->
          Ok (client_first.[0], String.sub client_first 2 (String.length client_first - 2))
      | _ -> Error "malformed SCRAM client-first-message"
    in
    let* () =
      match gs2_flag with
      | 'n' | 'y' -> Ok ()
      | 'p' -> Error "channel binding is not supported"
      | _ -> Error "malformed SCRAM gs2 header"
    in
    let* client_first_bare =
      match String.index_opt rest ',' with
      | Some 0 -> Ok (String.sub rest 1 (String.length rest - 1))
      | Some _ -> Error "SCRAM authorization identity is not supported"
      | None -> Error "malformed SCRAM gs2 header"
    in
    let gs2_header =
      String.sub client_first 0
        (String.length client_first - String.length client_first_bare)
    in
    let* cnonce =
      match attrs client_first_bare with
      | Some ('m', _) :: _ -> Error "SCRAM mandatory extensions are not supported"
      | Some ('n', _) :: Some ('r', r) :: _ when valid_nonce r -> Ok r
      | _ -> Error "malformed SCRAM client-first-message"
    in
    let verifier, real =
      match verifier with
      | Some v -> (v, true)
      | None ->
          let salt =
            String.sub (Sec.hmac_sha256 ~key:mock_secret ("salt:" ^ user)) 0 16
          in
          ( {
              iterations = 4096;
              salt;
              stored_key = Sec.hmac_sha256 ~key:mock_secret ("stored:" ^ user);
              server_key = Sec.hmac_sha256 ~key:mock_secret ("server:" ^ user);
            },
            false )
    in
    let nonce = cnonce ^ server_nonce in
    let server_first =
      Printf.sprintf "r=%s,s=%s,i=%d" nonce
        (Sec.b64_encode verifier.salt)
        verifier.iterations
    in
    Ok
      ( { verifier; real; client_first_bare; server_first; gs2_header; nonce },
        server_first )

  let finish t client_final =
    let fail = Error "SCRAM authentication failed" in
    let p_marker = ",p=" in
    let rec find_last i =
      if i < 0 then None
      else if
        client_final.[i] = ',' && client_final.[i + 1] = 'p' && client_final.[i + 2] = '='
      then Some i
      else find_last (i - 1)
    in
    match find_last (String.length client_final - String.length p_marker) with
    | None -> Error "malformed SCRAM client-final-message"
    | Some i -> (
        let without_proof = String.sub client_final 0 i in
        let proof_b64 =
          String.sub client_final (i + 3) (String.length client_final - i - 3)
        in
        match attrs without_proof with
        | Some ('c', cb) :: Some ('r', r) :: _ -> (
            if not (Sec.ct_equal cb (Sec.b64_encode t.gs2_header)) then
              Error "SCRAM channel binding mismatch"
            else if not (Sec.ct_equal r t.nonce) then Error "SCRAM nonce mismatch"
            else
              match Sec.b64_decode proof_b64 with
              | Some proof when String.length proof = 32 ->
                  let auth_message =
                    t.client_first_bare ^ "," ^ t.server_first ^ "," ^ without_proof
                  in
                  let client_sig =
                    Sec.hmac_sha256 ~key:t.verifier.stored_key auth_message
                  in
                  let client_key = Sec.xor proof client_sig in
                  let ok = Sec.ct_equal (Sec.sha256 client_key) t.verifier.stored_key in
                  if ok && t.real then
                    let server_sig =
                      Sec.hmac_sha256 ~key:t.verifier.server_key auth_message
                    in
                    Ok ("v=" ^ Sec.b64_encode server_sig)
                  else fail
              | _ -> Error "malformed SCRAM proof")
        | _ -> Error "malformed SCRAM client-final-message")
end

module Client = struct
  type t = {
    cnonce : string;
    client_first_bare : string;
    server_signature : string option;
  }

  let first ?(user = "") ~nonce () =
    let esc =
      String.concat ""
        (List.map
           (function ',' -> "=2C" | '=' -> "=3D" | c -> String.make 1 c)
           (List.init (String.length user) (String.get user)))
    in
    let bare = "n=" ^ esc ^ ",r=" ^ nonce in
    ({ cnonce = nonce; client_first_bare = bare; server_signature = None }, "n,," ^ bare)

  let final t ~password server_first =
    match attrs server_first with
    | Some ('r', r) :: Some ('s', s) :: Some ('i', i) :: _ -> (
        let iterations =
          if
            i <> ""
            && String.length i <= 9
            && String.for_all (function '0' .. '9' -> true | _ -> false) i
          then int_of_string i
          else 0
        in
        match Sec.b64_decode s with
        | Some salt
          when iterations >= 1 && iterations <= 10_000_000 && salt <> ""
               && starts_with ~prefix:t.cnonce r
               && String.length r > String.length t.cnonce
               && valid_nonce r ->
            let salted = pbkdf2_sha256 ~password ~salt ~iterations in
            let client_key, stored_key, server_key = keys_of_salted salted in
            let without_proof = "c=biws,r=" ^ r in
            let auth_message =
              t.client_first_bare ^ "," ^ server_first ^ "," ^ without_proof
            in
            let client_sig = Sec.hmac_sha256 ~key:stored_key auth_message in
            let proof = Sec.xor client_key client_sig in
            let server_sig = Sec.hmac_sha256 ~key:server_key auth_message in
            Ok
              ( { t with server_signature = Some server_sig },
                without_proof ^ ",p=" ^ Sec.b64_encode proof )
        | _ -> Error "invalid SCRAM server-first-message")
    | _ -> Error "malformed SCRAM server-first-message"

  let verify_server t server_final =
    match (t.server_signature, attrs server_final) with
    | Some expected, Some ('v', v) :: _ -> (
        match Sec.b64_decode v with
        | Some got when Sec.ct_equal got expected -> Ok ()
        | _ -> Error "upstream SCRAM server signature mismatch")
    | Some _, Some ('e', e) :: _ -> Error ("upstream SCRAM error: " ^ e)
    | _ -> Error "malformed SCRAM server-final-message"
end
