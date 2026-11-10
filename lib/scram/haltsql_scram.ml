(** SCRAM; see haltsql_scram.mli. *)

type hash = SHA256 | SHA512

let mechanism = function SHA256 -> "SCRAM-SHA-256" | SHA512 -> "SCRAM-SHA-512"
let max_message_length = 4096
let default_min_iterations = 4096
let default_max_iterations = 600_000
let nonce_entropy_bytes = 24
let ( let* ) = Result.bind

let hmac h ~key msg =
  match h with
  | SHA256 -> Digestif.SHA256.(to_raw_string (hmac_string ~key msg))
  | SHA512 -> Digestif.SHA512.(to_raw_string (hmac_string ~key msg))

let digest h s =
  match h with
  | SHA256 -> Digestif.SHA256.(to_raw_string (digest_string s))
  | SHA512 -> Digestif.SHA512.(to_raw_string (digest_string s))

let hi h ~password ~salt ~iterations =
  let prf, dk_len = match h with SHA256 -> (`SHA256, 32l) | SHA512 -> (`SHA512, 64l) in
  Pbkdf.pbkdf2 ~prf ~password ~salt ~count:(max 1 iterations) ~dk_len

let equal_ct a b = Eqaf.equal a b

(* Both arguments are digests of the same hash, so the lengths agree. *)
let xor a b =
  String.init (String.length a) (fun i -> Char.chr (Char.code a.[i] lxor Char.code b.[i]))

let b64_encode s = Base64.encode_string s

(* [Base64.decode] tolerates non-zero trailing bits and excess padding; comparing the
   re-encoded value accepts the canonical padded encoding only. *)
let b64_decode s =
  match Base64.decode s with
  | Ok v when String.equal (b64_encode v) s -> Some v
  | Ok _ | Error _ -> None

let nonce_of_entropy = b64_encode

type error =
  | Message_too_long
  | Malformed_client_first
  | Malformed_server_first
  | Malformed_client_final
  | Malformed_server_final
  | Unsupported_extension
  | Channel_binding_unsupported
  | Authzid_unsupported
  | Channel_binding_mismatch
  | Invalid_nonce
  | Nonce_not_extended
  | Nonce_mismatch
  | Invalid_salt
  | Invalid_iteration_count
  | Iteration_count_out_of_range of { count : int; min : int; max : int }
  | Invalid_proof
  | Server_error of string
  | Server_signature_mismatch
  | Authentication_failed

let error_to_string = function
  | Message_too_long -> "SCRAM: message too long"
  | Malformed_client_first -> "SCRAM: malformed client-first-message"
  | Malformed_server_first -> "SCRAM: malformed server-first-message"
  | Malformed_client_final -> "SCRAM: malformed client-final-message"
  | Malformed_server_final -> "SCRAM: malformed server-final-message"
  | Unsupported_extension -> "SCRAM: unsupported mandatory extension"
  | Channel_binding_unsupported -> "SCRAM: channel binding is not supported"
  | Authzid_unsupported -> "SCRAM: authorization identity is not supported"
  | Channel_binding_mismatch -> "SCRAM: channel binding mismatch"
  | Invalid_nonce -> "SCRAM: invalid nonce"
  | Nonce_not_extended -> "SCRAM: server nonce does not extend the client nonce"
  | Nonce_mismatch -> "SCRAM: nonce mismatch"
  | Invalid_salt -> "SCRAM: invalid salt"
  | Invalid_iteration_count -> "SCRAM: invalid iteration count"
  | Iteration_count_out_of_range { count; min; max } ->
      Printf.sprintf "SCRAM: iteration count %d outside %d..%d" count min max
  | Invalid_proof -> "SCRAM: malformed proof"
  | Server_error e -> "SCRAM: server error: " ^ e
  | Server_signature_mismatch ->
      "SCRAM: server signature mismatch (server did not prove it knows the password)"
  | Authentication_failed -> "SCRAM: authentication failed"

let bounded s =
  if String.length s > max_message_length then Error Message_too_long else Ok ()

(* ["k=v,k=v"]: every part must be a letter, ['='] and a value (which may contain ['='],
   as base64 does). [None] if any part is not. *)
let attrs s =
  let part p =
    if String.length p >= 2 && p.[1] = '=' then
      match p.[0] with
      | 'a' .. 'z' | 'A' .. 'Z' -> Some (p.[0], String.sub p 2 (String.length p - 2))
      | _ -> None
    else None
  in
  let rec go acc = function
    | [] -> Some (List.rev acc)
    | p :: rest -> ( match part p with Some a -> go (a :: acc) rest | None -> None)
  in
  go [] (String.split_on_char ',' s)

let valid_nonce n =
  n <> "" && String.for_all (fun c -> c >= '\x21' && c <= '\x7e' && c <> ',') n

(* Decimal digits only (no sign, no [0x], no [_]), at most nine so the value fits an
   [int] everywhere. *)
let decimal s =
  let n = String.length s in
  if n >= 1 && n <= 9 && String.for_all (function '0' .. '9' -> true | _ -> false) s
  then Some (int_of_string s)
  else None

let saslname s =
  let b = Buffer.create (String.length s) in
  String.iter
    (function
      | '=' -> Buffer.add_string b "=3D"
      | ',' -> Buffer.add_string b "=2C"
      | c -> Buffer.add_char b c)
    s;
  Buffer.contents b

(* ---------------------------------------------------------------- client *)

type client_first = { nonce : string; bare : string; message : string }

let gs2_header = "n,,"

let client_first ?(user = "") ~nonce () =
  let bare = "n=" ^ saslname user ^ ",r=" ^ nonce in
  { nonce; bare; message = gs2_header ^ bare }

type client_final = { final_message : string; server_signature : string }

let client_final ?(min_iterations = default_min_iterations)
    ?(max_iterations = default_max_iterations) h (cf : client_first) ~password
    ~server_first =
  let* () = bounded server_first in
  let* r, s, i =
    match attrs server_first with
    | Some (('m', _) :: _) -> Error Unsupported_extension
    | Some (('r', r) :: ('s', s) :: ('i', i) :: _) -> Ok (r, s, i)
    | Some _ | None -> Error Malformed_server_first
  in
  let* () =
    if String.length r > String.length cf.nonce && String.starts_with ~prefix:cf.nonce r
    then Ok ()
    else Error Nonce_not_extended
  in
  let* () = if valid_nonce r then Ok () else Error Invalid_nonce in
  let* salt =
    match b64_decode s with
    | Some salt when salt <> "" -> Ok salt
    | _ -> Error Invalid_salt
  in
  let* iterations =
    match decimal i with
    | None -> Error Invalid_iteration_count
    | Some n when n < min_iterations || n > max_iterations ->
        Error
          (Iteration_count_out_of_range
             { count = n; min = min_iterations; max = max_iterations })
    | Some n -> Ok n
  in
  let salted = hi h ~password ~salt ~iterations in
  let client_key = hmac h ~key:salted "Client Key" in
  let stored_key = digest h client_key in
  let server_key = hmac h ~key:salted "Server Key" in
  let without_proof = "c=" ^ b64_encode gs2_header ^ ",r=" ^ r in
  let auth_message = cf.bare ^ "," ^ server_first ^ "," ^ without_proof in
  let proof = xor client_key (hmac h ~key:stored_key auth_message) in
  Ok
    {
      final_message = without_proof ^ ",p=" ^ b64_encode proof;
      server_signature = hmac h ~key:server_key auth_message;
    }

let printable = String.map (fun c -> if c < ' ' || c > '~' then '?' else c)

let verify_server_signature ~expected server_final =
  let* () = bounded server_final in
  match attrs server_final with
  | Some (('e', e) :: _) -> Error (Server_error (printable e))
  | Some (('v', v) :: rest) when not (List.mem_assoc 'e' rest) -> (
      match b64_decode v with
      | Some got when equal_ct got expected -> Ok ()
      | Some _ | None -> Error Server_signature_mismatch)
  | Some _ | None -> Error Malformed_server_final

let verify_server_final (f : client_final) server_final =
  verify_server_signature ~expected:f.server_signature server_final

(* ---------------------------------------------------------------- server *)

type verifier = {
  iterations : int;
  salt : string;
  stored_key : string;
  server_key : string;
}

let parse_verifier s =
  match String.split_on_char '$' s with
  | [ "SCRAM-SHA-256"; iter_salt; keys ] -> (
      match (String.split_on_char ':' iter_salt, String.split_on_char ':' keys) with
      | [ it; salt ], [ sk; svk ] -> (
          match (decimal it, b64_decode salt, b64_decode sk, b64_decode svk) with
          | Some iterations, Some salt, Some stored_key, Some server_key
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
  Printf.sprintf "SCRAM-SHA-256$%d:%s$%s:%s" v.iterations (b64_encode v.salt)
    (b64_encode v.stored_key) (b64_encode v.server_key)

let make_verifier ?(iterations = 4096) ~salt password =
  let salted = hi SHA256 ~password ~salt ~iterations in
  let stored_key = digest SHA256 (hmac SHA256 ~key:salted "Client Key") in
  let server_key = hmac SHA256 ~key:salted "Server Key" in
  { iterations; salt; stored_key; server_key }

type server = {
  verifier : verifier;
  real : bool;
  client_first_bare : string;
  server_first : string;
  client_gs2_header : string;
  nonce : string;
}

let server_start ~verifier ~mock_secret ~user ~server_nonce client_first =
  let* () = bounded client_first in
  (* gs2-header: ("n" | "y" | "p=" cb-name) "," [authzid] "," *)
  let len = String.length client_first in
  let* gs2_flag, rest =
    match String.index_opt client_first ',' with
    | Some 1 -> Ok (client_first.[0], String.sub client_first 2 (len - 2))
    | Some _ when len >= 2 && client_first.[0] = 'p' && client_first.[1] = '=' ->
        Error Channel_binding_unsupported
    | _ -> Error Malformed_client_first
  in
  let* () =
    match gs2_flag with 'n' | 'y' -> Ok () | _ -> Error Malformed_client_first
  in
  let* client_first_bare =
    match String.index_opt rest ',' with
    | Some 0 -> Ok (String.sub rest 1 (String.length rest - 1))
    | Some _ -> Error Authzid_unsupported
    | None -> Error Malformed_client_first
  in
  let client_gs2_header =
    String.sub client_first 0 (len - String.length client_first_bare)
  in
  let* cnonce =
    match attrs client_first_bare with
    | Some (('m', _) :: _) -> Error Unsupported_extension
    | Some (('n', _) :: ('r', r) :: _) ->
        if valid_nonce r then Ok r else Error Invalid_nonce
    | Some _ | None -> Error Malformed_client_first
  in
  let verifier, real =
    match verifier with
    | Some v -> (v, true)
    | None ->
        let mock label = hmac SHA256 ~key:mock_secret (label ^ user) in
        ( {
            iterations = 4096;
            salt = String.sub (mock "salt:") 0 16;
            stored_key = mock "stored:";
            server_key = mock "server:";
          },
          false )
  in
  let nonce = cnonce ^ server_nonce in
  let server_first =
    Printf.sprintf "r=%s,s=%s,i=%d" nonce (b64_encode verifier.salt) verifier.iterations
  in
  Ok
    ( { verifier; real; client_first_bare; server_first; client_gs2_header; nonce },
      server_first )

let server_finish t client_final =
  let* () = bounded client_final in
  (* The proof is the last attribute. *)
  let rec find_last i =
    if i < 0 then None
    else if
      client_final.[i] = ',' && client_final.[i + 1] = 'p' && client_final.[i + 2] = '='
    then Some i
    else find_last (i - 1)
  in
  match find_last (String.length client_final - 3) with
  | None -> Error Malformed_client_final
  | Some i -> (
      let without_proof = String.sub client_final 0 i in
      let proof_b64 =
        String.sub client_final (i + 3) (String.length client_final - i - 3)
      in
      match attrs without_proof with
      | Some (('c', cb) :: ('r', r) :: _) -> (
          if not (equal_ct cb (b64_encode t.client_gs2_header)) then
            Error Channel_binding_mismatch
          else if not (equal_ct r t.nonce) then Error Nonce_mismatch
          else
            match b64_decode proof_b64 with
            | Some proof when String.length proof = 32 ->
                let auth_message =
                  t.client_first_bare ^ "," ^ t.server_first ^ "," ^ without_proof
                in
                let client_sig = hmac SHA256 ~key:t.verifier.stored_key auth_message in
                let client_key = xor proof client_sig in
                let ok = equal_ct (digest SHA256 client_key) t.verifier.stored_key in
                let server_sig = hmac SHA256 ~key:t.verifier.server_key auth_message in
                if ok && t.real then Ok ("v=" ^ b64_encode server_sig)
                else Error Authentication_failed
            | Some _ | None -> Error Invalid_proof)
      | Some _ | None -> Error Malformed_client_final)
