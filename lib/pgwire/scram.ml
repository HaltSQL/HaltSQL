(** SCRAM-SHA-256 for the proxy: {!Haltsql_scram} plus the CSPRNG salt; see scram.mli. *)

module S = Haltsql_scram

let mechanism = S.mechanism S.SHA256
let pbkdf2_sha256 = S.hi S.SHA256

type verifier = S.verifier = {
  iterations : int;
  salt : string;
  stored_key : string;
  server_key : string;
}

let parse_verifier = S.parse_verifier
let verifier_to_string = S.verifier_to_string

let make_verifier ?iterations ?salt password =
  let salt = match salt with Some s -> s | None -> Sec.random 16 in
  S.make_verifier ?iterations ~salt password

let new_nonce () = S.nonce_of_entropy (Sec.random S.nonce_entropy_bytes)

module Server = struct
  type t = S.server

  let start ~verifier ~mock_secret ~user ~server_nonce client_first =
    Result.map_error S.error_to_string
      (S.server_start ~verifier ~mock_secret ~user ~server_nonce client_first)

  let finish t client_final =
    Result.map_error S.error_to_string (S.server_finish t client_final)
end

module Client = struct
  type t = { first : S.client_first; final : S.client_final option }

  let error = function
    | S.Server_error e -> "upstream SCRAM error: " ^ e
    | S.Server_signature_mismatch -> "upstream SCRAM server signature mismatch"
    | e -> "upstream " ^ S.error_to_string e

  let first ?user ~nonce () =
    let first = S.client_first ?user ~nonce () in
    ({ first; final = None }, first.message)

  let final t ~password server_first =
    match S.client_final S.SHA256 t.first ~password ~server_first with
    | Ok f -> Ok ({ t with final = Some f }, f.final_message)
    | Error e -> Error (error e)

  let verify_server t server_final =
    match t.final with
    | None -> Error "upstream SCRAM: unexpected server-final-message"
    | Some f -> Result.map_error error (S.verify_server_final f server_final)
end
