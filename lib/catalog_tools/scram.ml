(** SCRAM-SHA-256 client: {!Haltsql_scram} (see scram.mli). *)

module S = Haltsql_scram

let equal_ct = S.equal_ct
let pbkdf2_sha256 = S.hi S.SHA256

type client_first = { message : string; bare : string }

let client_first ~user ~nonce =
  let f = S.client_first ~user ~nonce () in
  { message = f.message; bare = f.bare }

type client_final = { final_message : string; expected_server_signature : string }

let client_final ~password ~client_first ~client_nonce ~server_first =
  let first : S.client_first =
    { nonce = client_nonce; bare = client_first.bare; message = client_first.message }
  in
  match S.client_final S.SHA256 first ~password ~server_first with
  | Ok f ->
      Ok
        {
          final_message = f.final_message;
          expected_server_signature = f.server_signature;
        }
  | Error e -> Error (S.error_to_string e)

let verify_server_final cf msg =
  Result.map_error S.error_to_string
    (S.verify_server_signature ~expected:cf.expected_server_signature msg)
