(** SCRAM-SHA-256 client: {!Haltsql_scram} with this library's error wording. See
    scram.mli. *)

module S = Haltsql_scram

type state = { first : S.client_first; final : S.client_final option }

let constant_time_equal = S.equal_ct
let pbkdf2_sha256 = S.hi S.SHA256

let error = function
  | S.Iteration_count_out_of_range _ -> "SCRAM: iteration count out of range"
  | e -> S.error_to_string e

let client_first ~user ~nonce =
  let first = S.client_first ~user ~nonce () in
  ({ first; final = None }, first.message)

let client_final st ~password ~server_first =
  match S.client_final S.SHA256 st.first ~password ~server_first with
  | Ok f -> Ok ({ st with final = Some f }, f.final_message)
  | Error e -> Error (error e)

let verify_server_final st msg =
  match st.final with
  | None -> Error "SCRAM: exchange incomplete"
  | Some f -> Result.map_error error (S.verify_server_final f msg)
