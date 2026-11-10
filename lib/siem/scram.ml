module S = Haltsql_scram

type hash = Sha256 | Sha512
type client_first = S.client_first = { nonce : string; bare : string; message : string }

let hash = function Sha256 -> S.SHA256 | Sha512 -> S.SHA512
let hi h = S.hi (hash h)

let rng_ready =
  lazy
    (try ignore (Mirage_crypto_rng.generate 1)
     with Mirage_crypto_rng.Unseeded_generator -> Mirage_crypto_rng_unix.use_default ())

let client_first ?nonce ~username () =
  let nonce =
    match nonce with
    | Some n -> n
    | None ->
        Lazy.force rng_ready;
        S.nonce_of_entropy (Mirage_crypto_rng.generate S.nonce_entropy_bytes)
  in
  S.client_first ~user:username ~nonce ()

let client_final h ~password cf ~server_first =
  match S.client_final (hash h) cf ~password ~server_first with
  | Ok f -> Ok (f.final_message, Base64.encode_string f.server_signature)
  | Error e -> Error (S.error_to_string e)

let verify_server_final ~expected msg =
  match Base64.decode expected with
  | Ok expected ->
      Result.map_error S.error_to_string (S.verify_server_signature ~expected msg)
  | Error _ -> Error (S.error_to_string S.Server_signature_mismatch)
