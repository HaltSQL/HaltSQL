(** Standard base64 (RFC 4648, with padding), on the [base64] package. *)

let encode s = Base64.encode_string s

(* [Base64.decode] tolerates excess padding (e.g. "A==="); requiring the re-encoded
   length to equal the input length rejects it. *)
let decode s =
  if String.length s mod 4 <> 0 then None
  else
    match Base64.decode s with
    | Ok v when String.length (encode v) = String.length s -> Some v
    | Ok _ | Error _ -> None
