let encode s = Base64.encode_string s

(* [Base64.decode] tolerates non-zero trailing bits and excess padding; re-encoding and
   comparing accepts only the canonical padded encoding. *)
let decode s =
  match Base64.decode s with
  | Ok v when String.equal (encode v) s -> Some v
  | Ok _ | Error _ -> None
