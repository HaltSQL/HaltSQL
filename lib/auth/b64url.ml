(** Strict unpadded base64url, on the [base64] package. *)

let alphabet = Base64.uri_safe_alphabet
let encode s = Base64.encode_string ~pad:false ~alphabet s

let is_alphabet_char = function
  | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '_' -> true
  | _ -> false

(* [Base64.decode] tolerates padding and non-zero trailing bits. Re-encoding the result
   and comparing it with the input restores "exactly one accepted encoding per byte
   string". *)
let decode s =
  if String.length s mod 4 = 1 then Error "invalid base64url length"
  else if not (String.for_all is_alphabet_char s) then Error "invalid base64url"
  else
    match Base64.decode ~pad:false ~alphabet s with
    | Ok v when String.equal (encode v) s -> Ok v
    | Ok _ -> Error "non-canonical base64url"
    | Error _ -> Error "invalid base64url"
