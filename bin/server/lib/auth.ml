(** Bearer-token authentication. Tokens are stored as SHA-256 hex digests; comparison is
    constant-time and always scans every configured token so timing does not reveal which
    (or whether a) token matched. *)

open Haltsql

let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let ct_equal a b =
  let la = String.length a and lb = String.length b in
  let r = ref (la lxor lb) in
  for i = 0 to la - 1 do
    let cb = if lb = 0 then 0 else Char.code b.[i mod lb] in
    r := !r lor (Char.code a.[i] lxor cb)
  done;
  !r = 0

type outcome =
  | Missing  (** no Authorization header *)
  | Invalid  (** malformed header or unknown token *)
  | Token of Config.token

let authenticate (tokens : Config.token list) (header : string option) =
  match header with
  | None -> Missing
  | Some h -> (
      let h = String.trim h in
      let prefix = "bearer " in
      let lp = String.length prefix in
      if String.length h <= lp || String.lowercase_ascii (String.sub h 0 lp) <> prefix
      then Invalid
      else
        let token = String.trim (String.sub h lp (String.length h - lp)) in
        if token = "" then Invalid
        else
          let digest = sha256_hex token in
          let found =
            List.fold_left
              (fun acc (t : Config.token) ->
                let m = ct_equal digest (String.lowercase_ascii t.token_sha256) in
                match acc with None when m -> Some t | _ -> acc)
              None tokens
          in
          match found with Some t -> Token t | None -> Invalid)
