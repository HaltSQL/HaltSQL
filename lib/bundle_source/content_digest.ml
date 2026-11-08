type algorithm = Sha256 | Sha512

let algorithm_of d =
  if not (Oci_ref.valid_digest d) then None
  else if String.starts_with ~prefix:"sha256:" d then Some Sha256
  else Some Sha512

let compute alg s =
  match alg with
  | Sha256 -> "sha256:" ^ Digestif.SHA256.(to_hex (digest_string s))
  | Sha512 -> "sha512:" ^ Digestif.SHA512.(to_hex (digest_string s))

let sha256 = compute Sha256

let matches ~expected content =
  match algorithm_of expected with
  | None -> false
  | Some alg -> Eqaf.equal (compute alg content) expected
