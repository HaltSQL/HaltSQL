(** Security helpers; see sec.mli. *)

let ct_equal = Haltsql_scram.equal_ct
let b64_encode = Haltsql_b64.encode
let b64_decode = Haltsql_b64.decode

let hex s =
  let b = Buffer.create (String.length s * 2) in
  String.iter (fun c -> Buffer.add_string b (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents b

let rng_ready = ref false

let init_rng () =
  if not !rng_ready then begin
    Mirage_crypto_rng_unix.use_default ();
    rng_ready := true
  end

let random n =
  init_rng ();
  Mirage_crypto_rng.generate n

let random_hex n = hex (random n)

let random_int32 () =
  let s = random 4 in
  Int32.to_int (String.get_int32_be s 0)

let md5_hex s = Digestif.MD5.(to_hex (digest_string s))
let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
let hmac_sha256 ~key m = Digestif.SHA256.(to_raw_string (hmac_string ~key m))

let xor a b =
  if String.length a <> String.length b then invalid_arg "Sec.xor";
  String.init (String.length a) (fun i -> Char.chr (Char.code a.[i] lxor Char.code b.[i]))
