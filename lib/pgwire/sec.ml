(* Security helpers; see sec.mli. *)

let ct_equal a b =
  let la = String.length a and lb = String.length b in
  if la <> lb then false
  else begin
    let acc = ref 0 in
    for i = 0 to la - 1 do
      acc :=
        !acc lor (Char.code (String.unsafe_get a i) lxor Char.code (String.unsafe_get b i))
    done;
    !acc = 0
  end

let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let b64_encode s =
  let n = String.length s in
  let b = Buffer.create ((n + 2) / 3 * 4) in
  let i = ref 0 in
  while !i < n do
    let c0 = Char.code s.[!i] in
    let c1 = if !i + 1 < n then Char.code s.[!i + 1] else 0 in
    let c2 = if !i + 2 < n then Char.code s.[!i + 2] else 0 in
    let w = (c0 lsl 16) lor (c1 lsl 8) lor c2 in
    Buffer.add_char b alphabet.[(w lsr 18) land 63];
    Buffer.add_char b alphabet.[(w lsr 12) land 63];
    Buffer.add_char b (if !i + 1 < n then alphabet.[(w lsr 6) land 63] else '=');
    Buffer.add_char b (if !i + 2 < n then alphabet.[w land 63] else '=');
    i := !i + 3
  done;
  Buffer.contents b

let b64_value = function
  | 'A' .. 'Z' as c -> Char.code c - 65
  | 'a' .. 'z' as c -> Char.code c - 97 + 26
  | '0' .. '9' as c -> Char.code c - 48 + 52
  | '+' -> 62
  | '/' -> 63
  | _ -> -1

let b64_decode s =
  let n = String.length s in
  if n mod 4 <> 0 then None
  else
    let b = Buffer.create (n / 4 * 3) in
    let ok = ref true in
    let i = ref 0 in
    while !ok && !i < n do
      let last = !i + 4 = n in
      let v k = b64_value s.[!i + k] in
      let p2 = s.[!i + 2] = '=' and p3 = s.[!i + 3] = '=' in
      if (p2 || p3) && not last then ok := false
      else if p2 && not p3 then ok := false
      else begin
        let a = v 0 and bb = v 1 in
        let c = if p2 then 0 else v 2 in
        let d = if p3 then 0 else v 3 in
        if a < 0 || bb < 0 || c < 0 || d < 0 then ok := false
        else if (p2 && bb land 0xf <> 0) || (p3 && (not p2) && c land 0x3 <> 0) then
          (* non-canonical: padding bits must be zero *)
          ok := false
        else begin
          let w = (a lsl 18) lor (bb lsl 12) lor (c lsl 6) lor d in
          Buffer.add_char b (Char.chr ((w lsr 16) land 0xff));
          if not p2 then Buffer.add_char b (Char.chr ((w lsr 8) land 0xff));
          if not p3 then Buffer.add_char b (Char.chr (w land 0xff))
        end
      end;
      i := !i + 4
    done;
    if !ok then Some (Buffer.contents b) else None

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
