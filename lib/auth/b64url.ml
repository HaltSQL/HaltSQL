(* Strict unpadded base64url. *)

let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

let encode s =
  let n = String.length s in
  let b = Buffer.create ((n + 2) / 3 * 4) in
  let get i = Char.code s.[i] in
  let rec go i =
    if i + 3 <= n then begin
      let v = (get i lsl 16) lor (get (i + 1) lsl 8) lor get (i + 2) in
      Buffer.add_char b alphabet.[(v lsr 18) land 63];
      Buffer.add_char b alphabet.[(v lsr 12) land 63];
      Buffer.add_char b alphabet.[(v lsr 6) land 63];
      Buffer.add_char b alphabet.[v land 63];
      go (i + 3)
    end
    else if n - i = 2 then begin
      let v = (get i lsl 16) lor (get (i + 1) lsl 8) in
      Buffer.add_char b alphabet.[(v lsr 18) land 63];
      Buffer.add_char b alphabet.[(v lsr 12) land 63];
      Buffer.add_char b alphabet.[(v lsr 6) land 63]
    end
    else if n - i = 1 then begin
      let v = get i lsl 16 in
      Buffer.add_char b alphabet.[(v lsr 18) land 63];
      Buffer.add_char b alphabet.[(v lsr 12) land 63]
    end
  in
  go 0;
  Buffer.contents b

let value = function
  | 'A' .. 'Z' as c -> Some (Char.code c - 65)
  | 'a' .. 'z' as c -> Some (Char.code c - 97 + 26)
  | '0' .. '9' as c -> Some (Char.code c - 48 + 52)
  | '-' -> Some 62
  | '_' -> Some 63
  | _ -> None

exception Bad of string

let decode s =
  let n = String.length s in
  if n mod 4 = 1 then Error "invalid base64url length"
  else
    try
      let v i =
        match value s.[i] with Some x -> x | None -> raise (Bad "invalid base64url")
      in
      let b = Buffer.create (n * 3 / 4) in
      let rec go i =
        if i + 4 <= n then begin
          let x =
            (v i lsl 18) lor (v (i + 1) lsl 12) lor (v (i + 2) lsl 6) lor v (i + 3)
          in
          Buffer.add_char b (Char.chr ((x lsr 16) land 255));
          Buffer.add_char b (Char.chr ((x lsr 8) land 255));
          Buffer.add_char b (Char.chr (x land 255));
          go (i + 4)
        end
        else if n - i = 3 then begin
          let x = (v i lsl 18) lor (v (i + 1) lsl 12) lor (v (i + 2) lsl 6) in
          if x land 0xff <> 0 then raise (Bad "non-canonical base64url");
          Buffer.add_char b (Char.chr ((x lsr 16) land 255));
          Buffer.add_char b (Char.chr ((x lsr 8) land 255))
        end
        else if n - i = 2 then begin
          let x = (v i lsl 18) lor (v (i + 1) lsl 12) in
          if x land 0xffff <> 0 then raise (Bad "non-canonical base64url");
          Buffer.add_char b (Char.chr ((x lsr 16) land 255))
        end
      in
      go 0;
      Ok (Buffer.contents b)
    with Bad m -> Error m
