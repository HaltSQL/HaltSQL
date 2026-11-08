(** Strict canonical standard base64 (RFC 4648, padded); see b64.mli. *)

let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let encode s =
  let n = String.length s in
  let b = Buffer.create ((n + 2) / 3 * 4) in
  let get i = if i < n then Char.code s.[i] else 0 in
  let i = ref 0 in
  while !i < n do
    let x = (get !i lsl 16) lor (get (!i + 1) lsl 8) lor get (!i + 2) in
    let rem = n - !i in
    Buffer.add_char b alphabet.[(x lsr 18) land 63];
    Buffer.add_char b alphabet.[(x lsr 12) land 63];
    Buffer.add_char b (if rem > 1 then alphabet.[(x lsr 6) land 63] else '=');
    Buffer.add_char b (if rem > 2 then alphabet.[x land 63] else '=');
    i := !i + 3
  done;
  Buffer.contents b

let value c =
  match c with
  | 'A' .. 'Z' -> Some (Char.code c - 65)
  | 'a' .. 'z' -> Some (Char.code c - 97 + 26)
  | '0' .. '9' -> Some (Char.code c - 48 + 52)
  | '+' -> Some 62
  | '/' -> Some 63
  | _ -> None

exception Bad

let decode s =
  let n = String.length s in
  if n mod 4 <> 0 then None
  else
    try
      let b = Buffer.create (n / 4 * 3) in
      let i = ref 0 in
      while !i < n do
        let last = !i + 4 = n in
        let v k = match value s.[!i + k] with Some v -> v | None -> raise Bad in
        let pad2 = s.[!i + 2] = '=' and pad3 = s.[!i + 3] = '=' in
        if (pad2 || pad3) && not last then raise Bad;
        if pad2 && not pad3 then raise Bad;
        let a = v 0 and c = v 1 in
        if pad2 then begin
          if c land 0xf <> 0 then raise Bad;
          Buffer.add_char b (Char.chr ((a lsl 2) lor (c lsr 4)))
        end
        else if pad3 then begin
          let d = v 2 in
          if d land 0x3 <> 0 then raise Bad;
          Buffer.add_char b (Char.chr ((a lsl 2) lor (c lsr 4)));
          Buffer.add_char b (Char.chr (((c land 0xf) lsl 4) lor (d lsr 2)))
        end
        else begin
          let d = v 2 and e = v 3 in
          Buffer.add_char b (Char.chr ((a lsl 2) lor (c lsr 4)));
          Buffer.add_char b (Char.chr (((c land 0xf) lsl 4) lor (d lsr 2)));
          Buffer.add_char b (Char.chr (((d land 0x3) lsl 6) lor e))
        end;
        i := !i + 4
      done;
      Some (Buffer.contents b)
    with Bad -> None
