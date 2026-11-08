(** Standard base64 (RFC 4648, with padding). *)

let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let encode s =
  let n = String.length s in
  let b = Buffer.create ((n + 2) / 3 * 4) in
  let get i = if i < n then Char.code s.[i] else 0 in
  let i = ref 0 in
  while !i < n do
    let x = (get !i lsl 16) lor (get (!i + 1) lsl 8) lor get (!i + 2) in
    Buffer.add_char b alphabet.[(x lsr 18) land 63];
    Buffer.add_char b alphabet.[(x lsr 12) land 63];
    Buffer.add_char b (if !i + 1 < n then alphabet.[(x lsr 6) land 63] else '=');
    Buffer.add_char b (if !i + 2 < n then alphabet.[x land 63] else '=');
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

let decode s =
  let n = String.length s in
  if n mod 4 <> 0 then None
  else begin
    let b = Buffer.create (n / 4 * 3) in
    let ok = ref true in
    let i = ref 0 in
    while !ok && !i < n do
      let pad = (if s.[!i + 3] = '=' then 1 else 0) + if s.[!i + 2] = '=' then 1 else 0 in
      if pad > 0 && !i + 4 <> n then ok := false
      else if pad = 2 && s.[!i + 3] <> '=' then ok := false
      else begin
        let v k = if k >= 4 - pad then Some 0 else value s.[!i + k] in
        match (v 0, v 1, v 2, v 3) with
        | Some a, Some b', Some c, Some d ->
            let x = (a lsl 18) lor (b' lsl 12) lor (c lsl 6) lor d in
            Buffer.add_char b (Char.chr ((x lsr 16) land 255));
            if pad < 2 then Buffer.add_char b (Char.chr ((x lsr 8) land 255));
            if pad < 1 then Buffer.add_char b (Char.chr (x land 255))
        | _ -> ok := false
      end;
      i := !i + 4
    done;
    if !ok then Some (Buffer.contents b) else None
  end
