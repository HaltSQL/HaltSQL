(* Replace every occurrence of [sub] in [s] by [by]. *)
let replace s sub by =
  let n = String.length s and m = String.length sub in
  let b = Buffer.create n in
  let rec go i =
    if i > n - m then Buffer.add_string b (String.sub s i (n - i))
    else if String.sub s i m = sub then begin
      Buffer.add_string b by;
      go (i + m)
    end
    else begin
      Buffer.add_char b s.[i];
      go (i + 1)
    end
  in
  if m = 0 then s
  else (
    go 0;
    Buffer.contents b)
