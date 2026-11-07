(* SQL identifiers as written in policy documents.

   Unquoted names are folded to lower case (ASCII only, like Postgres);
   double-quoted names keep their case ("" inside quotes is a literal quote).
   Names are limited to 63 bytes (Postgres NAMEDATALEN - 1). *)

let max_len = 63

let is_start c =
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c = '_' || Char.code c >= 0x80

let is_cont c = is_start c || (c >= '0' && c <= '9') || c = '$'

(* Parse a dot-separated identifier path. *)
let parse_parts ?(lower_unquoted = true) (s : string) : (string list, string) result =
  let n = String.length s in
  let err m = Error (Printf.sprintf "invalid identifier %S: %s" s m) in
  let rec part i acc =
    if i >= n then err "empty name"
    else if s.[i] = '"' then begin
      let b = Buffer.create 16 in
      let rec q j =
        if j >= n then None
        else if s.[j] = '"' then
          if j + 1 < n && s.[j + 1] = '"' then begin
            Buffer.add_char b '"';
            q (j + 2)
          end
          else Some (j + 1)
        else begin
          Buffer.add_char b s.[j];
          q (j + 1)
        end
      in
      match q (i + 1) with
      | None -> err "unterminated quoted name"
      | Some j ->
          let name = Buffer.contents b in
          if name = "" then err "empty quoted name"
          else if String.length name > max_len then
            err (Printf.sprintf "name longer than %d bytes" max_len)
          else after j (name :: acc)
    end
    else if not (is_start s.[i]) then
      err (Printf.sprintf "unexpected character %C (quote names that need it)" s.[i])
    else begin
      let j = ref i in
      while !j < n && is_cont s.[!j] do
        incr j
      done;
      let raw = String.sub s i (!j - i) in
      if String.length raw > max_len then
        err (Printf.sprintf "name longer than %d bytes" max_len)
      else
        let name = if lower_unquoted then String.lowercase_ascii raw else raw in
        after !j (name :: acc)
    end
  and after i acc =
    if i >= n then Ok (List.rev acc)
    else if s.[i] = '.' then part (i + 1) acc
    else err (Printf.sprintf "unexpected character %C (quote names that need it)" s.[i])
  in
  part 0 []

let parse_one s =
  match parse_parts s with
  | Ok [ x ] -> Ok x
  | Ok _ -> Error (Printf.sprintf "invalid identifier %S: expected a single name" s)
  | Error e -> Error e

(* Render a stored name so that [parse_one] gives it back. *)
let render name =
  if name <> "" && parse_one name = Ok name then name
  else begin
    let b = Buffer.create (String.length name + 2) in
    Buffer.add_char b '"';
    String.iter
      (fun c -> if c = '"' then Buffer.add_string b "\"\"" else Buffer.add_char b c)
      name;
    Buffer.add_char b '"';
    Buffer.contents b
  end

let render_qualified schema name = render schema ^ "." ^ render name
