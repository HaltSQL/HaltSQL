(* Key paths used in error messages, e.g. [tables."app.orders".tenant_column]
   or [policies[0].path]. Stored reversed (innermost segment first). *)

type seg = Key of string | Idx of int
type t = seg list

let root : t = []
let key (p : t) k : t = Key k :: p
let idx (p : t) i : t = Idx i :: p
let parent : t -> t option = function [] -> None | _ :: p -> Some p

let bare_key k =
  k <> ""
  && String.for_all
       (fun c ->
         (c >= 'a' && c <= 'z')
         || (c >= 'A' && c <= 'Z')
         || (c >= '0' && c <= '9')
         || c = '_' || c = '-')
       k

let quote_key k =
  let b = Buffer.create (String.length k + 2) in
  Buffer.add_char b '"';
  String.iter
    (fun c ->
      match c with
      | '"' -> Buffer.add_string b "\\\""
      | '\\' -> Buffer.add_string b "\\\\"
      | '\n' -> Buffer.add_string b "\\n"
      | c -> Buffer.add_char b c)
    k;
  Buffer.add_char b '"';
  Buffer.contents b

let to_string (p : t) =
  let b = Buffer.create 32 in
  List.iter
    (function
      | Key k ->
          if Buffer.length b > 0 then Buffer.add_char b '.';
          Buffer.add_string b (if bare_key k then k else quote_key k)
      | Idx i -> Buffer.add_string b (Printf.sprintf "[%d]" i))
    (List.rev p);
  Buffer.contents b
