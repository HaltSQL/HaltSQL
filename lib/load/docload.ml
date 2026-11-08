(* Shared YAML/JSON reader. Parsing (and all safety limits) lives in
   [Docpos]; this module adds the public API and the printers. *)

type format = Docpos.format = Yaml | Json

let format_of_path = Docpos.format_of_path
let max_document_bytes = Docpos.max_document_bytes
let of_string ?file fmt s = Result.map fst (Docpos.parse ?file fmt s)
let of_file ?format file = Result.map fst (Docpos.parse_file ?format file)

(* ---------------------------------------------------------------------- *)
(* YAML printer: clean block style that round-trips through [of_string].   *)

let float_repr f =
  let s =
    let rec try_prec p =
      let s = Printf.sprintf "%.*g" p f in
      if p >= 17 || float_of_string s = f then s else try_prec (p + 1)
    in
    try_prec 15
  in
  if String.exists (fun c -> c = '.' || c = 'e' || c = 'n' || c = 'i') s then s
  else s ^ ".0"

let plain_safe_char c =
  (c >= 'a' && c <= 'z')
  || (c >= 'A' && c <= 'Z')
  || (c >= '0' && c <= '9')
  || c = '_' || c = '.' || c = '/' || c = '-' || c = ' ' || c = '$' || c = '+' || c = '('
  || c = ')' || c = '='

(* Words that YAML 1.1 readers (PyYAML, older tools) would retype; quoted so
   the output means the same thing everywhere. *)
let yaml11_words =
  [
    "y";
    "Y";
    "yes";
    "Yes";
    "YES";
    "n";
    "N";
    "no";
    "No";
    "NO";
    "on";
    "On";
    "ON";
    "off";
    "Off";
    "OFF";
  ]

(* A string may be written unquoted only if it uses a conservative character
   set, starts with a letter, '_', '/' or '$' (so nothing numeric-looking is
   ever plain), is not a YAML 1.1 boolean word, has no trailing space, and the
   core-schema resolver would read it back as that string. *)
let plain_ok s =
  s <> ""
  && String.length s <= 200
  && String.for_all plain_safe_char s
  && (match s.[0] with 'a' .. 'z' | 'A' .. 'Z' | '_' | '/' | '$' -> true | _ -> false)
  && (not (List.mem s yaml11_words))
  && s.[String.length s - 1] <> ' '
  && Docpos.resolve_plain s = Ok (`String s)

let quote_yaml b s =
  Buffer.add_char b '"';
  let n = String.length s in
  let i = ref 0 in
  while !i < n do
    let c = s.[!i] in
    (match c with
    | '"' -> Buffer.add_string b "\\\""
    | '\\' -> Buffer.add_string b "\\\\"
    | '\n' -> Buffer.add_string b "\\n"
    | '\t' -> Buffer.add_string b "\\t"
    | '\r' -> Buffer.add_string b "\\r"
    | c when Char.code c < 0x20 || Char.code c = 0x7f ->
        Buffer.add_string b (Printf.sprintf "\\u%04x" (Char.code c))
    | '\xc2' when !i + 1 < n && s.[!i + 1] = '\x85' ->
        Buffer.add_string b "\\u0085";
        incr i
    | '\xe2'
      when !i + 2 < n
           && s.[!i + 1] = '\x80'
           && (s.[!i + 2] = '\xa8' || s.[!i + 2] = '\xa9') ->
        Buffer.add_string b (if s.[!i + 2] = '\xa8' then "\\u2028" else "\\u2029");
        i := !i + 2
    | '\xef' when !i + 2 < n && s.[!i + 1] = '\xbb' && s.[!i + 2] = '\xbf' ->
        Buffer.add_string b "\\ufeff";
        i := !i + 2
    | c -> Buffer.add_char b c);
    incr i
  done;
  Buffer.add_char b '"'

let add_str b s = if plain_ok s then Buffer.add_string b s else quote_yaml b s

let add_scalar b (j : Yojson.Safe.t) =
  match j with
  | `Null -> Buffer.add_string b "null"
  | `Bool true -> Buffer.add_string b "true"
  | `Bool false -> Buffer.add_string b "false"
  | `Int i -> Buffer.add_string b (string_of_int i)
  | `Intlit s -> Buffer.add_string b s
  | `Float f -> Buffer.add_string b (float_repr f)
  | `String s -> add_str b s
  | `Assoc [] -> Buffer.add_string b "{}"
  | `List [] -> Buffer.add_string b "[]"
  | (`Assoc (_ :: _) | `List (_ :: _)) as j ->
      (* Not reached: callers check [is_scalar] first. JSON is valid YAML flow
         syntax, so this is still a correct (if less pretty) rendering. *)
      Buffer.add_string b (Yojson.Safe.to_string j)

let is_scalar = function `Assoc (_ :: _) | `List (_ :: _) -> false | _ -> true
let indent b n = Buffer.add_string b (String.make n ' ')

(* YAML implicit keys are limited to 1024 characters; longer keys use the
   explicit "? key" form. *)
let long_key k = String.length k > 512

let rec emit_value b ind (v : Yojson.Safe.t) =
  (* the cursor is right after "key:" or "-"; emits the rest *)
  if is_scalar v then begin
    Buffer.add_char b ' ';
    add_scalar b v;
    Buffer.add_char b '\n'
  end
  else begin
    Buffer.add_char b '\n';
    emit_block b (ind + 2) v
  end

and emit_block b ind (v : Yojson.Safe.t) =
  match v with
  | `Assoc kvs ->
      List.iter
        (fun (k, v) ->
          indent b ind;
          if long_key k then begin
            Buffer.add_string b "? ";
            quote_yaml b k;
            Buffer.add_char b '\n';
            indent b ind;
            Buffer.add_char b ':'
          end
          else begin
            add_str b k;
            Buffer.add_char b ':'
          end;
          emit_value b ind v)
        kvs
  | `List items ->
      List.iter
        (fun v ->
          indent b ind;
          if is_scalar v then begin
            Buffer.add_char b '-';
            emit_value b ind v
          end
          else begin
            (* "- first: x\n  second: y": render the child at ind+2 and put
               the dash where the first line's indentation was *)
            let sub = Buffer.create 256 in
            emit_block sub (ind + 2) v;
            Buffer.add_string b "- ";
            Buffer.add_string b (Buffer.sub sub (ind + 2) (Buffer.length sub - ind - 2))
          end)
        items
  | v ->
      indent b ind;
      add_scalar b v;
      Buffer.add_char b '\n'

let to_yaml (j : Yojson.Safe.t) =
  let b = Buffer.create 1024 in
  if is_scalar j then begin
    add_scalar b j;
    Buffer.add_char b '\n'
  end
  else emit_block b 0 j;
  Buffer.contents b

let to_string fmt j =
  match fmt with Json -> Yojson.Safe.pretty_to_string j ^ "\n" | Yaml -> to_yaml j
