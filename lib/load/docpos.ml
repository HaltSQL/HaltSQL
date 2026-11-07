(* Position-tracking YAML/JSON reader. Internal to haltsql.load; the public
   entry point is [Docload]. Produces a [Yojson.Safe.t] tree plus a table
   mapping rendered key paths (see [Lpath]) to 1-based source positions, so
   decoders can report [file:line:col: path: message].

   YAML is read from the libyaml event stream (via the [yaml] package) and
   typed with the YAML 1.2 core schema, with these deliberate choices:
   - only plain (unquoted) scalars are typed; quoted, literal and folded
     scalars are always strings;
   - null: [~], [null], [Null], [NULL] and the empty scalar;
   - bool: [true]/[True]/[TRUE]/[false]/[False]/[FALSE] only ([yes], [no],
     [on], [off], [y], [n] stay strings — no "Norway problem");
   - int: [[-+]?[0-9]+], [0o[0-7]+], [0x[0-9a-fA-F]+]. Decimal numbers with a
     leading zero ([012], [-007]) are kept as STRINGS rather than read as 12:
     they are almost always identifiers (zip codes, account numbers) and YAML
     1.1 tools would read them as octal, so neither reading is safe;
   - float: core-schema floats ([1.5], [-2e3], [.5]); [.inf]/[.nan] are
     rejected because they cannot be represented in JSON;
   - every explicit tag ([!!str], [!custom], ...) is rejected;
   - aliases are expanded, but at most [max_alias_nodes] nodes in total may be
     produced by alias expansion (billion-laughs protection);
   - a stream must contain at most one document; nesting is limited to
     [max_depth]; input is limited to [max_document_bytes]. *)

open Haltsql_core

type json = Yojson.Safe.t
type pos = { line : int; column : int }
type positions = (string, pos) Hashtbl.t
type format = Yaml | Json

let max_document_bytes = 4 * 1024 * 1024
let max_depth = 64
let max_alias_nodes = 10_000

exception Fail of Load_error.t

let fail ?file ?pos ?(path = Lpath.root) msg =
  let line, column =
    match pos with Some p -> (Some p.line, Some p.column) | None -> (None, None)
  in
  raise (Fail (Load_error.make ?file ?line ?column ~path:(Lpath.to_string path) msg))

(* ---------------------------------------------------------------------- *)
(* YAML 1.2 core-schema scalar resolution                                  *)

let is_digit c = c >= '0' && c <= '9'
let is_hex c = is_digit c || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
let is_oct c = c >= '0' && c <= '7'

let all_from s i f =
  let n = String.length s in
  let rec go j = j >= n || (f s.[j] && go (j + 1)) in
  i < n && go i

(* Number of significant digits after stripping leading zeros. *)
let significant s i =
  let n = String.length s in
  let j = ref i in
  while !j < n && s.[!j] = '0' do
    incr j
  done;
  n - !j

(* Matches the core-schema float grammar; [None] if [s] is not a float. The
   integer part must not have a leading zero (see header comment). *)
let float_syntax s =
  let n = String.length s in
  let i = ref 0 in
  if !i < n && (s.[!i] = '+' || s.[!i] = '-') then incr i;
  let int_start = !i in
  while !i < n && is_digit s.[!i] do
    incr i
  done;
  let int_len = !i - int_start in
  let frac_len = ref (-1) in
  if !i < n && s.[!i] = '.' then begin
    incr i;
    let fs = !i in
    while !i < n && is_digit s.[!i] do
      incr i
    done;
    frac_len := !i - fs
  end;
  let mantissa_ok =
    (int_len > 0 || !frac_len > 0) && not (int_len > 1 && s.[int_start] = '0')
  in
  let exp_ok =
    if !i < n && (s.[!i] = 'e' || s.[!i] = 'E') then begin
      incr i;
      if !i < n && (s.[!i] = '+' || s.[!i] = '-') then incr i;
      let es = !i in
      while !i < n && is_digit s.[!i] do
        incr i
      done;
      !i > es
    end
    else true
  in
  mantissa_ok && exp_ok && !i = n

let resolve_plain (s : string) : (json, string) result =
  match s with
  | "" | "~" | "null" | "Null" | "NULL" -> Ok `Null
  | "true" | "True" | "TRUE" -> Ok (`Bool true)
  | "false" | "False" | "FALSE" -> Ok (`Bool false)
  | ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" | "-.inf" | "-.Inf" | "-.INF"
  | ".nan" | ".NaN" | ".NAN" ->
      Error
        (Printf.sprintf "%s cannot be represented in JSON; quote it to use a string" s)
  | _ ->
      let n = String.length s in
      if n > 2 && s.[0] = '0' && s.[1] = 'x' && all_from s 2 is_hex then
        if significant s 2 > 15 then Error ("integer out of range: " ^ s)
        else Ok (`Int (int_of_string s))
      else if n > 2 && s.[0] = '0' && s.[1] = 'o' && all_from s 2 is_oct then
        if significant s 2 > 20 then Error ("integer out of range: " ^ s)
        else Ok (`Int (int_of_string s))
      else
        let sign = if n > 0 && (s.[0] = '+' || s.[0] = '-') then 1 else 0 in
        if all_from s sign is_digit then
          if n - sign > 1 && s.[sign] = '0' then Ok (`String s)
          else
            match int_of_string_opt s with
            | Some i -> Ok (`Int i)
            | None ->
                let lit = if s.[0] = '+' then String.sub s 1 (n - 1) else s in
                Ok (`Intlit lit)
        else if float_syntax s then
          match float_of_string_opt s with
          | Some f when Float.is_finite f -> Ok (`Float f)
          | _ -> Error ("number out of range: " ^ s)
        else Ok (`String s)

(* ---------------------------------------------------------------------- *)
(* YAML                                                                    *)

module E = Yaml.Stream.Event

type yst = {
  yp : Yaml.Stream.parser;
  yfile : string option;
  ypos : positions;
  anchors : (string, json * int) Hashtbl.t;
  mutable alias_nodes : int;
  mutable last : pos;
}

let pos_of_mark (m : Yaml.Stream.Mark.t) = { line = m.line + 1; column = m.column + 1 }

let clean_yaml_msg m =
  let strip_prefix p s =
    let lp = String.length p in
    if String.length s >= lp && String.sub s 0 lp = p then
      String.sub s lp (String.length s - lp)
    else s
  in
  let m = strip_prefix "error calling parser: " m in
  (* ocaml-yaml appends " character N position N returned: N" *)
  let rec find i =
    if i < 0 then m
    else if i + 11 <= String.length m && String.sub m i 11 = " character " then
      String.sub m 0 i
    else find (i - 1)
  in
  find (String.length m - 1)

let ynext st =
  match Yaml.Stream.do_parse st.yp with
  | Ok (ev, p) ->
      let start = pos_of_mark p.start_mark in
      st.last <- pos_of_mark p.end_mark;
      (ev, start)
  | Error (`Msg m) ->
      fail ?file:st.yfile ~pos:st.last ("YAML syntax error near here: " ^ clean_yaml_msg m)

let check_tag st path p = function
  | None -> ()
  | Some t ->
      fail ?file:st.yfile ~pos:p ~path
        (Printf.sprintf "YAML tags are not allowed (found %s); remove the tag" t)

let register st anchor v n =
  match anchor with Some a -> Hashtbl.replace st.anchors a (v, n) | None -> ()

let rec ynode st path depth ((ev : E.t), (p : pos)) : json * int =
  match ev with
  | Scalar sc ->
      check_tag st path p sc.tag;
      let v =
        match sc.style with
        | `Plain | `Any -> (
            match resolve_plain sc.value with
            | Ok v -> v
            | Error m -> fail ?file:st.yfile ~pos:p ~path m)
        | `Single_quoted | `Double_quoted | `Literal | `Folded -> `String sc.value
      in
      register st sc.anchor v 1;
      (v, 1)
  | Alias { anchor } -> (
      match Hashtbl.find_opt st.anchors anchor with
      | None -> fail ?file:st.yfile ~pos:p ~path ("undefined YAML alias *" ^ anchor)
      | Some (v, n) ->
          st.alias_nodes <- st.alias_nodes + n;
          if st.alias_nodes > max_alias_nodes then
            fail ?file:st.yfile ~pos:p ~path
              (Printf.sprintf
                 "YAML alias expansion exceeds %d nodes (possible billion-laughs attack)"
                 max_alias_nodes);
          (v, n))
  | Sequence_start { anchor; tag; _ } ->
      check_tag st path p tag;
      if depth + 1 > max_depth then
        fail ?file:st.yfile ~pos:p ~path
          (Printf.sprintf "nesting deeper than %d levels" max_depth);
      let rec items i acc cnt =
        let ((ev, ip) as e) = ynext st in
        match ev with
        | Sequence_end -> (List.rev acc, cnt)
        | _ ->
            let ipath = Lpath.idx path i in
            Hashtbl.replace st.ypos (Lpath.to_string ipath) ip;
            let v, n = ynode st ipath (depth + 1) e in
            items (i + 1) (v :: acc) (cnt + n)
      in
      let l, cnt = items 0 [] 1 in
      let v = `List l in
      register st anchor v cnt;
      (v, cnt)
  | Mapping_start { anchor; tag; _ } ->
      check_tag st path p tag;
      if depth + 1 > max_depth then
        fail ?file:st.yfile ~pos:p ~path
          (Printf.sprintf "nesting deeper than %d levels" max_depth);
      let seen = Hashtbl.create 8 in
      let rec members acc cnt =
        let ev, kp = ynext st in
        match ev with
        | Mapping_end -> (List.rev acc, cnt)
        | Scalar sc ->
            check_tag st path kp sc.tag;
            let k = sc.value in
            let kpath = Lpath.key path k in
            (match Hashtbl.find_opt seen k with
            | Some (first : pos) ->
                fail ?file:st.yfile ~pos:kp ~path:kpath
                  (Printf.sprintf "duplicate key %S (first defined at line %d, column %d)"
                     k first.line first.column)
            | None -> Hashtbl.add seen k kp);
            Hashtbl.replace st.ypos (Lpath.to_string kpath) kp;
            let v, n = ynode st kpath (depth + 1) (ynext st) in
            members ((k, v) :: acc) (cnt + n + 1)
        | Alias _ ->
            fail ?file:st.yfile ~pos:kp ~path "aliases cannot be used as mapping keys"
        | _ -> fail ?file:st.yfile ~pos:kp ~path "mapping keys must be scalars"
      in
      let kvs, cnt = members [] 1 in
      let v = `Assoc kvs in
      register st anchor v cnt;
      (v, cnt)
  | _ -> fail ?file:st.yfile ~pos:p ~path "unexpected YAML event"

let parse_yaml ?file (s : string) : json * positions =
  let positions = Hashtbl.create 64 in
  match Yaml.Stream.parser s with
  | Error (`Msg m) -> fail ?file ("cannot initialise YAML parser: " ^ m)
  | Ok yp -> (
      let st =
        {
          yp;
          yfile = file;
          ypos = positions;
          anchors = Hashtbl.create 8;
          alias_nodes = 0;
          last = { line = 1; column = 1 };
        }
      in
      (match ynext st with
      | Stream_start _, _ -> ()
      | _ -> fail ?file "malformed YAML stream");
      match ynext st with
      | Stream_end, _ -> (`Null, positions)
      | Document_start _, _ -> (
          let ((_, rp) as e) = ynext st in
          Hashtbl.replace positions "" rp;
          let v, _ = ynode st Lpath.root 0 e in
          (match ynext st with
          | Document_end _, _ -> ()
          | _, p -> fail ?file ~pos:p "malformed YAML document");
          match ynext st with
          | Stream_end, _ -> (v, positions)
          | Document_start _, p ->
              fail ?file ~pos:p "multiple YAML documents in one file are not allowed"
          | _, p -> fail ?file ~pos:p "unexpected content after the YAML document")
      | _, p -> fail ?file ~pos:p "malformed YAML stream")

(* ---------------------------------------------------------------------- *)
(* JSON (strict RFC 8259, with positions and duplicate-key detection)      *)

type jst = {
  s : string;
  mutable i : int;
  mutable line : int;
  mutable bol : int; (* index of the first byte of the current line *)
  jfile : string option;
  jpos : positions;
}

let jpos_here st = { line = st.line; column = st.i - st.bol + 1 }
let jfail st ?path msg = fail ?file:st.jfile ~pos:(jpos_here st) ?path msg

let rec skip_ws st =
  if st.i < String.length st.s then
    match st.s.[st.i] with
    | ' ' | '\t' | '\r' ->
        st.i <- st.i + 1;
        skip_ws st
    | '\n' ->
        st.i <- st.i + 1;
        st.line <- st.line + 1;
        st.bol <- st.i;
        skip_ws st
    | _ -> ()

let peek st = if st.i < String.length st.s then Some st.s.[st.i] else None

let describe = function
  | None -> "end of input"
  | Some c when c >= ' ' && c <= '~' -> Printf.sprintf "'%c'" c
  | Some c -> Printf.sprintf "byte 0x%02x" (Char.code c)

let add_utf8 b cp =
  if cp < 0x80 then Buffer.add_char b (Char.chr cp)
  else if cp < 0x800 then begin
    Buffer.add_char b (Char.chr (0xC0 lor (cp lsr 6)));
    Buffer.add_char b (Char.chr (0x80 lor (cp land 0x3F)))
  end
  else if cp < 0x10000 then begin
    Buffer.add_char b (Char.chr (0xE0 lor (cp lsr 12)));
    Buffer.add_char b (Char.chr (0x80 lor ((cp lsr 6) land 0x3F)));
    Buffer.add_char b (Char.chr (0x80 lor (cp land 0x3F)))
  end
  else begin
    Buffer.add_char b (Char.chr (0xF0 lor (cp lsr 18)));
    Buffer.add_char b (Char.chr (0x80 lor ((cp lsr 12) land 0x3F)));
    Buffer.add_char b (Char.chr (0x80 lor ((cp lsr 6) land 0x3F)));
    Buffer.add_char b (Char.chr (0x80 lor (cp land 0x3F)))
  end

let hex4 st =
  if st.i + 4 > String.length st.s then jfail st "truncated \\u escape";
  let v = ref 0 in
  for k = 0 to 3 do
    let c = st.s.[st.i + k] in
    let d =
      if is_digit c then Char.code c - 48
      else if c >= 'a' && c <= 'f' then Char.code c - 87
      else if c >= 'A' && c <= 'F' then Char.code c - 55
      else jfail st "invalid \\u escape"
    in
    v := (!v * 16) + d
  done;
  st.i <- st.i + 4;
  !v

let jstring st =
  (* at opening quote *)
  st.i <- st.i + 1;
  let b = Buffer.create 16 in
  let rec loop () =
    match peek st with
    | None -> jfail st "unterminated string"
    | Some '"' -> st.i <- st.i + 1
    | Some '\\' ->
        st.i <- st.i + 1;
        (match peek st with
        | Some '"' ->
            Buffer.add_char b '"';
            st.i <- st.i + 1
        | Some '\\' ->
            Buffer.add_char b '\\';
            st.i <- st.i + 1
        | Some '/' ->
            Buffer.add_char b '/';
            st.i <- st.i + 1
        | Some 'b' ->
            Buffer.add_char b '\b';
            st.i <- st.i + 1
        | Some 'f' ->
            Buffer.add_char b '\012';
            st.i <- st.i + 1
        | Some 'n' ->
            Buffer.add_char b '\n';
            st.i <- st.i + 1
        | Some 'r' ->
            Buffer.add_char b '\r';
            st.i <- st.i + 1
        | Some 't' ->
            Buffer.add_char b '\t';
            st.i <- st.i + 1
        | Some 'u' ->
            st.i <- st.i + 1;
            let cp = hex4 st in
            if cp >= 0xD800 && cp <= 0xDBFF then
              begin if
                st.i + 1 < String.length st.s
                && st.s.[st.i] = '\\'
                && st.s.[st.i + 1] = 'u'
              then begin
                st.i <- st.i + 2;
                let lo = hex4 st in
                if lo >= 0xDC00 && lo <= 0xDFFF then
                  add_utf8 b (0x10000 + ((cp - 0xD800) lsl 10) + (lo - 0xDC00))
                else jfail st "invalid UTF-16 surrogate pair"
              end
              else jfail st "lone UTF-16 surrogate in \\u escape"
              end
            else if cp >= 0xDC00 && cp <= 0xDFFF then
              jfail st "lone UTF-16 surrogate in \\u escape"
            else add_utf8 b cp
        | c -> jfail st ("invalid escape sequence \\" ^ describe c));
        loop ()
    | Some c when Char.code c < 0x20 ->
        jfail st "control character in string (must be escaped)"
    | Some c ->
        Buffer.add_char b c;
        st.i <- st.i + 1;
        loop ()
  in
  loop ();
  Buffer.contents b

let jnumber st =
  let start = st.i in
  let n = String.length st.s in
  let digits () =
    let s0 = st.i in
    while st.i < n && is_digit st.s.[st.i] do
      st.i <- st.i + 1
    done;
    st.i - s0
  in
  if peek st = Some '-' then st.i <- st.i + 1;
  (match peek st with
  | Some '0' -> st.i <- st.i + 1
  | Some c when is_digit c -> ignore (digits ())
  | c -> jfail st ("invalid number: unexpected " ^ describe c));
  let is_float = ref false in
  if peek st = Some '.' then begin
    st.i <- st.i + 1;
    is_float := true;
    if digits () = 0 then jfail st "invalid number: expected digits after '.'"
  end;
  (match peek st with
  | Some ('e' | 'E') ->
      st.i <- st.i + 1;
      is_float := true;
      (match peek st with Some ('+' | '-') -> st.i <- st.i + 1 | _ -> ());
      if digits () = 0 then jfail st "invalid number: expected exponent digits"
  | _ -> ());
  (match peek st with
  | Some c when is_digit c -> jfail st "invalid number: leading zeros are not allowed"
  | _ -> ());
  let lit = String.sub st.s start (st.i - start) in
  if !is_float then
    match float_of_string_opt lit with
    | Some f when Float.is_finite f -> `Float f
    | _ -> jfail st ("number out of range: " ^ lit)
  else match int_of_string_opt lit with Some i -> `Int i | None -> `Intlit lit

let expect_lit st lit v =
  let l = String.length lit in
  if st.i + l <= String.length st.s && String.sub st.s st.i l = lit then begin
    st.i <- st.i + l;
    v
  end
  else jfail st ("unexpected " ^ describe (peek st))

let rec jvalue st path depth : json =
  skip_ws st;
  match peek st with
  | Some '{' ->
      if depth + 1 > max_depth then
        jfail st ~path (Printf.sprintf "nesting deeper than %d levels" max_depth);
      st.i <- st.i + 1;
      skip_ws st;
      if peek st = Some '}' then begin
        st.i <- st.i + 1;
        `Assoc []
      end
      else begin
        let seen = Hashtbl.create 8 in
        let rec members acc =
          skip_ws st;
          if peek st <> Some '"' then
            jfail st ~path ("expected a string key, found " ^ describe (peek st));
          let kp = jpos_here st in
          let k = jstring st in
          let kpath = Lpath.key path k in
          (match Hashtbl.find_opt seen k with
          | Some (first : pos) ->
              fail ?file:st.jfile ~pos:kp ~path:kpath
                (Printf.sprintf "duplicate key %S (first defined at line %d, column %d)" k
                   first.line first.column)
          | None -> Hashtbl.add seen k kp);
          Hashtbl.replace st.jpos (Lpath.to_string kpath) kp;
          skip_ws st;
          if peek st <> Some ':' then
            jfail st ~path:kpath ("expected ':', found " ^ describe (peek st));
          st.i <- st.i + 1;
          let v = jvalue st kpath (depth + 1) in
          skip_ws st;
          match peek st with
          | Some ',' ->
              st.i <- st.i + 1;
              members ((k, v) :: acc)
          | Some '}' ->
              st.i <- st.i + 1;
              `Assoc (List.rev ((k, v) :: acc))
          | c -> jfail st ~path ("expected ',' or '}', found " ^ describe c)
        in
        members []
      end
  | Some '[' ->
      if depth + 1 > max_depth then
        jfail st ~path (Printf.sprintf "nesting deeper than %d levels" max_depth);
      st.i <- st.i + 1;
      skip_ws st;
      if peek st = Some ']' then begin
        st.i <- st.i + 1;
        `List []
      end
      else begin
        let rec items i acc =
          skip_ws st;
          let ipath = Lpath.idx path i in
          Hashtbl.replace st.jpos (Lpath.to_string ipath) (jpos_here st);
          let v = jvalue st ipath (depth + 1) in
          skip_ws st;
          match peek st with
          | Some ',' ->
              st.i <- st.i + 1;
              items (i + 1) (v :: acc)
          | Some ']' ->
              st.i <- st.i + 1;
              `List (List.rev (v :: acc))
          | c -> jfail st ~path ("expected ',' or ']', found " ^ describe c)
        in
        items 0 []
      end
  | Some '"' -> `String (jstring st)
  | Some 't' -> expect_lit st "true" (`Bool true)
  | Some 'f' -> expect_lit st "false" (`Bool false)
  | Some 'n' -> expect_lit st "null" `Null
  | Some ('-' | '0' .. '9') -> jnumber st
  | c -> jfail st ~path ("unexpected " ^ describe c)

(* Returns the index of the first invalid UTF-8 sequence, if any. *)
let invalid_utf8 s =
  let n = String.length s in
  let cont k = k < n && Char.code s.[k] land 0xC0 = 0x80 in
  let rec go i =
    if i >= n then None
    else
      let c = Char.code s.[i] in
      if c < 0x80 then go (i + 1)
      else if c >= 0xC2 && c <= 0xDF && cont (i + 1) then go (i + 2)
      else if c >= 0xE0 && c <= 0xEF && cont (i + 1) && cont (i + 2) then
        let c1 = Char.code s.[i + 1] in
        if (c = 0xE0 && c1 < 0xA0) || (c = 0xED && c1 >= 0xA0) then Some i else go (i + 3)
      else if c >= 0xF0 && c <= 0xF4 && cont (i + 1) && cont (i + 2) && cont (i + 3) then
        let c1 = Char.code s.[i + 1] in
        if (c = 0xF0 && c1 < 0x90) || (c = 0xF4 && c1 >= 0x90) then Some i else go (i + 4)
      else Some i
  in
  go 0

let parse_json ?file (s : string) : json * positions =
  let positions = Hashtbl.create 64 in
  let st = { s; i = 0; line = 1; bol = 0; jfile = file; jpos = positions } in
  if String.length s >= 3 && String.sub s 0 3 = "\xef\xbb\xbf" then begin
    st.i <- 3;
    st.bol <- 3
  end;
  (match invalid_utf8 s with
  | Some k ->
      let line = ref 1 and bol = ref 0 in
      for j = 0 to k - 1 do
        if s.[j] = '\n' then begin
          incr line;
          bol := j + 1
        end
      done;
      fail ?file ~pos:{ line = !line; column = k - !bol + 1 } "invalid UTF-8"
  | None -> ());
  skip_ws st;
  if st.i >= String.length s then jfail st "empty JSON document";
  Hashtbl.replace positions "" (jpos_here st);
  let v = jvalue st Lpath.root 0 in
  skip_ws st;
  if st.i < String.length s then
    jfail st ("unexpected content after the JSON value: " ^ describe (peek st));
  (v, positions)

let parse ?file (fmt : format) (s : string) : (json * positions, Load_error.t list) result
    =
  if String.length s > max_document_bytes then
    Error
      [
        Load_error.make ?file
          (Printf.sprintf "document is %d bytes; the limit is %d bytes" (String.length s)
             max_document_bytes);
      ]
  else
    try match fmt with Yaml -> Ok (parse_yaml ?file s) | Json -> Ok (parse_json ?file s)
    with Fail e -> Error [ e ]

let read_file ?(limit = max_document_bytes) file : (string, Load_error.t list) result =
  match open_in_bin file with
  | exception Sys_error m -> Error [ Load_error.make ~file ("cannot read file: " ^ m) ]
  | ic -> (
      Fun.protect ~finally:(fun () -> close_in_noerr ic) @@ fun () ->
      match in_channel_length ic with
      | exception Sys_error m ->
          Error [ Load_error.make ~file ("cannot read file: " ^ m) ]
      | len when len > limit ->
          Error
            [
              Load_error.make ~file
                (Printf.sprintf "file is %d bytes; the limit is %d bytes" len limit);
            ]
      | len -> (
          match really_input_string ic len with
          | s -> Ok s
          | exception (Sys_error m | Failure m) ->
              Error [ Load_error.make ~file ("cannot read file: " ^ m) ]
          | exception End_of_file ->
              Error [ Load_error.make ~file "cannot read file: truncated" ]))

let format_of_path p =
  let p = String.lowercase_ascii p in
  if Filename.check_suffix p ".json" then Some Json
  else if Filename.check_suffix p ".yaml" || Filename.check_suffix p ".yml" then Some Yaml
  else None

let parse_file ?format file : (json * positions, Load_error.t list) result =
  match match format with Some f -> Some f | None -> format_of_path file with
  | None ->
      Error
        [
          Load_error.make ~file
            "cannot detect the document format: use a .yaml, .yml or .json extension";
        ]
  | Some fmt -> Result.bind (read_file file) (parse ~file fmt)
