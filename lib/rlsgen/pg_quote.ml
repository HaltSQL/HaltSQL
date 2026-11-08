(* SQL quoting that matches PostgreSQL's quote_ident / quote_literal. *)

(* Every keyword of the PostgreSQL 17 grammar whose category is not
   UNRESERVED_KEYWORD (reserved, column-name and type/function-name keywords).
   Extracted from vendor/libpg_query/src/postgres/include/parser/kwlist.h; these
   are exactly the keywords quote_ident() quotes. *)
let quoted_keywords =
  [
    "all";
    "analyse";
    "analyze";
    "and";
    "any";
    "array";
    "as";
    "asc";
    "asymmetric";
    "authorization";
    "between";
    "bigint";
    "binary";
    "bit";
    "boolean";
    "both";
    "case";
    "cast";
    "char";
    "character";
    "check";
    "coalesce";
    "collate";
    "collation";
    "column";
    "concurrently";
    "constraint";
    "create";
    "cross";
    "current_catalog";
    "current_date";
    "current_role";
    "current_schema";
    "current_time";
    "current_timestamp";
    "current_user";
    "dec";
    "decimal";
    "default";
    "deferrable";
    "desc";
    "distinct";
    "do";
    "else";
    "end";
    "except";
    "exists";
    "extract";
    "false";
    "fetch";
    "float";
    "for";
    "foreign";
    "freeze";
    "from";
    "full";
    "grant";
    "greatest";
    "group";
    "grouping";
    "having";
    "ilike";
    "in";
    "initially";
    "inner";
    "inout";
    "int";
    "integer";
    "intersect";
    "interval";
    "into";
    "is";
    "isnull";
    "join";
    "json";
    "json_array";
    "json_arrayagg";
    "json_exists";
    "json_object";
    "json_objectagg";
    "json_query";
    "json_scalar";
    "json_serialize";
    "json_table";
    "json_value";
    "lateral";
    "leading";
    "least";
    "left";
    "like";
    "limit";
    "localtime";
    "localtimestamp";
    "merge_action";
    "national";
    "natural";
    "nchar";
    "none";
    "normalize";
    "not";
    "notnull";
    "null";
    "nullif";
    "numeric";
    "offset";
    "on";
    "only";
    "or";
    "order";
    "out";
    "outer";
    "overlaps";
    "overlay";
    "placing";
    "position";
    "precision";
    "primary";
    "real";
    "references";
    "returning";
    "right";
    "row";
    "select";
    "session_user";
    "setof";
    "similar";
    "smallint";
    "some";
    "substring";
    "symmetric";
    "system_user";
    "table";
    "tablesample";
    "then";
    "time";
    "timestamp";
    "to";
    "trailing";
    "treat";
    "trim";
    "true";
    "union";
    "unique";
    "user";
    "using";
    "values";
    "varchar";
    "variadic";
    "verbose";
    "when";
    "where";
    "window";
    "with";
    "xmlattributes";
    "xmlconcat";
    "xmlelement";
    "xmlexists";
    "xmlforest";
    "xmlnamespaces";
    "xmlparse";
    "xmlpi";
    "xmlroot";
    "xmlserialize";
    "xmltable";
  ]

let keyword_table =
  let h = Hashtbl.create 256 in
  List.iter (fun k -> Hashtbl.replace h k ()) quoted_keywords;
  h

let is_quoted_keyword s = Hashtbl.mem keyword_table s
let is_safe_start c = (c >= 'a' && c <= 'z') || c = '_'
let is_safe_cont c = is_safe_start c || (c >= '0' && c <= '9')

let needs_quotes s =
  s = ""
  || (not (is_safe_start s.[0]))
  || (not (String.for_all is_safe_cont s))
  || is_quoted_keyword s

let quote_ident s =
  if String.contains s '\000' then invalid_arg "Pg_quote.quote_ident: NUL byte";
  if not (needs_quotes s) then s
  else begin
    let b = Buffer.create (String.length s + 2) in
    Buffer.add_char b '"';
    String.iter
      (fun c -> if c = '"' then Buffer.add_string b "\"\"" else Buffer.add_char b c)
      s;
    Buffer.add_char b '"';
    Buffer.contents b
  end

let quote_qualified ~schema ~name = quote_ident schema ^ "." ^ quote_ident name

let quote_literal s =
  if String.contains s '\000' then invalid_arg "Pg_quote.quote_literal: NUL byte";
  let has_backslash = String.contains s '\\' in
  let b = Buffer.create (String.length s + 3) in
  if has_backslash then Buffer.add_char b 'E';
  Buffer.add_char b '\'';
  String.iter
    (fun c ->
      match c with
      | '\'' -> Buffer.add_string b "''"
      | '\\' -> Buffer.add_string b "\\\\"
      | c -> Buffer.add_char b c)
    s;
  Buffer.add_char b '\'';
  Buffer.contents b

let dollar_quote body =
  let rec pick i =
    let tag = if i = 0 then "$haltsql$" else Printf.sprintf "$haltsql%d$" i in
    let rec contains_at j =
      let lt = String.length tag and lb = String.length body in
      if j + lt > lb then false
      else if String.sub body j lt = tag then true
      else contains_at (j + 1)
    in
    if contains_at 0 then pick (i + 1) else tag
  in
  let tag = pick 0 in
  tag ^ body ^ tag
