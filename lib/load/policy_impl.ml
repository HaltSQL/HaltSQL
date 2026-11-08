(* Policy document decoding (internal; see [Policy_load] for the public API
   and PLAN.md §6.5 for the format). *)

open Haltsql_core

type json = Yojson.Safe.t

(* ---------------------------------------------------------------------- *)
(* Built-in allowlists                                                     *)

(* Curated, side-effect-free built-ins. Deliberately excluded everywhere:
   anything that sleeps, reads files, opens connections, touches large
   objects, sequences, settings, advisory locks, other backends, XML, random
   or generated values, and generate_series (resource exhaustion: opt in
   explicitly via functions.allow). [row_to_json] is excluded because it
   serializes whole rows. Regex functions live in their own "regex" preset
   because user-supplied patterns can be slow (ReDoS); enable it knowingly. *)
let function_presets : (string * string list) list =
  [
    ( "aggregates",
      [
        "count";
        "sum";
        "avg";
        "min";
        "max";
        "bool_and";
        "bool_or";
        "every";
        "string_agg";
        "array_agg";
        "stddev";
        "stddev_pop";
        "stddev_samp";
        "variance";
        "var_pop";
        "var_samp";
        "percentile_cont";
        "percentile_disc";
        "mode";
      ] );
    ( "math",
      [
        "abs";
        "ceil";
        "ceiling";
        "floor";
        "round";
        "trunc";
        "sign";
        "sqrt";
        "cbrt";
        "power";
        "mod";
        "div";
        "ln";
        "log";
        "log10";
        "exp";
        "pi";
        "degrees";
        "radians";
      ] );
    ( "string",
      [
        "lower";
        "upper";
        "length";
        "char_length";
        "character_length";
        "octet_length";
        "substring";
        "substr";
        "trim";
        "btrim";
        "ltrim";
        "rtrim";
        "replace";
        "concat";
        "concat_ws";
        "left";
        "right";
        "position";
        "strpos";
        "split_part";
        "starts_with";
        "initcap";
        "lpad";
        "rpad";
        "reverse";
        "translate";
      ] );
    ( "regex",
      [
        "regexp_replace";
        "regexp_match";
        "regexp_like";
        "regexp_count";
        "regexp_instr";
        "regexp_substr";
        "regexp_split_to_array";
      ] );
    ( "datetime",
      [
        "now";
        "date_trunc";
        "date_part";
        "extract";
        "date_bin";
        "age";
        "make_date";
        "make_time";
        "make_timestamp";
        "make_timestamptz";
        "make_interval";
        "to_char";
        "to_date";
        "to_timestamp";
        "timezone";
        "justify_days";
        "justify_hours";
        "justify_interval";
        "isfinite";
      ] );
    ( "json",
      [
        "jsonb_extract_path";
        "jsonb_extract_path_text";
        "json_extract_path";
        "json_extract_path_text";
        "jsonb_array_length";
        "json_array_length";
        "jsonb_typeof";
        "json_typeof";
        "jsonb_build_object";
        "json_build_object";
        "jsonb_build_array";
        "json_build_array";
        "jsonb_agg";
        "json_agg";
        "jsonb_object_agg";
        "json_object_agg";
        "to_jsonb";
        "to_json";
      ] );
    ("conditional", [ "num_nulls"; "num_nonnulls" ]);
    ( "window",
      [
        "row_number";
        "rank";
        "dense_rank";
        "percent_rank";
        "cume_dist";
        "ntile";
        "lag";
        "lead";
        "first_value";
        "last_value";
        "nth_value";
      ] );
  ]

let default_operators =
  [
    (* comparison *)
    "=";
    "<>";
    "!=";
    "<";
    ">";
    "<=";
    ">=";
    (* arithmetic (also date/interval arithmetic) *)
    "+";
    "-";
    "*";
    "/";
    "%";
    (* string concatenation *)
    "||";
    (* LIKE / ILIKE internals and POSIX regex *)
    "~~";
    "!~~";
    "~~*";
    "!~~*";
    "~";
    "~*";
    "!~";
    "!~*";
    (* JSON / JSONB *)
    "->";
    "->>";
    "#>";
    "#>>";
    "@>";
    "<@";
    "?";
    "?|";
    "?&";
    (* arrays (@> and <@ above) *)
    "&&";
  ]

let default_deny_casts =
  [
    "regclass";
    "regproc";
    "regprocedure";
    "regoper";
    "regoperator";
    "regtype";
    "regconfig";
    "regdictionary";
    "regnamespace";
    "regrole";
    "regcollation";
    "txid_snapshot";
  ]

(* ---------------------------------------------------------------------- *)

let top_keys =
  [
    "apiVersion";
    "kind";
    "metadata";
    "dialect";
    "search_path";
    "catalog";
    "limits";
    "statements";
    "require_limit";
    "tenancy";
    "tables";
    "functions";
    "operators";
    "deny_casts";
    "allow_explain";
    "mode";
  ]

let is_word_char c =
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c = '_'

let valid_word s =
  s <> ""
  && (match s.[0] with 'a' .. 'z' | 'A' .. 'Z' | '_' -> true | _ -> false)
  && String.for_all is_word_char s

let valid_name s =
  String.length s >= 1
  && String.length s <= 128
  && (match s.[0] with 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' -> true | _ -> false)
  && String.for_all (fun c -> is_word_char c || c = '-' || c = '.') s

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

(* "${ctx.<field>}" -> field *)
let ctx_field s =
  let n = String.length s in
  if n > 7 && String.sub s 0 6 = "${ctx." && s.[n - 1] = '}' then
    let f = String.sub s 6 (n - 7) in
    if valid_word f then Some f else None
  else None

(* Placeholders: only ${ctx.<field>} and only in tenancy.keys / tenancy.value. *)
let scan_placeholders ctx base (j : json) =
  let check path rel s =
    if contains s "${" then
      let allowed =
        match rel with
        | [ Lpath.Key "tenancy"; Lpath.Key "keys"; Lpath.Key _ ]
        | [ Lpath.Key "tenancy"; Lpath.Key "value" ] ->
            true
        | _ -> false
      in
      if contains s "${env:" || contains s "${file:" then
        Dec.error ctx path
          "${env:...} and ${file:...} placeholders are only allowed in Config documents, \
           never in policies"
      else if not allowed then
        Dec.error ctx path
          "placeholders (${ctx.<field>}) are only allowed in tenancy.keys"
  in
  let rec walk path rel = function
    | `String s -> check path (List.rev rel) s
    | `List l -> List.iteri (fun i x -> walk (Lpath.idx path i) (Lpath.Idx i :: rel) x) l
    | `Assoc kvs ->
        List.iter
          (fun (k, v) ->
            let p = Lpath.key path k in
            if contains k "${" then check p [ Lpath.Key "<key>" ] k;
            walk p (Lpath.Key k :: rel) v)
          kvs
    | _ -> ()
  in
  walk base [] j

let ident ctx path s =
  match Ident.parse_one s with
  | Ok x -> Some x
  | Error e ->
      Dec.error ctx path e;
      None

let ident_j ctx path j = Option.bind (Dec.string ctx path j) (ident ctx path)

(* Column list: "*" or a non-empty list of identifiers without duplicates. *)
let columns_j ctx path (j : json) : Policy.columns option =
  match j with
  | `String "*" -> Some Policy.All
  | `String s ->
      Dec.error ctx path
        (Printf.sprintf "expected \"*\" or a list of column names, found %S" s);
      None
  | `List [] ->
      Dec.error ctx path "must not be empty (use \"*\" for all columns)";
      None
  | `List l ->
      let seen = Hashtbl.create 16 in
      let cols =
        List.filter_map Fun.id
          (List.mapi
             (fun i x ->
               let p = Lpath.idx path i in
               match ident_j ctx p x with
               | Some c when Hashtbl.mem seen c ->
                   Dec.error ctx p (Printf.sprintf "duplicate column %S" c);
                   None
               | Some c ->
                   Hashtbl.add seen c ();
                   Some c
               | None -> None)
             l)
      in
      Some (Policy.Only cols)
  | j ->
      Dec.type_error ctx path "\"*\" or a list of column names" j;
      None

let limits_j ctx path j : Policy.limits =
  let d = Policy.default_limits in
  match
    Dec.obj ctx path ~keys:[ "max_bytes"; "max_depth"; "max_nodes"; "max_joins" ] j
  with
  | None -> d
  | Some kvs ->
      let get k ~min ~max def =
        Option.value
          (Dec.opt kvs path k (fun p v -> Dec.int ctx p ~min ~max v))
          ~default:def
      in
      {
        max_bytes = get "max_bytes" ~min:1 ~max:(16 * 1024 * 1024) d.max_bytes;
        max_depth = get "max_depth" ~min:1 ~max:1000 d.max_depth;
        max_nodes = get "max_nodes" ~min:1 ~max:10_000_000 d.max_nodes;
        max_joins = get "max_joins" ~min:0 ~max:256 d.max_joins;
      }

let stmt_values =
  [
    ("select", Policy.Select);
    ("insert", Policy.Insert);
    ("update", Policy.Update);
    ("delete", Policy.Delete);
  ]

let statements_j ctx path j =
  match Dec.obj ctx path ~keys:[ "allow" ] j with
  | None -> None
  | Some kvs -> (
      match
        Dec.req ctx kvs path "allow" (fun p v ->
            Dec.list_of ctx p (fun p x -> Dec.enum ctx p ~values:stmt_values x) v)
      with
      | None -> None
      | Some [] ->
          Dec.error ctx (Lpath.key path "allow") "must not be empty";
          None
      | Some l ->
          Some
            (List.filter
               (fun k -> List.mem k l)
               [ Policy.Select; Insert; Update; Delete ]))

let tenancy_j ctx path j : Policy.tenancy =
  let empty = { Policy.mode = Bound; keys = [] } in
  match Dec.obj ctx path ~keys:[ "mode"; "keys"; "value" ] j with
  | None -> empty
  | Some kvs ->
      let mode =
        Option.value ~default:Policy.Bound
          (Dec.opt kvs path "mode" (fun p v ->
               Dec.enum ctx p
                 ~values:[ ("bound", Policy.Bound); ("literal", Policy.Literal) ]
                 v))
      in
      let field_of p v =
        match Dec.string ctx p v with
        | None -> None
        | Some s -> (
            match ctx_field s with
            | Some f -> Some f
            | None ->
                Dec.error ctx p
                  (Printf.sprintf
                     "expected a context placeholder like \"${ctx.tenant_id}\", found %S"
                     s);
                None)
      in
      let keys =
        Dec.opt kvs path "keys" (fun p v ->
            match Dec.map ctx p v with
            | None -> None
            | Some l ->
                if l = [] then Dec.error ctx p "must not be empty";
                Some
                  (List.filter_map
                     (fun (k, v) ->
                       let kp = Lpath.key p k in
                       if not (valid_word k) then begin
                         Dec.error ctx kp
                           (Printf.sprintf
                              "invalid tenancy key name %S (use letters, digits and _)" k);
                         None
                       end
                       else Option.map (fun f -> (k, f)) (field_of kp v))
                     l))
      in
      let value = Dec.opt kvs path "value" field_of in
      let keys =
        match (keys, value) with
        | Some _, Some _ ->
            Dec.error ctx (Lpath.key path "value")
              "use either tenancy.value or tenancy.keys, not both";
            []
        | Some ks, None -> ks
        | None, Some f -> [ ("tenant", f) ]
        | None, None -> []
      in
      { mode; keys = List.sort (fun (a, _) (b, _) -> compare a b) keys }

let fn_name ctx path s =
  match Ident.parse_parts s with
  | Ok parts when String.contains s '"' ->
      ignore parts;
      Dec.error ctx path (Printf.sprintf "function names must not be quoted: %S" s);
      None
  | Ok [ f ] -> Some f
  | Ok [ sch; f ] -> Some (sch ^ "." ^ f)
  | Ok _ ->
      Dec.error ctx path
        (Printf.sprintf "invalid function name %S (use name or schema.name)" s);
      None
  | Error e ->
      Dec.error ctx path e;
      None

let functions_j ctx path j =
  match Dec.obj ctx path ~keys:[ "allow"; "presets" ] j with
  | None -> []
  | Some kvs ->
      let allow =
        Option.value ~default:[]
          (Dec.opt kvs path "allow" (fun p v ->
               Dec.list_of ctx p
                 (fun p x -> Option.bind (Dec.string ctx p x) (fn_name ctx p))
                 v))
      in
      let presets =
        Option.value ~default:[]
          (Dec.opt kvs path "presets" (fun p v ->
               Dec.list_of ctx p
                 (fun p x ->
                   match Dec.string ctx p x with
                   | None -> None
                   | Some name -> (
                       match List.assoc_opt name function_presets with
                       | Some fs -> Some fs
                       | None ->
                           Dec.error ctx p
                             (Printf.sprintf "unknown function preset %S (available: %s)"
                                name
                                (String.concat ", " (List.map fst function_presets)));
                           None))
                 v))
      in
      List.sort_uniq compare (allow @ List.concat presets)

let operator_chars = "+-*/<>=~!@#%^&|`?"

let operator ctx path j =
  match Dec.string ctx path j with
  | None -> None
  | Some s ->
      if
        s = ""
        || String.length s > 63
        || not (String.for_all (fun c -> String.contains operator_chars c) s)
      then begin
        Dec.error ctx path (Printf.sprintf "invalid operator %S" s);
        None
      end
      else Some s

let operators_j ctx path j =
  match Dec.obj ctx path ~keys:[ "allow"; "extend" ] j with
  | None -> default_operators
  | Some kvs ->
      let lst k = Dec.opt kvs path k (fun p v -> Dec.list_of ctx p (operator ctx) v) in
      let base = Option.value (lst "allow") ~default:default_operators in
      let ext = Option.value (lst "extend") ~default:[] in
      base @ ext

let cast_type ctx path j =
  match Dec.string ctx path j with
  | None -> None
  | Some s ->
      let t = String.lowercase_ascii (String.trim s) in
      let ok =
        t <> ""
        && (match t.[0] with 'a' .. 'z' | '_' -> true | _ -> false)
        && String.for_all (fun c -> is_word_char c || c = ' ') t
      in
      if ok then Some t
      else begin
        Dec.error ctx path (Printf.sprintf "invalid type name %S" s);
        None
      end

let deny_casts_j ctx path (j : json) =
  match j with
  | `List _ -> Option.value ~default:[] (Dec.list_of ctx path (cast_type ctx) j)
  | `Assoc _ -> (
      match Dec.obj ctx path ~keys:[ "extend" ] j with
      | None -> default_deny_casts
      | Some kvs ->
          default_deny_casts
          @ Option.value ~default:[]
              (Dec.opt kvs path "extend" (fun p v -> Dec.list_of ctx p (cast_type ctx) v))
      )
  | j ->
      Dec.type_error ctx path "a list of type names or {extend: [...]}" j;
      default_deny_casts

(* A table entry before cross-validation. *)
type raw_table = { rt : Policy.table; rpath : Lpath.t }

let writes_j ctx path statements j : Policy.writes =
  match Dec.obj ctx path ~keys:[ "insert"; "update"; "delete" ] j with
  | None -> Policy.no_writes
  | Some kvs ->
      let need kind k enabled =
        if enabled && not (List.mem kind statements) then
          Dec.error ctx (Lpath.key path k)
            (Printf.sprintf "writes.%s is enabled but %S is not in statements.allow" k
               (Policy.stmt_kind_to_string kind))
      in
      let insert =
        Option.value ~default:false (Dec.opt kvs path "insert" (Dec.bool ctx))
      in
      let delete =
        Option.value ~default:false (Dec.opt kvs path "delete" (Dec.bool ctx))
      in
      let update =
        match Dec.field kvs "update" with
        | None | Some (`Bool false) -> None
        | Some (`Bool true) ->
            Dec.error ctx (Lpath.key path "update")
              "use \"*\" or a list of updatable columns instead of true";
            None
        | Some v -> columns_j ctx (Lpath.key path "update") v
      in
      need Policy.Insert "insert" insert;
      need Policy.Update "update" (update <> None);
      need Policy.Delete "delete" delete;
      { insert; update; delete }

let table_j ctx path ~search_path ~(tenancy : Policy.tenancy) ~statements key j :
    raw_table option =
  let names =
    match Ident.parse_parts key with
    | Ok [ n ] -> (
        match search_path with
        | s :: _ -> Some (s, n)
        | [] ->
            (* Not reached: [decode] never passes an empty search path. *)
            Dec.error ctx path
              (Printf.sprintf "table %S needs a schema: the search_path is empty" key);
            None)
    | Ok [ s; n ] -> Some (s, n)
    | Ok _ ->
        Dec.error ctx path
          (Printf.sprintf "table %S must be written as \"table\" or \"schema.table\"" key);
        None
    | Error e ->
        Dec.error ctx path e;
        None
  in
  match
    Dec.obj ctx path ~keys:[ "columns"; "tenant_column"; "tenant_columns"; "writes" ] j
  with
  | None -> None
  | Some kvs -> (
      let columns = Dec.req ctx kvs path "columns" (columns_j ctx) in
      let key_names = List.map fst tenancy.keys in
      let single =
        Dec.opt kvs path "tenant_column" (fun p v ->
            match ident_j ctx p v with
            | None -> None
            | Some col -> (
                match key_names with
                | [ k ] -> Some [ (col, k) ]
                | [] ->
                    Dec.error ctx p
                      "tenant_column needs a tenancy key: define tenancy.keys (or \
                       tenancy.value)";
                    None
                | ks ->
                    Dec.error ctx p
                      (Printf.sprintf
                         "tenancy defines several keys (%s); use tenant_columns: \
                          {column: key} instead"
                         (String.concat ", " ks));
                    None))
      in
      let multi =
        Dec.opt kvs path "tenant_columns" (fun p v ->
            match Dec.map ctx p v with
            | None -> None
            | Some l ->
                let seen = Hashtbl.create 4 in
                Some
                  (List.filter_map
                     (fun (c, kj) ->
                       let cp = Lpath.key p c in
                       match (ident ctx cp c, Dec.string ctx cp kj) with
                       | Some col, Some k ->
                           if Hashtbl.mem seen col then begin
                             Dec.error ctx cp
                               (Printf.sprintf "duplicate tenant column %S" col);
                             None
                           end
                           else if not (List.mem k key_names) then begin
                             Dec.error ctx cp
                               (Printf.sprintf "unknown tenancy key %S (defined: %s)" k
                                  (if key_names = [] then "none"
                                   else String.concat ", " key_names));
                             None
                           end
                           else begin
                             Hashtbl.add seen col ();
                             Some (col, k)
                           end
                       | _ -> None)
                     l))
      in
      let tenant_columns =
        match (single, multi) with
        | Some _, Some _ ->
            Dec.error ctx
              (Lpath.key path "tenant_columns")
              "use either tenant_column or tenant_columns, not both";
            []
        | Some l, None | None, Some l -> l
        | None, None -> []
      in
      let tenant_columns = List.sort compare tenant_columns in
      (match columns with
      | Some (Policy.Only cols) ->
          List.iter
            (fun (c, _) ->
              if not (List.mem c cols) then
                Dec.error ctx
                  (Lpath.key path
                     (if single <> None then "tenant_column" else "tenant_columns"))
                  (Printf.sprintf "tenant column %S must be listed in columns" c))
            tenant_columns
      | _ -> ());
      let writes =
        Option.value ~default:Policy.no_writes
          (Dec.opt kvs path "writes" (fun p v -> Some (writes_j ctx p statements v)))
      in
      (match writes.update with
      | Some (Policy.Only ucols) ->
          List.iter
            (fun (c, _) ->
              if List.mem c ucols then
                Dec.error ctx
                  (Lpath.key (Lpath.key path "writes") "update")
                  (Printf.sprintf "tenant column %S must not be updatable" c))
            tenant_columns
      | _ -> ());
      match (names, columns) with
      | Some (schema, name), Some columns ->
          Some
            {
              rt = { Policy.schema; name; columns; tenant_columns; writes };
              rpath = path;
            }
      | _ -> None)

let check_against_catalog ctx (cat : Catalog.t) (rts : raw_table list) =
  List.iter
    (fun { rt = t; rpath } ->
      match Catalog.find cat ~schema:t.schema ~name:t.name with
      | None ->
          Dec.error ctx rpath
            (Printf.sprintf "table %s is not in the catalog snapshot"
               (Ident.render_qualified t.schema t.name))
      | Some ct -> (
          let known = Catalog.column_names ct in
          let check where cols =
            List.iter
              (fun c ->
                if not (List.mem c known) then
                  Dec.error ctx (Lpath.key rpath where)
                    (Printf.sprintf
                       "column %S does not exist in %s according to the catalog" c
                       (Ident.render_qualified t.schema t.name)))
              cols
          in
          (match t.columns with Only cols -> check "columns" cols | All -> ());
          check
            (if List.length t.tenant_columns = 1 then "tenant_column"
             else "tenant_columns")
            (List.map fst t.tenant_columns);
          match t.writes.update with Some (Only cols) -> check "writes" cols | _ -> ()))
    rts

(* ---------------------------------------------------------------------- *)
(* Normalized JSON and version                                             *)

let columns_to_json = function
  | Policy.All -> `String "*"
  | Only cols -> `List (List.map (fun c -> `String (Ident.render c)) cols)

let to_json (p : Policy.t) : json =
  let opt k = function Some v -> [ (k, `String v) ] | None -> [] in
  let strs l = `List (List.map (fun s -> `String s) l) in
  let catalog =
    if p.catalog = Catalog.empty then []
    else [ ("catalog", Catalog_impl.to_json p.catalog) ]
  in
  `Assoc
    ([
       ("apiVersion", `String p.api_version);
       ("kind", `String "Policy");
       ( "metadata",
         `Assoc
           ((("name", `String p.name) :: opt "owner" p.owner)
           @ opt "description" p.description) );
       ("dialect", `String p.dialect);
       ("search_path", `List (List.map (fun s -> `String (Ident.render s)) p.search_path));
     ]
    @ catalog
    @ [
        ( "limits",
          `Assoc
            [
              ("max_bytes", `Int p.limits.max_bytes);
              ("max_depth", `Int p.limits.max_depth);
              ("max_nodes", `Int p.limits.max_nodes);
              ("max_joins", `Int p.limits.max_joins);
            ] );
        ( "statements",
          `Assoc [ ("allow", strs (List.map Policy.stmt_kind_to_string p.statements)) ] );
      ]
    @ (match p.require_limit with
      | Some m -> [ ("require_limit", `Assoc [ ("max", `Int m) ]) ]
      | None -> [])
    @ [
        ( "tenancy",
          `Assoc
            [
              ( "mode",
                `String
                  (match p.tenancy.mode with Bound -> "bound" | Literal -> "literal") );
              ( "keys",
                `Assoc
                  (List.map
                     (fun (k, f) -> (k, `String ("${ctx." ^ f ^ "}")))
                     p.tenancy.keys) );
            ] );
        ( "tables",
          `Assoc
            (List.map
               (fun (t : Policy.table) ->
                 ( Ident.render_qualified t.schema t.name,
                   `Assoc
                     [
                       ("columns", columns_to_json t.columns);
                       ( "tenant_columns",
                         `Assoc
                           (List.map
                              (fun (c, k) -> (Ident.render c, `String k))
                              t.tenant_columns) );
                       ( "writes",
                         `Assoc
                           [
                             ("insert", `Bool t.writes.insert);
                             ( "update",
                               match t.writes.update with
                               | None -> `Bool false
                               | Some c -> columns_to_json c );
                             ("delete", `Bool t.writes.delete);
                           ] );
                     ] ))
               p.tables) );
        ("functions", `Assoc [ ("allow", strs p.functions) ]);
        ("operators", `Assoc [ ("allow", strs p.operators) ]);
        ("deny_casts", strs p.deny_casts);
        ("allow_explain", `Bool p.allow_explain);
        ("mode", `String (match p.mode with Enforce -> "enforce" | Shadow -> "shadow"));
      ])

let rec sort_keys (j : json) : json =
  match j with
  | `Assoc kvs ->
      `Assoc
        (List.stable_sort
           (fun (a, _) (b, _) -> String.compare a b)
           (List.map (fun (k, v) -> (k, sort_keys v)) kvs))
  | `List l -> `List (List.map sort_keys l)
  | j -> j

let canonical_string p = Yojson.Safe.to_string (sort_keys (to_json p))

let compute_version p =
  "sha256:" ^ Digestif.SHA256.(to_hex (digest_string (canonical_string p)))

(* ---------------------------------------------------------------------- *)
(* Main decoder                                                            *)

let valid_dialect s =
  s = "postgres"
  || String.length s = 11
     && String.sub s 0 9 = "postgres-"
     && Docpos.is_digit s.[9]
     && Docpos.is_digit s.[10]

let decode ctx ?base_dir ?(inline = false) path (j : json) : Policy.t option =
  match Dec.obj ctx path ~keys:top_keys j with
  | None -> None
  | Some kvs -> (
      scan_placeholders ctx path j;
      Dec.header ctx ~required:(not inline) kvs path ~kind:"Policy";
      let meta =
        Dec.req ctx kvs path "metadata" (fun p v ->
            match Dec.obj ctx p ~keys:[ "name"; "owner"; "description" ] v with
            | None -> None
            | Some m ->
                let name =
                  Dec.req ctx m p "name" (fun p v ->
                      match Dec.string ctx p v with
                      | Some n when valid_name n -> Some n
                      | Some n ->
                          Dec.error ctx p
                            (Printf.sprintf
                               "invalid policy name %S (1-128 characters: letters, \
                                digits, '.', '_', '-'; must start with a letter or \
                                digit)"
                               n);
                          None
                      | None -> None)
                in
                let owner = Dec.opt m p "owner" (Dec.string ctx) in
                let description = Dec.opt m p "description" (Dec.string ctx) in
                Option.map (fun n -> (n, owner, description)) name)
      in
      let dialect =
        Option.value ~default:"postgres"
          (Dec.opt kvs path "dialect" (fun p v ->
               match Dec.string ctx p v with
               | Some d when valid_dialect d -> Some d
               | Some d ->
                   Dec.error ctx p
                     (Printf.sprintf
                        "unsupported dialect %S (expected \"postgres\" or \
                         \"postgres-NN\", e.g. \"postgres-17\")"
                        d);
                   None
               | None -> None))
      in
      let search_path =
        match
          Dec.opt kvs path "search_path" (fun p v ->
              match Dec.list_of ctx p (fun p x -> ident_j ctx p x) v with
              | Some [] ->
                  Dec.error ctx p "must not be empty";
                  None
              | Some l ->
                  if List.length (Dec.dedup l) <> List.length l then
                    Dec.error ctx p "contains duplicate schemas";
                  Some l
              | None -> None)
        with
        | Some l -> l
        | None -> [ "public" ]
      in
      let limits =
        Option.value ~default:Policy.default_limits
          (Dec.opt kvs path "limits" (fun p v -> Some (limits_j ctx p v)))
      in
      let statements =
        Option.value ~default:[ Policy.Select ]
          (Dec.opt kvs path "statements" (statements_j ctx))
      in
      let require_limit =
        Dec.opt kvs path "require_limit" (fun p v ->
            match Dec.obj ctx p ~keys:[ "max" ] v with
            | None -> None
            | Some m ->
                Dec.req ctx m p "max" (fun p v -> Dec.int ctx p ~min:1 ~max:100_000_000 v))
      in
      let tenancy =
        Option.value
          ~default:{ Policy.mode = Bound; keys = [] }
          (Dec.opt kvs path "tenancy" (fun p v -> Some (tenancy_j ctx p v)))
      in
      let snapshot =
        Dec.opt kvs path "catalog" (fun p v ->
            match v with
            | `String "" ->
                Dec.error ctx p "must not be empty";
                None
            | `String file -> (
                let abs = Dec.absolute ?base_dir file in
                match Catalog_impl.of_file abs with
                | Ok c -> Some c
                | Error errs ->
                    Dec.error ctx p (Printf.sprintf "cannot load catalog snapshot %S" abs);
                    Dec.add_errors ctx errs;
                    None)
            | `Assoc _ -> Catalog_impl.decode ctx p v
            | v ->
                Dec.type_error ctx p "a path to a catalog snapshot or an inline snapshot"
                  v;
                None)
      in
      let raw_tables =
        Option.value ~default:[]
          (Dec.opt kvs path "tables" (fun p v ->
               match Dec.map ctx p v with
               | None -> None
               | Some l ->
                   Some
                     (List.filter_map
                        (fun (k, tj) ->
                          table_j ctx (Lpath.key p k) ~search_path ~tenancy ~statements k
                            tj)
                        l)))
      in
      (* duplicates after normalization, e.g. "orders" and "public.orders" *)
      let seen = Hashtbl.create 16 in
      List.iter
        (fun { rt; rpath } ->
          let k = (rt.Policy.schema, rt.name) in
          if Hashtbl.mem seen k then
            Dec.error ctx rpath
              (Printf.sprintf "table %s is defined more than once"
                 (Ident.render_qualified rt.schema rt.name))
          else Hashtbl.add seen k ())
        raw_tables;
      let functions =
        Option.value ~default:[]
          (Dec.opt kvs path "functions" (fun p v -> Some (functions_j ctx p v)))
      in
      let operators =
        Option.value ~default:default_operators
          (Dec.opt kvs path "operators" (fun p v -> Some (operators_j ctx p v)))
      in
      let deny_casts =
        Option.value ~default:default_deny_casts
          (Dec.opt kvs path "deny_casts" (fun p v -> Some (deny_casts_j ctx p v)))
      in
      let allow_explain =
        Option.value ~default:false (Dec.opt kvs path "allow_explain" (Dec.bool ctx))
      in
      let mode =
        Option.value ~default:Policy.Enforce
          (Dec.opt kvs path "mode" (fun p v ->
               Dec.enum ctx p
                 ~values:[ ("enforce", Policy.Enforce); ("shadow", Policy.Shadow) ]
                 v))
      in
      let tables =
        List.stable_sort
          (fun (a : Policy.table) (b : Policy.table) ->
            compare (a.schema, a.name) (b.schema, b.name))
          (List.map (fun r -> r.rt) raw_tables)
      in
      let catalog =
        match snapshot with
        | Some c ->
            check_against_catalog ctx c raw_tables;
            c
        | None ->
            (* No snapshot: the catalog stays EMPTY. Never derive it from the
               allowed-column lists — the real table may have more columns, and
               consumers treat catalog entries as complete column lists (a
               derived entry would make SELECT * look safe). *)
            Catalog.empty
      in
      match meta with
      | Some (name, owner, description) when not (Dec.has_errors ctx) ->
          let p =
            {
              Policy.api_version = "haltsql.dev/v1";
              name;
              owner;
              description;
              dialect;
              search_path;
              limits;
              statements;
              require_limit;
              tenancy;
              tables;
              functions;
              operators = List.sort_uniq compare operators;
              deny_casts = List.sort_uniq compare deny_casts;
              allow_explain;
              mode;
              catalog;
              version = "";
            }
          in
          Some { p with version = compute_version p }
      | _ -> None)

let of_json ?file ?base_dir ?positions j =
  let ctx = Dec.create ?file ?positions () in
  let base_dir = Dec.base_dir_of ?base_dir file in
  match decode ctx ?base_dir Lpath.root j with
  | Some p when not (Dec.has_errors ctx) -> Ok p
  | _ -> Error (Dec.errors ctx)

let of_string ?file ?base_dir fmt s =
  match Docpos.parse ?file fmt s with
  | Error e -> Error e
  | Ok (j, positions) -> of_json ?file ?base_dir ~positions j

let of_file file =
  match Docpos.parse_file file with
  | Error e -> Error e
  | Ok (j, positions) -> of_json ~file ~base_dir:(Filename.dirname file) ~positions j
