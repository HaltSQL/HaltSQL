(* Conservative policy suggestions; see suggest.mli for the rules. *)

open Haltsql_core
module Ident = Haltsql_load.Ident

type change =
  | Add_column of { schema : string; table : string; column : string }
  | Add_function of string
  | Set_limit_max of { current : int; proposed : int }
  | Add_table of {
      schema : string;
      table : string;
      columns : string list;
      tenant_columns : (string * string) list;
    }

type evidence = {
  records : int;
  denied : int;
  shadow_denied : int;
  callers : (string * int) list;
  queries : int;
}

type suggestion = {
  id : string;
  policy : string;
  code : string;
  change : change;
  evidence : evidence;
  summary : string;
  yaml : string;
  notes : string list;
  applicable : bool;
}

type category = Pii | Unsafe | Query_fix | Never_weaken | Already_allowed | Needs_review

type item = {
  i_policy : string;
  i_code : string;
  target : string;
  category : category;
  reason : string;
  i_evidence : evidence;
}

type code_row = {
  c_code : string;
  c_category : category;
  c_records : int;
  advice : string;
}

type t = {
  suggestions : suggestion list;
  pii_flagged : item list;
  not_suggested : item list;
  codes : code_row list;
  missing_detail : int;
}

type config = {
  policies : (string * Policy.t) list;
  pii : Pii.lookup;
  verify : (Policy.t -> Context.t -> string -> Verdict.t) option;
  min_records : int;
  limit_factor : int;
  limit_ceiling : int;
}

let default_config =
  {
    policies = [];
    pii = Pii.none;
    verify = None;
    min_records = 1;
    limit_factor = 10;
    limit_ceiling = 100_000;
  }

let category_to_string = function
  | Pii -> "pii"
  | Unsafe -> "unsafe"
  | Query_fix -> "query_fix"
  | Never_weaken -> "never_weaken"
  | Already_allowed -> "already_allowed"
  | Needs_review -> "needs_review"

(* ---- code classification (exhaustive: a new code must be classified here) ---- *)

let classify (c : Reason.code) =
  match c with
  | E_COLUMN_DENIED | E_FUNCTION_DENIED | E_LIMIT_TOO_HIGH | E_TABLE_DENIED -> None
  | E_TENANT_MISSING | E_TENANT_MISMATCH | E_TENANT_WRITE | E_CONTEXT_MISSING ->
      Some Never_weaken
  | E_WRITE_DENIED | E_STATEMENT_KIND | E_DATA_MODIFYING_CTE | E_SELECT_INTO
  | E_LOCKING_CLAUSE | E_EXTERNAL_POLICY ->
      Some Never_weaken
  | E_PARSE | E_EMPTY | E_MULTI_STATEMENT | E_LIMIT | E_COLUMN_UNRESOLVED
  | E_OPERATOR_DENIED | E_CAST_DENIED | E_PARAM_UNBOUND | E_LIMIT_REQUIRED | E_JOIN_BUDGET
  | E_UNSUPPORTED | E_INTERNAL ->
      Some Query_fix

let code_advice (c : Reason.code) =
  match c with
  | E_COLUMN_DENIED -> "add the column to the table's columns, unless it is sensitive"
  | E_FUNCTION_DENIED -> "add the function to functions.allow, if it is side-effect free"
  | E_LIMIT_TOO_HIGH -> "raise require_limit.max, or make the query use a smaller LIMIT"
  | E_TABLE_DENIED -> "add the table to tables, with its tenancy"
  | E_TENANT_MISSING ->
      "tenant isolation is never relaxed: the query must carry a tenant predicate on \
       every tenant-scoped table"
  | E_TENANT_MISMATCH ->
      "tenant isolation is never relaxed: the tenant literal must equal the caller's \
       context value"
  | E_TENANT_WRITE -> "tenant isolation is never relaxed: fix the write's tenant columns"
  | E_CONTEXT_MISSING ->
      "the caller must send the tenancy context value; the policy is not changed"
  | E_WRITE_DENIED -> "writes are never suggested; grant them deliberately by hand"
  | E_STATEMENT_KIND -> "statement kinds are never suggested; the agent must not run it"
  | E_DATA_MODIFYING_CTE -> "writes are never suggested (data-modifying CTE)"
  | E_SELECT_INTO -> "SELECT ... INTO creates a table: never suggested"
  | E_LOCKING_CLAUSE -> "FOR UPDATE / FOR SHARE takes row locks: never suggested"
  | E_PARSE -> "needs a query fix: the SQL does not parse"
  | E_EMPTY -> "needs a query fix: no statement"
  | E_MULTI_STATEMENT -> "needs a query fix: send one statement per request"
  | E_LIMIT -> "needs a query fix: the query exceeds the size/depth/node limits"
  | E_COLUMN_UNRESOLVED -> "needs a query fix: qualify or correct the column names"
  | E_OPERATOR_DENIED ->
      "needs a query fix: rewrite without the operator (operators are not suggested)"
  | E_CAST_DENIED -> "needs a query fix: remove the cast to the denied type"
  | E_PARAM_UNBOUND -> "needs a query fix: bind the $n parameters (prepared statement)"
  | E_LIMIT_REQUIRED -> "needs a query fix: add a constant LIMIT to the outermost SELECT"
  | E_JOIN_BUDGET -> "needs a query fix: fewer joins, or a join condition"
  | E_UNSUPPORTED -> "needs a query fix: syntax HaltSQL does not analyze"
  | E_INTERNAL -> "analyzer error: please report it; nothing to change in the policy"
  | E_EXTERNAL_POLICY ->
      "denied by the external policy engine (OPA): change the OPA policy, not the \
       HaltSQL policy"

(* ---- safety filters ---- *)

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let unsafe_exact =
  [
    "set_config";
    "current_setting";
    "nextval";
    "setval";
    "currval";
    "lastval";
    "row_to_json";
    "to_json";
    "to_jsonb";
    "json_agg";
    "jsonb_agg";
    "version";
    "ts_stat";
    "ts_rewrite";
    "plainto_tsquery";
    "phraseto_tsquery";
    "websearch_to_tsquery";
    "brin_summarize_new_values";
    "brin_summarize_range";
    "brin_desummarize_range";
    "gin_clean_pending_list";
    "setseed";
    "getpgusername";
    "xpath";
    "xpath_exists";
    "xmlparse";
    "xmltable";
    "xmlelement";
    "xmlforest";
    "xmlagg";
    "generate_series";
    "generate_subscripts";
    "col_description";
    "obj_description";
    "shobj_description";
    "format_type";
    "aclexplode";
    "acldefault";
    "dblink";
    "lo_import";
    "lo_export";
    "lo_get";
    "lo_put";
    "lo_from_bytea";
    "lo_unlink";
    "query_to_xml";
    "txid_current";
    "gen_random_bytes";
    "inet_client_addr";
    "inet_server_addr";
    "inet_client_port";
    "inet_server_port";
  ]

let unsafe_prefixes =
  [
    "pg_";
    "lo_";
    "dblink";
    "txid_";
    "set_";
    "current_";
    "session_";
    "has_";
    "inet_";
    "to_reg";
    "query_to_";
    "table_to_";
    "schema_to_";
    "database_to_";
    "cursor_to_";
  ]

let unsafe_function f =
  let f = String.lowercase_ascii f in
  let base =
    if starts_with ~prefix:"pg_catalog." f then String.sub f 11 (String.length f - 11)
    else f
  in
  if String.contains base '.' then
    Some
      "schema-qualified (user-defined) function: review its definition (side effects, \
       SECURITY DEFINER, dynamic SQL) and add it by hand"
  else if
    List.mem base unsafe_exact
    || List.exists (fun p -> starts_with ~prefix:p base) unsafe_prefixes
  then Some "function with side effects, dynamic SQL or access to server state"
  else None

let system_schema s =
  let s = String.lowercase_ascii s in
  s = "information_schema" || starts_with ~prefix:"pg_" s

(* ---- YAML rendering ---- *)

let yaml_reserved = [ "null"; "true"; "false"; "yes"; "no"; "on"; "off"; "y"; "n"; "~" ]

let yaml_scalar s =
  let plain =
    s <> ""
    && (match s.[0] with 'a' .. 'z' | 'A' .. 'Z' | '_' -> true | _ -> false)
    && String.for_all
         (fun c ->
           match c with
           | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '.' | '$' -> true
           | _ -> false)
         s
    && not (List.mem (String.lowercase_ascii s) yaml_reserved)
  in
  if plain then s else Yojson.Safe.to_string (`String s)

let flow_list l = "[" ^ String.concat ", " (List.map yaml_scalar l) ^ "]"
let qualified schema name = Ident.render_qualified schema name

(* ---- evidence ---- *)

type acc = { mutable recs : Record.t list }

let evidence_of (recs : Record.t list) =
  let callers = Hashtbl.create 4 and fps = Hashtbl.create 8 in
  let denied = ref 0 and shadow = ref 0 in
  List.iter
    (fun (r : Record.t) ->
      (match r.outcome with
      | Denied -> incr denied
      | Shadow_denied -> incr shadow
      | Allowed -> ());
      Hashtbl.replace callers r.caller
        (1 + Option.value (Hashtbl.find_opt callers r.caller) ~default:0);
      Hashtbl.replace fps (Record.fingerprint_key r) ())
    recs;
  {
    records = List.length recs;
    denied = !denied;
    shadow_denied = !shadow;
    callers =
      Hashtbl.fold (fun k v acc -> (k, v) :: acc) callers []
      |> List.sort (fun (a, n) (b, m) ->
          match compare m n with 0 -> compare a b | c -> c);
    queries = Hashtbl.length fps;
  }

let evidence_to_json e : Yojson.Safe.t =
  `Assoc
    [
      ("records", `Int e.records);
      ("denied", `Int e.denied);
      ("shadow_denied", `Int e.shadow_denied);
      ("distinct_queries", `Int e.queries);
      ( "callers",
        `List
          (List.map
             (fun (c, n) -> `Assoc [ ("caller", `String c); ("count", `Int n) ])
             e.callers) );
    ]

let phrase e =
  let kind =
    if e.denied = 0 then "shadow-denied"
    else if e.shadow_denied = 0 then "denied"
    else "denied or shadow-denied"
  in
  let q = if e.records = 1 then "query" else "queries" in
  let callers =
    match e.callers with
    | [] -> ""
    | [ (c, _) ] -> " by caller " ^ c
    | l ->
        let shown = List.filteri (fun i _ -> i < 3) l |> List.map fst in
        let more = List.length l - List.length shown in
        " by callers " ^ String.concat ", " shown
        ^ if more > 0 then Printf.sprintf " (+%d more)" more else ""
  in
  Printf.sprintf "%d %s %s%s" e.records kind q callers

(* ---- probing for the columns of a table not yet in the policy ---- *)

let probe_value = "__haltsql_report_probe__"

let probe_context (p : Policy.t) =
  Context.make
    (List.map (fun (_, field) -> (field, Context.One probe_value)) p.tenancy.keys)

let new_table_tenancy (p : Policy.t) ~schema ~name =
  if p.tenancy.keys = [] then Ok []
  else
    let scoped =
      List.filter_map
        (fun (t : Policy.table) ->
          if t.tenant_columns = [] then None
          else Some (List.sort compare t.tenant_columns))
        p.tables
      |> List.sort_uniq compare
    in
    match scoped with
    | [ tc ] -> (
        match Catalog.find p.catalog ~schema ~name with
        | Some ct ->
            let cols = Catalog.column_names ct in
            let missing = List.filter (fun (c, _) -> not (List.mem c cols)) tc in
            if missing = [] then Ok tc
            else
              Error
                (Printf.sprintf
                   "the catalog lists %s without the tenant column(s) %s; decide by hand \
                    whether it is a global table"
                   (qualified schema name)
                   (String.concat ", " (List.map fst missing)))
        | None -> Ok tc)
    | [] ->
        Error
          "the policy has tenancy keys but no tenant-scoped table to copy the tenant \
           column from; decide the table's tenancy by hand"
    | _ ->
        Error
          "the policy's tenant-scoped tables use different tenant columns; decide the \
           new table's tenancy by hand"

(* Columns of [schema.name] read by [sql] under [p] with the table added. *)
let probe_columns verify (p : Policy.t) ~schema ~name ~tenant_columns sql =
  let tb =
    {
      Policy.schema;
      name;
      columns = Policy.All;
      tenant_columns;
      writes = Policy.no_writes;
    }
  in
  let p' = { p with tables = p.tables @ [ tb ] } in
  let v : Verdict.t = verify p' (probe_context p) sql in
  let prefix = schema ^ "." ^ name ^ "." in
  List.filter_map
    (fun c ->
      if starts_with ~prefix c then
        Some
          (String.sub c (String.length prefix) (String.length c - String.length prefix))
      else None)
    v.columns

(* ---- the main computation ---- *)

type key =
  | K_column of string * string  (** table as printed, column *)
  | K_star of string
  | K_function of string
  | K_sql_value of string
  | K_table of string option * string
  | K_system of string
  | K_limit
  | K_limit_nonconst

let code_of_string s = Reason.code_of_string s
let fixable s = match code_of_string s with Some c -> classify c = None | None -> false

let compute (cfg : config) (records : Record.t list) =
  let bad =
    List.filter
      (fun (r : Record.t) ->
        match r.outcome with Denied | Shadow_denied -> true | Allowed -> false)
      records
  in
  (* (policy, key) -> records (each record at most once per key); max LIMIT per policy *)
  let groups : (string * key, acc) Hashtbl.t = Hashtbl.create 64 in
  let order = ref [] in
  let max_limit : (string, int) Hashtbl.t = Hashtbl.create 4 in
  let missing = ref 0 in
  let code_counts : (string, int) Hashtbl.t = Hashtbl.create 16 in
  List.iter
    (fun (r : Record.t) ->
      List.iter
        (fun c ->
          if not (fixable c) then
            Hashtbl.replace code_counts c
              (1 + Option.value (Hashtbl.find_opt code_counts c) ~default:0))
        r.codes;
      let usable = List.filter (fun (d : Record.reason) -> fixable d.code) r.details in
      if usable = [] && List.exists fixable r.codes then incr missing;
      let seen = ref [] in
      List.iter
        (fun (d : Record.reason) ->
          let key =
            match Finding.of_reason d with
            | Finding.Column { table; column } -> Some (K_column (table, column))
            | Finding.Column_star t -> Some (K_star t)
            | Finding.Function f -> Some (K_function f)
            | Finding.Sql_value_function f -> Some (K_sql_value f)
            | Finding.Table { schema = Some s; name } -> Some (K_table (Some s, name))
            | Finding.Table { schema = None; name } -> (
                (* unqualified: the schema the policy would qualify it with *)
                match List.assoc_opt r.policy cfg.policies with
                | Some { Policy.search_path = s :: _; _ }
                  when not (starts_with ~prefix:"pg_" name) ->
                    Some (K_table (Some s, name))
                | Some _ | None -> Some (K_table (None, name)))
            | Finding.System_relation n -> Some (K_system n)
            | Finding.Limit_value n ->
                let cur = Option.value (Hashtbl.find_opt max_limit r.policy) ~default:0 in
                Hashtbl.replace max_limit r.policy (max cur n);
                Some K_limit
            | Finding.Limit_non_constant -> Some K_limit_nonconst
            | Finding.Unrecognized -> None
          in
          match key with
          | Some k when not (List.mem k !seen) -> (
              seen := k :: !seen;
              let gk = (r.policy, k) in
              match Hashtbl.find_opt groups gk with
              | Some a -> a.recs <- r :: a.recs
              | None ->
                  Hashtbl.replace groups gk { recs = [ r ] };
                  order := (gk, d.code) :: !order)
          | Some _ | None -> ())
        usable)
    bad;
  let suggestions = ref [] and flagged = ref [] and items = ref [] in
  let item ~policy ~code ~target ~category ~reason ev =
    let it =
      { i_policy = policy; i_code = code; target; category; reason; i_evidence = ev }
    in
    match category with Pii -> flagged := it :: !flagged | _ -> items := it :: !items
  in
  let suggest ~id ~policy ~code ~change ~ev ~summary ~yaml ~notes ~applicable =
    suggestions :=
      { id; policy; code; change; evidence = ev; summary; yaml; notes; applicable }
      :: !suggestions
  in
  let not_loaded policy =
    Printf.sprintf "policy %s is not loaded (pass it with --policy-file)" policy
  in
  List.iter
    (fun ((policy, key), code) ->
      let recs = (Hashtbl.find groups (policy, key)).recs in
      let ev = evidence_of recs in
      let pol = List.assoc_opt policy cfg.policies in
      if ev.records >= cfg.min_records then
        match key with
        | K_column (tname, column) -> (
            let target = tname ^ "." ^ column in
            let tb =
              Option.bind pol (fun (p : Policy.t) ->
                  List.find_opt
                    (fun t -> String.equal (Policy.table_qualified_name t) tname)
                    p.tables)
            in
            let schema, table =
              match tb with
              | Some t -> (t.Policy.schema, t.name)
              | None -> (
                  match String.index_opt tname '.' with
                  | Some i ->
                      ( String.sub tname 0 i,
                        String.sub tname (i + 1) (String.length tname - i - 1) )
                  | None -> ("", tname))
            in
            let pii_why =
              match cfg.pii ~schema ~table ~column with
              | Some _ as w -> w
              | None when schema = "" -> (
                  let def_schema =
                    match pol with
                    | Some { Policy.search_path = s :: _; _ } -> s
                    | _ -> "public"
                  in
                  match cfg.pii ~schema:def_schema ~table ~column with
                  | Some _ as w -> w
                  | None when def_schema <> "public" ->
                      cfg.pii ~schema:"public" ~table ~column
                  | None -> None)
              | None -> None
            in
            match pii_why with
            | Some why ->
                item ~policy ~code ~target ~category:Pii
                  ~reason:
                    ("sensitive column (" ^ why
                   ^ "): not suggested; rewrite the query without it")
                  ev
            | None -> (
                let summary =
                  Printf.sprintf "%s read %s (%s); add %s to tables.%s.columns"
                    (phrase ev) target code (Ident.render column) (qualified schema table)
                in
                let change = Add_column { schema; table; column } in
                let id = Printf.sprintf "%s/column/%s" policy target in
                match (pol, tb) with
                | None, _ ->
                    suggest ~id ~policy ~code ~change ~ev ~summary
                      ~yaml:
                        (Printf.sprintf "tables:\n  %s:\n    columns: [..., %s]\n"
                           (yaml_scalar (qualified schema table))
                           (yaml_scalar column))
                      ~notes:[ not_loaded policy ]
                      ~applicable:false
                | Some _, None ->
                    item ~policy ~code ~target ~category:Needs_review
                      ~reason:"the table is no longer in the loaded policy" ev
                | Some _, Some t -> (
                    match t.columns with
                    | Policy.All ->
                        item ~policy ~code ~target ~category:Already_allowed
                          ~reason:"the loaded policy allows every column of the table" ev
                    | Policy.Only cols ->
                        if List.mem column cols then
                          item ~policy ~code ~target ~category:Already_allowed
                            ~reason:"the loaded policy already allows this column" ev
                        else
                          suggest ~id ~policy ~code ~change ~ev ~summary
                            ~yaml:
                              (Printf.sprintf "tables:\n  %s:\n    columns: %s\n"
                                 (yaml_scalar (qualified schema table))
                                 (flow_list (List.map Ident.render (cols @ [ column ]))))
                            ~notes:[] ~applicable:true)))
        | K_star t ->
            item ~policy ~code ~target:(t ^ ".*") ~category:Query_fix
              ~reason:
                "SELECT * or a whole-row reference: list the needed columns explicitly"
              ev
        | K_sql_value f ->
            item ~policy ~code ~target:f ~category:Unsafe
              ~reason:"identity/session value functions are never allowed" ev
        | K_function f -> (
            match unsafe_function f with
            | Some why ->
                item ~policy ~code ~target:(f ^ "()") ~category:Unsafe ~reason:why ev
            | None -> (
                let id = Printf.sprintf "%s/function/%s" policy f in
                let summary =
                  Printf.sprintf "%s called %s() (%s); add %s to functions.allow"
                    (phrase ev) f code f
                in
                let yaml =
                  Printf.sprintf
                    "functions:\n  allow:\n    - %s   # append to functions.allow\n"
                    (yaml_scalar f)
                in
                let notes =
                  if starts_with ~prefix:"regexp_" f then
                    [ "regular expressions supplied by the model can be slow" ]
                  else []
                in
                match pol with
                | None ->
                    suggest ~id ~policy ~code ~change:(Add_function f) ~ev ~summary ~yaml
                      ~notes:(not_loaded policy :: notes) ~applicable:false
                | Some p ->
                    if List.mem f p.functions then
                      item ~policy ~code ~target:(f ^ "()") ~category:Already_allowed
                        ~reason:"the loaded policy already allows this function" ev
                    else
                      suggest ~id ~policy ~code ~change:(Add_function f) ~ev ~summary
                        ~yaml ~notes ~applicable:true))
        | K_limit_nonconst ->
            item ~policy ~code ~target:"LIMIT <non-constant>" ~category:Query_fix
              ~reason:"LIMIT must be an integer constant; a policy change cannot fix it"
              ev
        | K_limit -> (
            let n = Option.value (Hashtbl.find_opt max_limit policy) ~default:0 in
            let target = Printf.sprintf "LIMIT %d" n in
            match pol with
            | None ->
                item ~policy ~code ~target ~category:Needs_review
                  ~reason:(not_loaded policy) ev
            | Some p -> (
                match p.require_limit with
                | None ->
                    item ~policy ~code ~target ~category:Already_allowed
                      ~reason:"the loaded policy has no require_limit" ev
                | Some cur when n <= cur ->
                    item ~policy ~code ~target ~category:Already_allowed
                      ~reason:(Printf.sprintf "the loaded policy allows LIMIT %d" cur)
                      ev
                | Some cur ->
                    if n > cfg.limit_ceiling || n > cur * cfg.limit_factor then
                      item ~policy ~code ~target ~category:Needs_review
                        ~reason:
                          (Printf.sprintf
                             "far above the current maximum %d (more than %dx, or above \
                              %d): make the queries page instead"
                             cur cfg.limit_factor cfg.limit_ceiling)
                        ev
                    else
                      suggest ~id:(policy ^ "/limit") ~policy ~code
                        ~change:(Set_limit_max { current = cur; proposed = n })
                        ~ev
                        ~summary:
                          (Printf.sprintf
                             "%s used LIMIT up to %d, above require_limit.max %d (%s); \
                              raise require_limit.max to %d"
                             (phrase ev) n cur code n)
                        ~yaml:(Printf.sprintf "require_limit:\n  max: %d\n" n)
                        ~notes:[] ~applicable:true))
        | K_system n ->
            item ~policy ~code ~target:n ~category:Unsafe
              ~reason:"system catalogs are never readable" ev
        | K_table (schema_opt, name) -> (
            let shown = match schema_opt with Some s -> s ^ "." ^ name | None -> name in
            match pol with
            | None ->
                item ~policy ~code ~target:shown ~category:Needs_review
                  ~reason:(not_loaded policy) ev
            | Some p -> (
                let schema =
                  match schema_opt with
                  | Some s -> s
                  | None -> ( match p.search_path with s :: _ -> s | [] -> "public")
                in
                let target = schema ^ "." ^ name in
                if
                  system_schema schema
                  || (schema_opt = None && starts_with ~prefix:"pg_" name)
                then
                  item ~policy ~code ~target ~category:Unsafe
                    ~reason:"system schemas are never readable" ev
                else if Option.is_some (Policy.find_table p ~schema ~name) then
                  item ~policy ~code ~target ~category:Query_fix
                    ~reason:
                      "the table is in the policy but did not resolve (search_path \
                       shadowing): qualify the table name in the query"
                    ev
                else
                  let id = Printf.sprintf "%s/table/%s" policy target in
                  match new_table_tenancy p ~schema ~name with
                  | Error why ->
                      item ~policy ~code ~target ~category:Needs_review ~reason:why ev
                  | Ok tenant_columns ->
                      let star = ref false in
                      let cols =
                        match cfg.verify with
                        | None -> None
                        | Some verify ->
                            let probe_cache = Hashtbl.create 16 in
                            let found =
                              List.concat_map
                                (fun (r : Record.t) ->
                                  match r.sql with
                                  | Some sql -> (
                                      match Hashtbl.find_opt probe_cache sql with
                                      | Some cols -> cols
                                      | None ->
                                          let cols =
                                            probe_columns verify p ~schema ~name
                                              ~tenant_columns sql
                                          in
                                          Hashtbl.replace probe_cache sql cols;
                                          cols)
                                  | None -> [])
                                recs
                            in
                            if List.mem "*" found then star := true;
                            let found =
                              List.sort_uniq compare
                                (List.filter (fun c -> c <> "*") found)
                            in
                            if found = [] then None else Some found
                      in
                      let pii_cols, cols =
                        match cols with
                        | None -> ([], None)
                        | Some l ->
                            let pii, ok =
                              List.partition
                                (fun c -> cfg.pii ~schema ~table:name ~column:c <> None)
                                l
                            in
                            (pii, Some ok)
                      in
                      List.iter
                        (fun c ->
                          item ~policy ~code
                            ~target:(target ^ "." ^ c)
                            ~category:Pii
                            ~reason:
                              ("sensitive column ("
                              ^ Option.value
                                  (cfg.pii ~schema ~table:name ~column:c)
                                  ~default:""
                              ^ "): left out of the suggested table")
                            ev)
                        pii_cols;
                      let tenant_cols = List.map fst tenant_columns in
                      let columns =
                        match cols with
                        | None -> []
                        | Some l ->
                            tenant_cols
                            @ List.filter (fun c -> not (List.mem c tenant_cols)) l
                      in
                      let notes =
                        (match cols with
                          | None ->
                              [
                                "the columns the queries read are unknown (needs records \
                                 with raw SQL); fill in the column list";
                              ]
                          | Some [] -> [ "every column the queries read is sensitive" ]
                          | Some _ -> [])
                        @ (if !star then
                             [
                               "some queries use * on the table; they stay denied until \
                                they list columns";
                             ]
                           else [])
                        @
                        match tenant_columns with
                        | [] -> []
                        | tc ->
                            [
                              Printf.sprintf
                                "added as tenant-scoped on %s, like the other \
                                 tenant-scoped tables; confirm the column holds the \
                                 tenant id"
                                (String.concat ", " (List.map fst tc));
                            ]
                      in
                      let tenancy_yaml =
                        match (tenant_columns, p.tenancy.keys) with
                        | [], _ -> ""
                        | [ (c, _) ], [ _ ] ->
                            Printf.sprintf "    tenant_column: %s\n"
                              (yaml_scalar (Ident.render c))
                        | tc, _ ->
                            "    tenant_columns:\n"
                            ^ String.concat ""
                                (List.map
                                   (fun (c, k) ->
                                     Printf.sprintf "      %s: %s\n"
                                       (yaml_scalar (Ident.render c))
                                       (yaml_scalar k))
                                   tc)
                      in
                      let applicable =
                        match cols with Some (_ :: _) -> true | Some [] | None -> false
                      in
                      let yaml =
                        Printf.sprintf "tables:\n  %s:\n    columns: %s\n%s"
                          (yaml_scalar (qualified schema name))
                          (if columns = [] then "[]   # fill in"
                           else flow_list (List.map Ident.render columns))
                          tenancy_yaml
                      in
                      suggest ~id ~policy ~code
                        ~change:
                          (Add_table { schema; table = name; columns; tenant_columns })
                        ~ev
                        ~summary:
                          (Printf.sprintf "%s read %s (%s); add %s to tables%s"
                             (phrase ev) shown code (qualified schema name)
                             (match tenant_columns with
                             | [] -> ""
                             | tc ->
                                 " (tenant-scoped on "
                                 ^ String.concat ", " (List.map fst tc)
                                 ^ ")"))
                        ~yaml ~notes ~applicable)))
    (List.rev !order);
  let by_evidence a b = match compare b a with 0 -> 0 | n -> n in
  let suggestions =
    List.sort
      (fun a b ->
        match by_evidence a.evidence.records b.evidence.records with
        | 0 -> compare a.id b.id
        | n -> n)
      !suggestions
  in
  let sort_items l =
    List.sort
      (fun a b ->
        match compare b.i_evidence.records a.i_evidence.records with
        | 0 -> compare (a.i_policy, a.target) (b.i_policy, b.target)
        | n -> n)
      l
  in
  let codes =
    Hashtbl.fold
      (fun c n acc ->
        let category, advice =
          match code_of_string c with
          | Some code -> (
              match classify code with
              | Some cat -> (cat, code_advice code)
              | None -> (Needs_review, code_advice code))
          | None when starts_with ~prefix:"PROXY_" c ->
              ( Query_fix,
                "refused by haltsql-proxy itself (e.g. the audit log was unavailable); \
                 not a policy matter" )
          | None -> (Needs_review, "unknown reason code (newer HaltSQL?): review by hand")
        in
        { c_code = c; c_category = category; c_records = n; advice } :: acc)
      code_counts []
    |> List.sort (fun a b ->
        match compare b.c_records a.c_records with
        | 0 -> compare a.c_code b.c_code
        | n -> n)
  in
  {
    suggestions;
    pii_flagged = sort_items !flagged;
    not_suggested = sort_items !items;
    codes;
    missing_detail = !missing;
  }

let change_to_json = function
  | Add_column { schema; table; column } ->
      `Assoc
        [
          ("kind", `String "add_column");
          ("table", `String (qualified schema table));
          ("column", `String column);
        ]
  | Add_function f -> `Assoc [ ("kind", `String "add_function"); ("function", `String f) ]
  | Set_limit_max { current; proposed } ->
      `Assoc
        [
          ("kind", `String "raise_limit");
          ("current", `Int current);
          ("proposed", `Int proposed);
        ]
  | Add_table { schema; table; columns; tenant_columns } ->
      `Assoc
        [
          ("kind", `String "add_table");
          ("table", `String (qualified schema table));
          ("columns", `List (List.map (fun c -> `String c) columns));
          ( "tenant_columns",
            `Assoc (List.map (fun (c, k) -> (c, `String k)) tenant_columns) );
        ]

let item_to_json i : Yojson.Safe.t =
  `Assoc
    [
      ("policy", `String i.i_policy);
      ("code", `String i.i_code);
      ("target", `String i.target);
      ("category", `String (category_to_string i.category));
      ("reason", `String i.reason);
      ("evidence", evidence_to_json i.i_evidence);
    ]

let to_json t : Yojson.Safe.t =
  `Assoc
    [
      ( "suggestions",
        `List
          (List.map
             (fun s ->
               `Assoc
                 [
                   ("id", `String s.id);
                   ("policy", `String s.policy);
                   ("code", `String s.code);
                   ("change", change_to_json s.change);
                   ("summary", `String s.summary);
                   ("yaml", `String s.yaml);
                   ("notes", `List (List.map (fun n -> `String n) s.notes));
                   ("applicable", `Bool s.applicable);
                   ("evidence", evidence_to_json s.evidence);
                 ])
             t.suggestions) );
      ("pii_flagged", `List (List.map item_to_json t.pii_flagged));
      ("not_suggested", `List (List.map item_to_json t.not_suggested));
      ( "codes",
        `List
          (List.map
             (fun r ->
               `Assoc
                 [
                   ("code", `String r.c_code);
                   ("category", `String (category_to_string r.c_category));
                   ("records", `Int r.c_records);
                   ("advice", `String r.advice);
                 ])
             t.codes) );
      ("missing_detail", `Int t.missing_detail);
    ]
