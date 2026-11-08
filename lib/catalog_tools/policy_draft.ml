(** Starter policy drafting (see policy_draft.mli). *)

open Haltsql_core

type config = {
  name : string;
  tenant_column : string;
  tenancy_key : string;
  context_field : string;
  schemas : string list;
  catalog_ref : string;
  require_limit : int;
  presets : string list;
  name_patterns : string list;
  include_partitions : bool;
  pii_sources : string list;
}

let default_name_patterns =
  [
    "email";
    "phone";
    "mobile";
    "ssn";
    "password";
    "passwd";
    "secret";
    "token";
    "api_key";
    "apikey";
    "iban";
    "card";
    "dob";
    "birth";
    "address";
    "ip";
  ]

let default_config ~tenant_column ~catalog_ref =
  {
    name = "draft-policy";
    tenant_column;
    tenancy_key = "tenant";
    context_field = "tenant_id";
    schemas = [];
    catalog_ref;
    require_limit = 1000;
    presets = [ "aggregates"; "math"; "string"; "datetime" ];
    name_patterns = default_name_patterns;
    include_partitions = false;
    pii_sources = [];
  }

type exclusion = { column : string; reasons : string list }

type table_report = {
  schema : string;
  table : string;
  kind : Snapshot.relkind;
  included : string list;
  excluded : exclusion list;
  tenant_scoped : bool;
  skipped : string option;
}

type result = { yaml : string; tables : table_report list; warnings : string list }

(* ------------------------------------------------------------ paths *)

let split_path p =
  String.split_on_char '/' p |> List.filter (fun s -> s <> "" && s <> ".")

let normalize parts =
  List.fold_left
    (fun acc s ->
      match (s, acc) with "..", _ :: rest -> rest | "..", [] -> [] | s, acc -> s :: acc)
    [] parts
  |> List.rev

let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p

let relative_path ~from_dir file =
  let d = normalize (split_path (absolute from_dir)) in
  let f = normalize (split_path (absolute file)) in
  let rec strip a b =
    match (a, b) with x :: a', y :: b' when String.equal x y -> strip a' b' | _ -> (a, b)
  in
  let up, down = strip d f in
  match List.map (fun _ -> "..") up @ down with [] -> "." | l -> String.concat "/" l

(* ------------------------------------------------------------ YAML text *)

let reserved_plain = [ "true"; "false"; "null"; "yes"; "no"; "on"; "off"; "y"; "n"; "~" ]

let plain_ok s =
  s <> ""
  && (not (List.mem (String.lowercase_ascii s) reserved_plain))
  && (match s.[0] with 'a' .. 'z' | '_' -> true | _ -> false)
  && String.for_all
       (function 'a' .. 'z' | '0' .. '9' | '_' | '.' | '-' -> true | _ -> false)
       s
  && not (String.ends_with ~suffix:"." s)

(* A YAML scalar: plain when unambiguous, else a JSON string (valid YAML 1.2). *)
let scalar s = if plain_ok s then s else Yojson.Safe.to_string (`String s)
let flow l = "[" ^ String.concat ", " (List.map scalar l) ^ "]"

(* Comment text: no control characters (a newline would end the comment and inject
   YAML). *)
let comment_safe s =
  String.map (fun c -> if Char.code c < 0x20 || Char.code c = 0x7f then '?' else c) s

let valid_word s =
  s <> ""
  && String.for_all
       (function 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' -> true | _ -> false)
       s

(* ------------------------------------------------------------ drafting *)

let ( let* ) = Result.bind

let check_config c =
  let* () =
    if String.trim c.name = "" then Error "policy name must not be empty" else Ok ()
  in
  let* () =
    if String.exists (fun ch -> Char.code ch < 0x20) c.name then
      Error "policy name must not contain control characters"
    else Ok ()
  in
  let* () =
    if c.tenant_column = "" then Error "--tenant-column must not be empty" else Ok ()
  in
  let* () =
    if valid_word c.tenancy_key then Ok ()
    else
      Error
        (Printf.sprintf "invalid tenancy key %S (use letters, digits and _)" c.tenancy_key)
  in
  let* () =
    if valid_word c.context_field then Ok ()
    else
      Error
        (Printf.sprintf "invalid context field %S (use letters, digits and _)"
           c.context_field)
  in
  let* () =
    if c.require_limit >= 1 then Ok () else Error "require_limit must be at least 1"
  in
  let* () =
    if c.catalog_ref = "" then Error "catalog reference must not be empty" else Ok ()
  in
  Ok ()

let exclusion_reasons cfg pii (tb : Catalog.table) (col : Catalog.column) =
  let from_pii =
    match Pii.find pii ~schema:tb.schema ~table:tb.name ~column:col.col_name with
    | Some e ->
        [
          Printf.sprintf "%s: %s" (String.concat "+" e.sources)
            (String.concat ", " e.classifications);
        ]
    | None -> []
  in
  let from_name =
    match Pii.Matcher.find_match cfg.name_patterns col.col_name with
    | Some p -> [ Printf.sprintf "name matches %S" p ]
    | None -> []
  in
  from_pii @ from_name

let report_table cfg snap pii (tb : Catalog.table) =
  let kind =
    Option.value
      (Snapshot.relkind snap ~schema:tb.schema ~name:tb.name)
      ~default:Snapshot.Table
  in
  let tenant_scoped =
    List.exists
      (fun (c : Catalog.column) -> String.equal c.col_name cfg.tenant_column)
      tb.columns
  in
  let included, excluded, tenant_flag =
    List.fold_left
      (fun (inc, exc, tflag) (c : Catalog.column) ->
        match exclusion_reasons cfg pii tb c with
        | [] -> (c.col_name :: inc, exc, tflag)
        | reasons when String.equal c.col_name cfg.tenant_column ->
            (c.col_name :: inc, exc, Some reasons)
        | reasons -> (inc, { column = c.col_name; reasons } :: exc, tflag))
      ([], [], None) tb.columns
  in
  let included = List.rev included and excluded = List.rev excluded in
  let skipped =
    match kind with
    | Snapshot.Sequence -> Some "sequence"
    | Snapshot.Partition when not cfg.include_partitions ->
        Some "partition (query the partitioned parent table)"
    | _ -> if included = [] then Some "every column is excluded as PII" else None
  in
  ( {
      schema = tb.schema;
      table = tb.name;
      kind;
      included;
      excluded;
      tenant_scoped;
      skipped;
    },
    tenant_flag )

let draft ?(base_dir = ".") cfg (snap : Snapshot.t) (pii : Pii.t) =
  let* () = check_config cfg in
  let in_scope (tb : Catalog.table) =
    cfg.schemas = [] || List.mem tb.schema cfg.schemas
  in
  let selected = List.filter in_scope snap.catalog.tables in
  let warnings = ref [] in
  let warn fmt = Printf.ksprintf (fun s -> warnings := s :: !warnings) fmt in
  List.iter
    (fun s ->
      if not (List.exists (fun (tb : Catalog.table) -> String.equal tb.schema s) selected)
      then warn "schema %s has no relations in the catalog" s)
    cfg.schemas;
  let reports = List.map (report_table cfg snap pii) selected in
  (* PII entries that match nothing in the catalog: likely stale or misnamed. *)
  List.iter
    (fun (e : Pii.entry) ->
      let lc = String.lowercase_ascii in
      let hit =
        List.exists
          (fun (tb : Catalog.table) ->
            lc tb.schema = lc e.schema
            && lc tb.name = lc e.table
            && List.exists
                 (fun (c : Catalog.column) -> lc c.col_name = lc e.column)
                 tb.columns)
          snap.catalog.tables
      in
      if not hit then
        warn "PII column %s.%s.%s is not in the catalog" e.schema e.table e.column)
    pii;
  let kept = List.filter (fun (r, _) -> r.skipped = None) reports in
  if not (List.exists (fun (r, _) -> r.tenant_scoped) kept) then
    warn "no drafted table has a %S column; every table is global" cfg.tenant_column;
  let search_path =
    match cfg.schemas with
    | [] -> (
        match List.sort_uniq compare (List.map (fun (r, _) -> r.schema) kept) with
        | [] -> [ "public" ]
        | l -> l)
    | l -> l
  in
  let b = Buffer.create 4096 in
  let line fmt =
    Printf.ksprintf
      (fun s ->
        Buffer.add_string b s;
        Buffer.add_char b '\n')
      fmt
  in
  let c s = comment_safe s in
  line "# Starter HaltSQL policy drafted by `haltsql policy draft`. REVIEW BEFORE USE.";
  line "# Catalog: %s" (c cfg.catalog_ref);
  (match cfg.pii_sources with
  | [] -> line "# PII manifests: none"
  | l -> line "# PII manifests: %s" (c (String.concat ", " l)));
  if cfg.name_patterns <> [] then
    line "# Column-name heuristics: %s" (c (String.concat ", " cfg.name_patterns));
  line "# - Columns classified as PII are left out; each table says which and why.";
  line "# - Tables without a %s column are GLOBAL (no tenant predicate is required):"
    (c (Snapshot.render_ident cfg.tenant_column));
  line "#   remove or restrict any that hold tenant data.";
  line "# - Remove tables and columns the agent does not need.";
  line "apiVersion: haltsql.dev/v1";
  line "kind: Policy";
  line "metadata:";
  line "  name: %s" (scalar cfg.name);
  line "  description: %s"
    (scalar "Draft generated by haltsql policy draft; review before use");
  line "dialect: postgres-17";
  line "search_path: %s" (flow (List.map Snapshot.render_ident search_path));
  line "catalog: %s" (scalar cfg.catalog_ref);
  line "statements:";
  line "  allow: [select]";
  line "require_limit:";
  line "  max: %d" cfg.require_limit;
  line "tenancy:";
  line "  mode: bound";
  line "  keys:";
  line "    %s: %s" (scalar cfg.tenancy_key) (scalar ("${ctx." ^ cfg.context_field ^ "}"));
  let skipped = List.filter (fun (r, _) -> r.skipped <> None) reports in
  if kept = [] then line "tables: {}" else line "tables:";
  List.iter
    (fun (r, tflag) ->
      let key = Snapshot.table_key ~schema:r.schema ~name:r.table in
      let kind_note =
        match r.kind with
        | Snapshot.Table -> None
        | k -> Some (Snapshot.relkind_to_string k)
      in
      let scope_note =
        if r.tenant_scoped then None
        else
          Some
            (Printf.sprintf "GLOBAL: no %s column"
               (Snapshot.render_ident cfg.tenant_column))
      in
      (match List.filter_map Fun.id [ kind_note; scope_note ] with
      | [] -> ()
      | notes -> line "  # %s" (c (String.concat "; " notes)));
      List.iter
        (fun e ->
          line "  # excluded %s (%s)"
            (c (Snapshot.render_ident e.column))
            (c (String.concat "; " e.reasons)))
        r.excluded;
      (match tflag with
      | Some reasons ->
          line "  # kept tenant column %s although flagged (%s)"
            (c (Snapshot.render_ident cfg.tenant_column))
            (c (String.concat "; " reasons))
      | None -> ());
      line "  %s:" (scalar key);
      line "    columns: %s" (flow (List.map Snapshot.render_ident r.included));
      if r.tenant_scoped then
        line "    tenant_column: %s" (scalar (Snapshot.render_ident cfg.tenant_column)))
    kept;
  if skipped <> [] then begin
    line "# Not drafted:";
    List.iter
      (fun (r, _) ->
        line "#   %s: %s"
          (c (Snapshot.table_key ~schema:r.schema ~name:r.table))
          (c (Option.value r.skipped ~default:"")))
      skipped
  end;
  line "functions:";
  line "  presets: %s" (flow cfg.presets);
  line "mode: enforce";
  let yaml = Buffer.contents b in
  match
    Haltsql_load.Policy_load.of_string ~file:"<draft>" ~base_dir Haltsql_load.Docload.Yaml
      yaml
  with
  | Ok _ -> Ok { yaml; tables = List.map fst reports; warnings = List.rev !warnings }
  | Error errs ->
      Error
        ("the drafted policy does not load (this is a bug or an unusable input):\n"
        ^ String.concat "\n" (List.map Load_error.to_string errs))
