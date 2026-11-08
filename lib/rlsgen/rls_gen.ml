(* Policy -> role / grant / row-level-security DDL. See rls_gen.mli. *)

open Haltsql_core

type options = {
  role : string;
  setting_prefix : string;
  owner_role : string option;
  drop_existing : bool;
  force_rls : bool;
  set_fields : string list;
  catalog : Catalog.t option;
}

let default_options =
  {
    role = "haltsql_agent";
    setting_prefix = "haltsql";
    owner_role = None;
    drop_existing = false;
    force_rls = false;
    set_fields = [];
    catalog = None;
  }

type cmd = Select | Insert | Update | Delete

let all_cmds = [ Select; Insert; Update; Delete ]

let cmd_to_string = function
  | Select -> "SELECT"
  | Insert -> "INSERT"
  | Update -> "UPDATE"
  | Delete -> "DELETE"

let policy_name c = "haltsql_tenant_" ^ String.lowercase_ascii (cmd_to_string c)

type tenant_term = {
  column : string;
  setting : string;
  context_field : string;
  is_set : bool;
  cast : string option;
}

type table_plan = {
  schema : string;
  name : string;
  select : Policy.columns;
  insert : Policy.columns option;
  update : Policy.columns option;
  delete : bool;
  tenant : tenant_term list;
  commands : cmd list;
}

type plan = {
  policy_name_meta : string;
  policy_version : string;
  options : options;
  schemas : string list;
  tables : table_plan list;
  settings : (string * string * bool) list;
  warnings : string list;
}

(* ---------------------------------------------------------------- validation *)

let ( let* ) = Result.bind

let is_guc_part s =
  s <> ""
  && (match s.[0] with 'a' .. 'z' | 'A' .. 'Z' | '_' -> true | _ -> false)
  && String.for_all
       (function 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' -> true | _ -> false)
       s

let validate_prefix p =
  if p = "" then Error "setting prefix must not be empty"
  else if String.length p > 63 then Error "setting prefix is longer than 63 bytes"
  else if List.for_all is_guc_part (String.split_on_char '.' p) then Ok ()
  else
    Error
      (Printf.sprintf
         "invalid setting prefix %S: use dot-separated names of letters, digits and \
          underscores (not starting with a digit)"
         p)

let reserved_role_names =
  [ "public"; "none"; "current_user"; "session_user"; "current_role"; "system_user" ]

let validate_role ~what r =
  if r = "" then Error (what ^ " must not be empty")
  else if String.contains r '\000' then Error (what ^ " must not contain a NUL byte")
  else if String.length r > 63 then Error (what ^ " is longer than 63 bytes")
  else if List.mem (String.lowercase_ascii r) reserved_role_names then
    Error (Printf.sprintf "%s %S is a reserved role name" what r)
  else if String.length r >= 3 && String.lowercase_ascii (String.sub r 0 3) = "pg_" then
    Error (Printf.sprintf "%s %S: names starting with pg_ are reserved" what r)
  else Ok ()

let text_types = [ "text"; "varchar"; "character varying"; "pg_catalog.text" ]

(* Types we are willing to splice into "::type". Catalog snapshots record names such
   as int8, uuid, "character varying(64)", timestamptz. Anything with quotes or other
   punctuation is refused rather than guessed. *)
let valid_type_name t =
  t <> ""
  && (match t.[0] with 'a' .. 'z' | '_' -> true | _ -> false)
  && String.for_all
       (function
         | 'a' .. 'z' | '0' .. '9' | '_' | ' ' | '.' | '(' | ')' | ',' -> true
         | _ -> false)
       t

let base_type t =
  match String.index_opt t '(' with
  | Some i -> String.trim (String.sub t 0 i)
  | None -> String.trim t

let lookup_type opts (p : Policy.t) ~schema ~name ~column =
  let from cat =
    match Catalog.find cat ~schema ~name with
    | None -> None
    | Some tb -> (
        match
          List.find_opt (fun (c : Catalog.column) -> c.col_name = column) tb.columns
        with
        | Some { col_type = Some t; _ } -> Some t
        | _ -> None)
  in
  match Option.bind opts.catalog from with Some t -> Some t | None -> from p.catalog

let cast_for ~qualified ~column ty =
  match ty with
  | None -> Ok None
  | Some t ->
      let t = String.lowercase_ascii (String.trim t) in
      if String.contains t '[' then
        Error
          (Printf.sprintf "%s.%s: array-typed tenant columns (%s) are not supported"
             qualified column t)
      else if not (valid_type_name t) then
        Error (Printf.sprintf "%s.%s: unsupported column type %S" qualified column t)
      else if List.mem (base_type t) text_types then Ok None
      else Ok (Some t)

let rec collect = function
  | [] -> Ok []
  | Ok x :: rest ->
      let* xs = collect rest in
      Ok (x :: xs)
  | (Error _ as e) :: _ -> e

let has_suffix ~suffix s =
  let ls = String.length s and lx = String.length suffix in
  ls >= lx && String.sub s (ls - lx) lx = suffix

(* ---------------------------------------------------------------------- plan *)

let plan opts (p : Policy.t) =
  let* () = validate_role ~what:"--role" opts.role in
  let* () =
    match opts.owner_role with
    | None -> Ok ()
    | Some o ->
        let* () = validate_role ~what:"--owner-role" o in
        if o = opts.role then Error "--owner-role must differ from --role" else Ok ()
  in
  let* () = validate_prefix opts.setting_prefix in
  let fields = List.map snd p.tenancy.keys in
  let* () =
    collect
      (List.map
         (fun f ->
           if List.mem f fields then Ok ()
           else
             Error
               (Printf.sprintf
                  "--set-field %S is not a tenancy context field of this policy (fields: \
                   %s)"
                  f
                  (if fields = [] then "none" else String.concat ", " fields)))
         opts.set_fields)
    |> Result.map ignore
  in
  let* () =
    collect
      (List.map
         (fun f ->
           if is_guc_part f then Ok ()
           else
             Error
               (Printf.sprintf
                  "context field %S cannot be used in a setting name (letters, digits \
                   and underscores only)"
                  f))
         fields)
    |> Result.map ignore
  in
  let warnings = ref [] in
  let warn s = warnings := s :: !warnings in
  let allowed k = List.mem k p.statements in
  let table_plan (tb : Policy.table) =
    let qualified = Pg_quote.quote_qualified ~schema:tb.schema ~name:tb.name in
    let* tenant =
      collect
        (List.map
           (fun (column, key) ->
             match List.assoc_opt key p.tenancy.keys with
             | None ->
                 Error (Printf.sprintf "%s: tenancy key %S is not defined" qualified key)
             | Some field ->
                 let ty = lookup_type opts p ~schema:tb.schema ~name:tb.name ~column in
                 if ty = None then
                   warn
                     (Printf.sprintf
                        "%s.%s: column type unknown (no catalog entry); the setting is \
                         compared as text. Pass --catalog if the column is not text."
                        qualified (Pg_quote.quote_ident column));
                 let* cast =
                   cast_for ~qualified ~column:(Pg_quote.quote_ident column) ty
                 in
                 Ok
                   {
                     column;
                     setting = opts.setting_prefix ^ "." ^ field;
                     context_field = field;
                     is_set = List.mem field opts.set_fields;
                     cast;
                   })
           tb.tenant_columns)
    in
    let insert =
      if allowed Policy.Insert && tb.writes.insert then Some tb.columns else None
    in
    let update = if allowed Policy.Update then tb.writes.update else None in
    let delete = allowed Policy.Delete && tb.writes.delete in
    let commands =
      if tenant = [] then []
      else
        List.filter
          (function
            | Select -> true
            | Insert -> insert <> None
            | Update -> update <> None
            | Delete -> delete)
          all_cmds
    in
    Ok
      {
        schema = tb.schema;
        name = tb.name;
        select = tb.columns;
        insert;
        update;
        delete;
        tenant;
        commands;
      }
  in
  let sorted_tables =
    List.sort
      (fun (a : Policy.table) (b : Policy.table) ->
        compare (a.schema, a.name) (b.schema, b.name))
      p.tables
  in
  let* tables = collect (List.map table_plan sorted_tables) in
  List.iter
    (fun f ->
      if has_suffix ~suffix:"_ids" f && not (List.mem f opts.set_fields) then
        warn
          (Printf.sprintf
             "context field %S looks like a set of values; pass --set-field %s if the \
              context carries a list"
             f f))
    (List.sort_uniq compare fields);
  let schemas = List.sort_uniq compare (List.map (fun t -> t.schema) tables) in
  let settings =
    List.concat_map
      (fun t -> List.map (fun tt -> (tt.setting, tt.context_field, tt.is_set)) t.tenant)
      tables
    |> List.sort_uniq compare
  in
  Ok
    {
      policy_name_meta = p.name;
      policy_version = p.version;
      options = opts;
      schemas;
      tables;
      settings;
      warnings = List.sort_uniq compare !warnings;
    }

(* -------------------------------------------------------------------- render *)

let q = Pg_quote.quote_ident
let lit = Pg_quote.quote_literal

let setting_expr s =
  Printf.sprintf "NULLIF(pg_catalog.current_setting(%s, true), '')" (lit s)

let term_sql t =
  if t.is_set then
    let arr =
      Printf.sprintf "pg_catalog.array_remove(pg_catalog.string_to_array(%s, ','), '')"
        (setting_expr t.setting)
    in
    let arr = match t.cast with None -> arr | Some ty -> arr ^ "::" ^ ty ^ "[]" in
    Printf.sprintf "%s = ANY (%s)" (q t.column) arr
  else
    let v = setting_expr t.setting in
    let v = match t.cast with None -> v | Some ty -> v ^ "::" ^ ty in
    Printf.sprintf "%s = %s" (q t.column) v

let predicate terms = String.concat " AND " (List.map term_sql terms)

(* Comments must stay on one line: replace control characters. *)
let comment_safe s =
  String.map (fun c -> if Char.code c < 0x20 || Char.code c = 0x7f then ' ' else c) s

let col_list cols = String.concat ", " (List.map q cols)

let render (pl : plan) =
  let o = pl.options in
  let b = Buffer.create 8192 in
  let line s =
    Buffer.add_string b s;
    Buffer.add_char b '\n'
  in
  let linef fmt = Printf.ksprintf line fmt in
  let role = q o.role in
  let yes_no x = if x then "yes" else "no" in
  (* ---- header *)
  linef "-- Generated by `haltsql rls generate`. Regenerate instead of editing.";
  linef "-- Database-level defense in depth for a HaltSQL policy.";
  linef "-- Policy: %s" (comment_safe pl.policy_name_meta);
  linef "-- Policy version: %s" (comment_safe pl.policy_version);
  linef "-- Role: %s | setting prefix: %s | force RLS: %s | drop existing policies: %s"
    (comment_safe o.role) o.setting_prefix (yes_no o.force_rls) (yes_no o.drop_existing);
  (match o.owner_role with
  | Some r -> linef "-- Table DDL runs as owner role: %s" (comment_safe r)
  | None -> ());
  line "-- Target: PostgreSQL 13-17. Idempotent: re-running converges to the same state.";
  line "--";
  line "-- Session preamble (application side). In the SAME transaction as the SQL that";
  line "-- HaltSQL verified, set every setting below from the context values that were";
  line "-- passed to HaltSQL (never from the model or the prompt), then switch role:";
  line "--";
  line "--   BEGIN;";
  if pl.settings = [] then
    line "--   -- (no tenant settings: this policy has no tenant-scoped tables)";
  List.iteri
    (fun i (s, field, is_set) ->
      if is_set then
        linef
          "--   SELECT pg_catalog.set_config('%s', array_to_string($%d::text[], ','), \
           true);  -- $%d = ctx.%s (list)"
          s (i + 1) (i + 1) field
      else
        linef "--   SELECT pg_catalog.set_config('%s', $%d, true);  -- $%d = ctx.%s" s
          (i + 1) (i + 1) field)
    pl.settings;
  linef "--   SET LOCAL ROLE %s;" (comment_safe role);
  line "--   <the exact SQL HaltSQL allowed, binding its bind_params>";
  line "--   COMMIT;";
  line "--";
  (match pl.settings with
  | (s, field, _) :: _ ->
      linef "-- Equivalent: SET LOCAL %s = '<ctx.%s>';  (value written as a SQL literal)"
        s field
  | [] -> ());
  if List.exists (fun (_, _, s) -> s) pl.settings then
    line
      "-- Set-valued settings hold the values joined with ',' (values must not contain \
       ',').";
  line
    "-- A missing or empty setting matches no rows: the comparison with NULL is never \
     true.";
  line "";
  line "BEGIN;";
  line "";
  (* ---- role *)
  line "-- Role: no login, no RLS bypass. Refuse to continue if it can bypass RLS.";
  let role_body =
    String.concat "\n"
      [
        "";
        "BEGIN";
        Printf.sprintf
          "  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s) THEN"
          (lit o.role);
        Printf.sprintf "    CREATE ROLE %s NOLOGIN NOBYPASSRLS;" role;
        Printf.sprintf
          "  ELSIF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s AND \
           (rolsuper OR rolbypassrls)) THEN"
          (lit o.role);
        Printf.sprintf
          "    RAISE EXCEPTION 'haltsql: role %% is SUPERUSER or BYPASSRLS; row-level \
           security would not apply', %s;"
          (lit o.role);
        "  END IF;";
        "END";
        "";
      ]
  in
  linef "DO %s;" (Pg_quote.dollar_quote role_body);
  line "";
  (match o.owner_role with
  | Some r ->
      linef "SET LOCAL ROLE %s;" (q r);
      line ""
  | None -> ());
  (* ---- schemas *)
  List.iter
    (fun s ->
      linef "-- Schema %s: start from nothing, then allow lookups." (comment_safe s);
      linef "REVOKE ALL ON ALL TABLES IN SCHEMA %s FROM %s;" (q s) role;
      linef "REVOKE ALL ON ALL SEQUENCES IN SCHEMA %s FROM %s;" (q s) role;
      linef "REVOKE CREATE ON SCHEMA %s FROM %s;" (q s) role;
      linef "GRANT USAGE ON SCHEMA %s TO %s;" (q s) role;
      line "")
    pl.schemas;
  (* ---- tables *)
  List.iter
    (fun t ->
      let qt = Pg_quote.quote_qualified ~schema:t.schema ~name:t.name in
      if t.tenant = [] then
        linef "-- Table %s: global (not tenant-scoped); grants only." (comment_safe qt)
      else
        linef "-- Table %s: tenant-scoped by %s." (comment_safe qt)
          (String.concat ", "
             (List.map
                (fun tt ->
                  Printf.sprintf "%s = %s%s" (q tt.column) tt.setting
                    (if tt.is_set then " (set)" else ""))
                t.tenant)
          |> comment_safe);
      (match t.select with
      | Policy.All -> linef "GRANT SELECT ON TABLE %s TO %s;" qt role
      | Policy.Only [] -> line "-- (no readable columns: no SELECT grant)"
      | Policy.Only cols ->
          linef "GRANT SELECT (%s) ON TABLE %s TO %s;" (col_list cols) qt role);
      (match t.insert with
      | None -> ()
      | Some Policy.All -> linef "GRANT INSERT ON TABLE %s TO %s;" qt role
      | Some (Policy.Only []) -> ()
      | Some (Policy.Only cols) ->
          linef "GRANT INSERT (%s) ON TABLE %s TO %s;" (col_list cols) qt role);
      (match t.update with
      | None -> ()
      | Some Policy.All -> linef "GRANT UPDATE ON TABLE %s TO %s;" qt role
      | Some (Policy.Only []) -> ()
      | Some (Policy.Only cols) ->
          linef "GRANT UPDATE (%s) ON TABLE %s TO %s;" (col_list cols) qt role);
      if t.delete then linef "GRANT DELETE ON TABLE %s TO %s;" qt role;
      if t.insert <> None then begin
        (* serial / owned sequences: INSERT relying on a column default calls nextval() *)
        let body =
          String.concat "\n"
            [
              "";
              "DECLARE s record;";
              "BEGIN";
              "  FOR s IN SELECT c.oid::pg_catalog.regclass::text AS seq";
              "           FROM pg_catalog.pg_depend d";
              "           JOIN pg_catalog.pg_class c ON c.oid = d.objid";
              Printf.sprintf "           WHERE d.refobjid = %s::pg_catalog.regclass"
                (lit qt);
              "             AND d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass";
              "             AND d.deptype = 'a' AND c.relkind = 'S'";
              "           ORDER BY 1";
              "  LOOP";
              Printf.sprintf
                "    EXECUTE pg_catalog.format('GRANT USAGE ON SEQUENCE %%s TO %%I', \
                 s.seq, %s);"
                (lit o.role);
              "  END LOOP;";
              "END";
              "";
            ]
        in
        linef "DO %s;" (Pg_quote.dollar_quote body)
      end;
      if t.tenant <> [] then begin
        linef "ALTER TABLE %s ENABLE ROW LEVEL SECURITY;" qt;
        if o.force_rls then linef "ALTER TABLE %s FORCE ROW LEVEL SECURITY;" qt;
        if o.drop_existing then begin
          let body =
            String.concat "\n"
              [
                "";
                "DECLARE p record;";
                "BEGIN";
                "  FOR p IN SELECT pol.polname FROM pg_catalog.pg_policy pol";
                Printf.sprintf
                  "           WHERE pol.polrelid = %s::pg_catalog.regclass ORDER BY 1"
                  (lit qt);
                "  LOOP";
                Printf.sprintf
                  "    EXECUTE pg_catalog.format('DROP POLICY %%I ON %%s', p.polname, \
                   %s);"
                  (lit qt);
                "  END LOOP;";
                "END";
                "";
              ]
          in
          linef "DO %s;" (Pg_quote.dollar_quote body)
        end
        else
          List.iter
            (fun c -> linef "DROP POLICY IF EXISTS %s ON %s;" (policy_name c) qt)
            all_cmds;
        let pred = predicate t.tenant in
        List.iter
          (fun c ->
            let clauses =
              match c with
              | Select | Delete -> Printf.sprintf "\n  USING (%s)" pred
              | Insert -> Printf.sprintf "\n  WITH CHECK (%s)" pred
              | Update -> Printf.sprintf "\n  USING (%s)\n  WITH CHECK (%s)" pred pred
            in
            linef "CREATE POLICY %s ON %s AS PERMISSIVE FOR %s TO %s%s;" (policy_name c)
              qt (cmd_to_string c) role clauses)
          t.commands
      end;
      line "")
    pl.tables;
  line "COMMIT;";
  Buffer.contents b

let generate opts p =
  let* pl = plan opts p in
  Ok (render pl, pl.warnings)

(* ---------------------------------------------------------------------- json *)

let columns_json = function
  | Policy.All -> `String "*"
  | Policy.Only l -> `List (List.map (fun c -> `String c) l)

let plan_to_json pl : Yojson.Safe.t =
  let o = pl.options in
  `Assoc
    [
      ("policy", `String pl.policy_name_meta);
      ("policy_version", `String pl.policy_version);
      ("role", `String o.role);
      ("setting_prefix", `String o.setting_prefix);
      ("owner_role", match o.owner_role with Some r -> `String r | None -> `Null);
      ("force_rls", `Bool o.force_rls);
      ("drop_existing", `Bool o.drop_existing);
      ("schemas", `List (List.map (fun s -> `String s) pl.schemas));
      ( "settings",
        `List
          (List.map
             (fun (s, f, set) ->
               `Assoc
                 [
                   ("setting", `String s); ("context_field", `String f); ("set", `Bool set);
                 ])
             pl.settings) );
      ( "tables",
        `List
          (List.map
             (fun t ->
               `Assoc
                 [
                   ("schema", `String t.schema);
                   ("name", `String t.name);
                   ("select", columns_json t.select);
                   ( "insert",
                     match t.insert with Some c -> columns_json c | None -> `Null );
                   ( "update",
                     match t.update with Some c -> columns_json c | None -> `Null );
                   ("delete", `Bool t.delete);
                   ( "tenant",
                     `List
                       (List.map
                          (fun tt ->
                            `Assoc
                              [
                                ("column", `String tt.column);
                                ("setting", `String tt.setting);
                                ("set", `Bool tt.is_set);
                                ( "cast",
                                  match tt.cast with Some c -> `String c | None -> `Null
                                );
                              ])
                          t.tenant) );
                   ( "policies",
                     `List (List.map (fun c -> `String (policy_name c)) t.commands) );
                   ( "predicate",
                     if t.tenant = [] then `Null else `String (predicate t.tenant) );
                 ])
             pl.tables) );
      ("warnings", `List (List.map (fun w -> `String w) pl.warnings));
    ]
