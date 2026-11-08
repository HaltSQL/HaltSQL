(** Policy vs live database drift. See rls_check.mli. *)

open Lwt.Syntax
open Haltsql_core

type severity = Critical | Warning
type finding = { kind : string; severity : severity; obj : string; message : string }

let severity_to_string = function Critical -> "critical" | Warning -> "warning"

let finding_to_json f : Yojson.Safe.t =
  `Assoc
    [
      ("kind", `String f.kind);
      ("severity", `String (severity_to_string f.severity));
      ("object", `String f.obj);
      ("message", `String f.message);
    ]

let lit = Pg_quote.quote_literal
let q = Pg_quote.quote_ident

(* ------------------------------------------------------- expression matching *)

let count_sub ~sub s =
  let ls = String.length s and lx = String.length sub in
  let rec go i n =
    if i + lx > ls then n
    else if String.sub s i lx = sub then go (i + lx) (n + 1)
    else go (i + 1) n
  in
  if lx = 0 then 0 else go 0 0

let is_ident_char c =
  match c with
  | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '$' | '"' -> true
  | c -> Char.code c >= 0x80

let contains_word ~word s =
  let ls = String.length s and lw = String.length word in
  let rec go i =
    if i + lw > ls then false
    else if
      String.sub s i lw = word
      && (i = 0 || (not (is_ident_char s.[i - 1])) || s.[i - 1] = '.')
      && (i + lw = ls || not (is_ident_char s.[i + lw]))
    then true
    else go (i + 1)
  in
  lw > 0 && go 0

let count_words ~word s =
  let ls = String.length s and lw = String.length word in
  let rec go i n =
    if i + lw > ls then n
    else if
      String.sub s i lw = word
      && (i = 0 || not (is_ident_char s.[i - 1]))
      && (i + lw = ls || not (is_ident_char s.[i + lw]))
    then go (i + lw) (n + 1)
    else go (i + 1) n
  in
  if lw = 0 then 0 else go 0 0

(* Blank out the contents of '...' string literals ('' escapes included) so that
   word checks do not look inside them. *)
let strip_literals s =
  let b = Buffer.create (String.length s) in
  let in_lit = ref false in
  String.iter
    (fun c ->
      if c = '\'' then begin
        in_lit := not !in_lit;
        Buffer.add_char b c
      end
      else if not !in_lit then Buffer.add_char b c)
    s;
  Buffer.contents b

let expression_matches (terms : Rls_gen.tenant_term list) expr =
  let bare = strip_literals expr in
  let up = String.uppercase_ascii bare in
  let n = List.length terms in
  terms <> []
  && count_sub ~sub:"current_setting(" expr = n
  (* our predicates are pure conjunctions: anything that could widen them is rejected *)
  && count_words ~word:"OR" up = 0
  && count_words ~word:"NOT" up = 0
  && count_words ~word:"IS" up = 0
  && count_words ~word:"CASE" up = 0
  && count_words ~word:"TRUE" up = n
  && List.for_all
       (fun (t : Rls_gen.tenant_term) ->
         count_sub ~sub:(lit t.setting) expr >= 1 && contains_word ~word:(q t.column) bare)
       terms

(* ------------------------------------------------------------------- queries *)

let bool_of = function Some "t" -> true | _ -> false
let str_of = function Some s -> s | None -> ""
let in_list xs = "(" ^ String.concat ", " (List.map lit xs) ^ ")"

let policy_cmd_of_char = function
  | "r" -> Some Rls_gen.Select
  | "a" -> Some Rls_gen.Insert
  | "w" -> Some Rls_gen.Update
  | "d" -> Some Rls_gen.Delete
  | _ -> None

let cmd_char = function
  | Rls_gen.Select -> "r"
  | Rls_gen.Insert -> "a"
  | Rls_gen.Update -> "w"
  | Rls_gen.Delete -> "d"

type db_table = {
  t_schema : string;
  t_name : string;
  rls : bool;
  force : bool;
  owner : string;
  tpriv : (string * bool) list;  (** table-level privilege -> effective *)
}

let table_privs =
  [ "SELECT"; "INSERT"; "UPDATE"; "DELETE"; "TRUNCATE"; "REFERENCES"; "TRIGGER" ]

let column_privs = [ "SELECT"; "INSERT"; "UPDATE"; "REFERENCES" ]

let check_body conn (pl : Rls_gen.plan) =
  let o = pl.options in
  let role = o.role in
  let findings = ref [] in
  let add kind severity obj message =
    findings := { kind; severity; obj; message } :: !findings
  in
  (* ---- role *)
  let* rows =
    Pg_wire.query conn
      (Printf.sprintf
         "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_catalog.pg_roles WHERE \
          rolname = %s"
         (lit role))
  in
  match rows with
  | [] ->
      add "role_missing" Critical role
        "role does not exist; apply the output of `haltsql rls generate`";
      Lwt.return !findings
  | row :: _ ->
      (match row with
      | [ su; by; login ] ->
          if bool_of su then
            add "role_bypasses_rls" Critical role
              "role is SUPERUSER: privileges and RLS do not apply";
          if bool_of by then
            add "role_bypasses_rls" Critical role
              "role has BYPASSRLS: row-level security does not apply";
          if bool_of login then
            add "role_can_login" Warning role
              "role can log in directly (generated role is NOLOGIN; use SET ROLE from \
               the application's login role)"
      | _ -> ());
      (* ---- schemas *)
      let* srows =
        Pg_wire.query conn
          (Printf.sprintf
             "SELECT n.nspname, pg_catalog.has_schema_privilege(%s, n.oid, 'USAGE'), \
              pg_catalog.has_schema_privilege(%s, n.oid, 'CREATE') FROM \
              pg_catalog.pg_namespace n WHERE n.nspname IN %s ORDER BY 1"
             (lit role) (lit role) (in_list pl.schemas))
      in
      let present_schemas =
        List.filter_map (function n :: _ -> Some (str_of n) | [] -> None) srows
      in
      List.iter
        (fun s ->
          if not (List.mem s present_schemas) then
            add "schema_missing" Warning (q s) "schema does not exist")
        pl.schemas;
      List.iter
        (function
          | [ n; usage; create ] ->
              let n = str_of n in
              if not (bool_of usage) then
                add "missing_grant" Warning (q n) "role lacks USAGE on the schema";
              if bool_of create then
                add "over_broad_grant" Critical (q n) "role has CREATE on the schema"
          | _ -> ())
        srows;
      if present_schemas = [] then Lwt.return !findings
      else
        (* ---- tables *)
        let priv_cols =
          String.concat ", "
            (List.map
               (fun p ->
                 Printf.sprintf "pg_catalog.has_table_privilege(%s, c.oid, %s)" (lit role)
                   (lit p))
               table_privs)
        in
        let* trows =
          Pg_wire.query conn
            (Printf.sprintf
               "SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity, \
                pg_catalog.pg_get_userbyid(c.relowner), %s FROM pg_catalog.pg_class c \
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname \
                IN %s AND c.relkind IN ('r', 'p', 'v', 'm', 'f') ORDER BY 1, 2"
               priv_cols (in_list present_schemas))
        in
        let tables =
          List.filter_map
            (fun r ->
              match r with
              | s :: n :: rls :: force :: owner :: privs
                when List.length privs = List.length table_privs ->
                  Some
                    {
                      t_schema = str_of s;
                      t_name = str_of n;
                      rls = bool_of rls;
                      force = bool_of force;
                      owner = str_of owner;
                      tpriv = List.combine table_privs (List.map bool_of privs);
                    }
              | _ -> None)
            trows
        in
        let ccols =
          String.concat ", "
            (List.map
               (fun p ->
                 Printf.sprintf
                   "pg_catalog.has_column_privilege(%s, a.attrelid, a.attnum, %s)"
                   (lit role) (lit p))
               column_privs)
        in
        let* crows =
          Pg_wire.query conn
            (Printf.sprintf
               "SELECT n.nspname, c.relname, a.attname, %s FROM pg_catalog.pg_attribute \
                a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN \
                pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN \
                %s AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT \
                a.attisdropped ORDER BY 1, 2, a.attnum"
               ccols (in_list present_schemas))
        in
        let columns_of s n =
          List.filter_map
            (function
              | s' :: n' :: a :: privs when str_of s' = s && str_of n' = n ->
                  Some (str_of a, List.combine column_privs (List.map bool_of privs))
              | _ -> None)
            crows
        in
        let* prows =
          Pg_wire.query conn
            (Printf.sprintf
               "SELECT n.nspname, c.relname, pol.polname, pol.polcmd::text, \
                pol.polpermissive, (0::pg_catalog.oid = ANY (pol.polroles) OR EXISTS \
                (SELECT 1 FROM pg_catalog.unnest(pol.polroles) r WHERE r <> 0 AND \
                pg_catalog.pg_has_role(%s, r, 'USAGE'))), (pol.polroles = ARRAY[(SELECT \
                oid FROM pg_catalog.pg_roles WHERE rolname = %s)]::pg_catalog.oid[]), \
                pg_catalog.pg_get_expr(pol.polqual, pol.polrelid), \
                pg_catalog.pg_get_expr(pol.polwithcheck, pol.polrelid) FROM \
                pg_catalog.pg_policy pol JOIN pg_catalog.pg_class c ON c.oid = \
                pol.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname IN %s ORDER BY 1, 2, 3"
               (lit role) (lit role) (in_list present_schemas))
        in
        let policies_of s n =
          List.filter_map
            (function
              | [ s'; n'; name; cmd; perm; applies; exact; qual; check ]
                when str_of s' = s && str_of n' = n ->
                  Some
                    ( str_of name,
                      str_of cmd,
                      bool_of perm,
                      bool_of applies,
                      bool_of exact,
                      qual,
                      check )
              | _ -> None)
            prows
        in
        let find_plan s n =
          List.find_opt
            (fun (t : Rls_gen.table_plan) -> t.schema = s && t.name = n)
            pl.tables
        in
        (* plan tables missing from the database *)
        List.iter
          (fun (t : Rls_gen.table_plan) ->
            if
              List.mem t.schema present_schemas
              && not
                   (List.exists
                      (fun d -> d.t_schema = t.schema && d.t_name = t.name)
                      tables)
            then
              add "table_missing" Warning
                (Pg_quote.quote_qualified ~schema:t.schema ~name:t.name)
                "table in the policy does not exist in the database")
          pl.tables;
        List.iter
          (fun d ->
            let obj = Pg_quote.quote_qualified ~schema:d.t_schema ~name:d.t_name in
            let cols = columns_of d.t_schema d.t_name in
            match find_plan d.t_schema d.t_name with
            | None ->
                let tp =
                  List.filter_map (fun (p, b) -> if b then Some p else None) d.tpriv
                in
                let cp =
                  List.filter_map
                    (fun p ->
                      let cs =
                        List.filter_map
                          (fun (c, ps) -> if List.assoc p ps then Some (q c) else None)
                          cols
                      in
                      if cs = [] then None
                      else Some (Printf.sprintf "%s (%s)" p (String.concat ", " cs)))
                    column_privs
                in
                if tp <> [] then
                  add "over_broad_grant" Critical obj
                    (Printf.sprintf "table is not in the policy but the role has %s on it"
                       (String.concat ", " tp))
                else if cp <> [] then
                  add "over_broad_grant" Critical obj
                    (Printf.sprintf "table is not in the policy but the role has %s"
                       (String.concat "; " cp))
            | Some t ->
                let col_names = List.map fst cols in
                let expected_cols = function
                  | None -> []
                  | Some Policy.All -> col_names
                  | Some (Policy.Only l) -> l
                in
                (* columns named by the policy but absent *)
                let named =
                  List.sort_uniq compare
                    (List.concat_map
                       (function Some (Policy.Only l) -> l | _ -> [])
                       [ Some t.select; t.insert; t.update ])
                in
                List.iter
                  (fun c ->
                    if not (List.mem c col_names) then
                      add "column_missing" Warning obj
                        (Printf.sprintf "policy column %s does not exist" (q c)))
                  named;
                (* table-level privileges *)
                let expect_table = function
                  | "SELECT" -> t.select = Policy.All
                  | "INSERT" -> t.insert = Some Policy.All
                  | "UPDATE" -> t.update = Some Policy.All
                  | "DELETE" -> t.delete
                  | _ -> false
                in
                List.iter
                  (fun (p, have) ->
                    let want = expect_table p in
                    if have && not want then
                      add "over_broad_grant" Critical obj
                        (Printf.sprintf "role has table-level %s (policy allows %s)" p
                           (match p with
                           | "SELECT" | "INSERT" | "UPDATE" -> "only listed columns"
                           | _ -> "none"))
                    else if want && not have then
                      add "missing_grant" Warning obj
                        (Printf.sprintf "role lacks table-level %s" p))
                  d.tpriv;
                (* column-level privileges *)
                List.iter
                  (fun p ->
                    let want =
                      match p with
                      | "SELECT" -> expected_cols (Some t.select)
                      | "INSERT" -> expected_cols t.insert
                      | "UPDATE" -> expected_cols t.update
                      | _ -> []
                    in
                    let extra =
                      List.filter_map
                        (fun (c, ps) ->
                          if List.assoc p ps && not (List.mem c want) then Some (q c)
                          else None)
                        cols
                    in
                    let missing =
                      List.filter_map
                        (fun c ->
                          match List.assoc_opt c cols with
                          | Some ps when not (List.assoc p ps) -> Some (q c)
                          | _ -> None)
                        want
                    in
                    if extra <> [] then
                      add "over_broad_grant" Critical obj
                        (Printf.sprintf "role has %s on columns not in the policy: %s" p
                           (String.concat ", " extra));
                    if missing <> [] then
                      add "missing_grant" Warning obj
                        (Printf.sprintf "role lacks %s on policy columns: %s" p
                           (String.concat ", " missing)))
                  column_privs;
                (* row-level security *)
                if t.tenant <> [] then begin
                  if not d.rls then
                    add "rls_disabled" Critical obj "row-level security is not enabled";
                  if o.force_rls && not d.force then
                    add "rls_not_forced" Warning obj "row-level security is not FORCEd";
                  if d.owner = role then
                    add "role_owns_table" Critical obj
                      "the role owns the table, so RLS does not apply to it (unless \
                       FORCEd)";
                  let pols = policies_of d.t_schema d.t_name in
                  List.iter
                    (fun c ->
                      let name = Rls_gen.policy_name c in
                      match
                        List.find_opt (fun (n, _, _, _, _, _, _) -> n = name) pols
                      with
                      | None ->
                          add "policy_missing" Critical obj
                            (Printf.sprintf "policy %s is missing" name)
                      | Some (_, cmd, perm, _, exact, qual, check) ->
                          let problems = ref [] in
                          let pr s = problems := s :: !problems in
                          if cmd <> cmd_char c then pr "wrong command";
                          if not perm then pr "not PERMISSIVE";
                          if not exact then pr "not granted to exactly the role";
                          let need_using = c <> Rls_gen.Insert in
                          let need_check = c = Rls_gen.Insert || c = Rls_gen.Update in
                          let ok_expr e =
                            match e with
                            | Some e -> expression_matches t.tenant e
                            | None -> false
                          in
                          if need_using && not (ok_expr qual) then
                            pr "USING expression differs";
                          if need_check && not (ok_expr check) then
                            pr "WITH CHECK expression differs";
                          if !problems <> [] then
                            add "policy_mismatch" Critical obj
                              (Printf.sprintf "policy %s: %s" name
                                 (String.concat ", " (List.rev !problems))))
                    t.commands;
                  List.iter
                    (fun (n, cmd, perm, applies, _, _, _) ->
                      let ours =
                        List.exists
                          (fun c -> Rls_gen.policy_name c = n)
                          Rls_gen.[ Select; Insert; Update; Delete ]
                      in
                      let expected =
                        List.exists (fun c -> Rls_gen.policy_name c = n) t.commands
                      in
                      if ours && not expected then
                        add "unexpected_policy" Warning obj
                          (Printf.sprintf
                             "policy %s exists but the policy does not allow %s" n
                             (match policy_cmd_of_char cmd with
                             | Some c -> Rls_gen.cmd_to_string c
                             | None -> "that command"))
                      else if (not ours) && perm && applies then
                        add "foreign_policy" Critical obj
                          (Printf.sprintf
                             "permissive policy %s also applies to the role and widens \
                              the rows it can see"
                             (q n)))
                    pols
                end)
          tables;
        Lwt.return !findings

let check conn pl =
  let* () =
    Pg_wire.exec conn "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
  in
  Lwt.finalize
    (fun () ->
      let* fs = check_body conn pl in
      Lwt.return
        (List.sort_uniq
           (fun a b -> compare (a.obj, a.kind, a.message) (b.obj, b.kind, b.message))
           fs))
    (fun () ->
      Lwt.catch (fun () -> Pg_wire.exec conn "ROLLBACK") (fun _ -> Lwt.return_unit))
