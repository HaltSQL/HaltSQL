(* Unit tests: quoting, predicates, planning errors, SCRAM, base64, DSN parsing,
   expression matching, golden SQL validity and the CLI driver. *)

open Haltsql
open Haltsql_rlsgen

let check_str = Alcotest.(check string)
let check_bool = Alcotest.(check bool)

let load path =
  match Policy_load.of_file path with
  | Ok p -> p
  | Error errs ->
      Alcotest.failf "cannot load %s: %s" path
        (String.concat "; " (List.map Load_error.to_string errs))

let load_catalog path =
  match Catalog_load.of_file path with
  | Ok c -> c
  | Error _ -> Alcotest.failf "cannot load catalog %s" path

(* ------------------------------------------------------------------ quoting *)

let test_quote_ident () =
  List.iter
    (fun (input, expected) -> check_str input expected (Pg_quote.quote_ident input))
    [
      ("orders", "orders");
      ("tenant_id", "tenant_id");
      ("t1", "t1");
      ("_x", "_x");
      ("Customers", "\"Customers\"");
      ("user", "\"user\"");
      ("select", "\"select\"");
      ("order", "\"order\"");
      ("group", "\"group\"");
      ("limit", "\"limit\"");
      ("desc", "\"desc\"");
      ("between", "\"between\"");
      (* unreserved keywords stay bare, like quote_ident() *)
      ("name", "name");
      ("action", "action");
      ("role", "role");
      ("a\"b", "\"a\"\"b\"");
      ("1abc", "\"1abc\"");
      ("a$b", "\"a$b\"");
      ("with space", "\"with space\"");
      ("caf\xc3\xa9", "\"caf\xc3\xa9\"");
      ("", "\"\"");
    ]

let test_quote_literal () =
  check_str "plain" "'acme'" (Pg_quote.quote_literal "acme");
  check_str "quote" "'it''s'" (Pg_quote.quote_literal "it's");
  check_str "backslash" "E'a\\\\b'" (Pg_quote.quote_literal "a\\b");
  check_str "both" "E'\\\\'''" (Pg_quote.quote_literal "\\'");
  Alcotest.check_raises "NUL" (Invalid_argument "Pg_quote.quote_literal: NUL byte")
    (fun () -> ignore (Pg_quote.quote_literal "a\000b"));
  check_str "qualified" "app.\"Customers\""
    (Pg_quote.quote_qualified ~schema:"app" ~name:"Customers")

let test_dollar_quote () =
  check_str "plain" "$haltsql$ x $haltsql$" (Pg_quote.dollar_quote " x ");
  check_str "collision" "$haltsql1$ $haltsql$ $haltsql1$"
    (Pg_quote.dollar_quote " $haltsql$ ")

(* --------------------------------------------------------------- predicates *)

let term ?(is_set = false) ?cast column setting : Rls_gen.tenant_term =
  { column; setting; context_field = "f"; is_set; cast }

let test_predicates () =
  check_str "scalar text"
    "tenant_id = NULLIF(pg_catalog.current_setting('haltsql.tenant_id', true), '')"
    (Rls_gen.predicate [ term "tenant_id" "haltsql.tenant_id" ]);
  check_str "scalar cast"
    "\"OrgId\" = NULLIF(pg_catalog.current_setting('p.org_id', true), '')::int8"
    (Rls_gen.predicate [ term ~cast:"int8" "OrgId" "p.org_id" ]);
  check_str "set"
    "tenant_id = ANY \
     (pg_catalog.array_remove(pg_catalog.string_to_array(NULLIF(pg_catalog.current_setting('haltsql.tenant_ids', \
     true), ''), ','), ''))"
    (Rls_gen.predicate [ term ~is_set:true "tenant_id" "haltsql.tenant_ids" ]);
  check_str "set cast"
    "org_id = ANY \
     (pg_catalog.array_remove(pg_catalog.string_to_array(NULLIF(pg_catalog.current_setting('h.org_ids', \
     true), ''), ','), '')::uuid[])"
    (Rls_gen.predicate [ term ~is_set:true ~cast:"uuid" "org_id" "h.org_ids" ]);
  check_str "composite"
    "org_id = NULLIF(pg_catalog.current_setting('h.org_id', true), '') AND workspace_id \
     = NULLIF(pg_catalog.current_setting('h.workspace_id', true), '')"
    (Rls_gen.predicate [ term "org_id" "h.org_id"; term "workspace_id" "h.workspace_id" ])

(* -------------------------------------------------------------------- plans *)

let opts = Rls_gen.default_options

let plan_err o p =
  match Rls_gen.plan o p with Ok _ -> Alcotest.fail "expected an error" | Error e -> e

let test_plan_composite () =
  let p = load "../fixtures/policies/composite.yaml" in
  match Rls_gen.plan opts p with
  | Error e -> Alcotest.fail e
  | Ok pl ->
      Alcotest.(check (list string)) "schemas" [ "app" ] pl.schemas;
      Alcotest.(check (list string))
        "tables"
        [ "org_members"; "plans"; "projects"; "tasks" ]
        (List.map (fun (t : Rls_gen.table_plan) -> t.name) pl.tables);
      let projects =
        List.find (fun (t : Rls_gen.table_plan) -> t.name = "projects") pl.tables
      in
      Alcotest.(check (list string))
        "settings"
        [ "haltsql.org_id"; "haltsql.workspace_id" ]
        (List.map (fun (t : Rls_gen.tenant_term) -> t.setting) projects.tenant);
      check_bool "only select policy" true (projects.commands = [ Rls_gen.Select ]);
      let plans =
        List.find (fun (t : Rls_gen.table_plan) -> t.name = "plans") pl.tables
      in
      check_bool "global table has no policies" true
        (plans.commands = [] && plans.tenant = []);
      Alcotest.(check int) "warnings: 5 unknown types" 5 (List.length pl.warnings)

let test_plan_writes () =
  let p = load "../fixtures/policies/writes.yaml" in
  match Rls_gen.plan opts p with
  | Error e -> Alcotest.fail e
  | Ok pl ->
      let find n = List.find (fun (t : Rls_gen.table_plan) -> t.name = n) pl.tables in
      check_bool "tickets: all four" true
        ((find "tickets").commands = Rls_gen.[ Select; Insert; Update; Delete ]);
      check_bool "comments: select+insert" true
        ((find "ticket_comments").commands = Rls_gen.[ Select; Insert ]);
      check_bool "tags: select+update" true
        ((find "tags").commands = Rls_gen.[ Select; Update ]);
      check_bool "orders: select" true ((find "orders").commands = Rls_gen.[ Select ]);
      check_bool "tickets update cols" true
        ((find "tickets").update
        = Some
            (Policy.Only [ "status"; "priority"; "assignee_id"; "title"; "updated_at" ]))

let test_plan_errors () =
  let p = load "../fixtures/policies/hierarchical.yaml" in
  check_str "unknown set field"
    "--set-field \"tenant_id\" is not a tenancy context field of this policy (fields: \
     tenant_ids)"
    (plan_err { opts with set_fields = [ "tenant_id" ] } p);
  check_str "reserved role" "--role \"PUBLIC\" is a reserved role name"
    (plan_err { opts with role = "PUBLIC" } p);
  check_str "pg_ role" "--role \"pg_monitor\": names starting with pg_ are reserved"
    (plan_err { opts with role = "pg_monitor" } p);
  check_str "empty role" "--role must not be empty" (plan_err { opts with role = "" } p);
  check_str "long role" "--role is longer than 63 bytes"
    (plan_err { opts with role = String.make 64 'a' } p);
  check_str "owner = role" "--owner-role must differ from --role"
    (plan_err { opts with owner_role = Some "haltsql_agent" } p);
  check_str "bad prefix"
    "invalid setting prefix \"a-b\": use dot-separated names of letters, digits and \
     underscores (not starting with a digit)"
    (plan_err { opts with setting_prefix = "a-b" } p);
  check_str "empty prefix part"
    "invalid setting prefix \"a..b\": use dot-separated names of letters, digits and \
     underscores (not starting with a digit)"
    (plan_err { opts with setting_prefix = "a..b" } p)

let catalog_with ty : Catalog.t =
  {
    tables =
      [
        {
          schema = "app";
          name = "accounts";
          columns = [ { col_name = "tenant_id"; col_type = Some ty } ];
        };
      ];
  }

let test_plan_types () =
  let p = load "../fixtures/policies/hierarchical.yaml" in
  check_str "array type"
    "app.accounts.tenant_id: array-typed tenant columns (text[]) are not supported"
    (plan_err { opts with catalog = Some (catalog_with "text[]") } p);
  check_str "quoted type"
    "app.accounts.tenant_id: unsupported column type \"\\\"evil\\\"\""
    (plan_err { opts with catalog = Some (catalog_with "\"evil\"") } p);
  let cast_of ty =
    match Rls_gen.plan { opts with catalog = Some (catalog_with ty) } p with
    | Error e -> Alcotest.fail e
    | Ok pl ->
        let t =
          List.find (fun (t : Rls_gen.table_plan) -> t.name = "accounts") pl.tables
        in
        (List.hd t.tenant).cast
  in
  Alcotest.(check (option string)) "text" None (cast_of "text");
  Alcotest.(check (option string)) "varchar(64)" None (cast_of "character varying(64)");
  Alcotest.(check (option string)) "int8" (Some "int8") (cast_of "int8");
  Alcotest.(check (option string)) "upper-case normalized" (Some "uuid") (cast_of "UUID");
  Alcotest.(check (option string))
    "numeric(10,0)" (Some "numeric(10,0)") (cast_of "numeric(10,0)")

let test_warnings () =
  let p = load "../fixtures/policies/hierarchical.yaml" in
  match Rls_gen.plan opts p with
  | Error e -> Alcotest.fail e
  | Ok pl -> (
      Alcotest.(check (list string))
        "warnings"
        [
          "app.accounts.tenant_id: column type unknown (no catalog entry); the setting \
           is compared as text. Pass --catalog if the column is not text.";
          "app.transactions.tenant_id: column type unknown (no catalog entry); the \
           setting is compared as text. Pass --catalog if the column is not text.";
          "context field \"tenant_ids\" looks like a set of values; pass --set-field \
           tenant_ids if the context carries a list";
        ]
        pl.warnings;
      match Rls_gen.plan { opts with set_fields = [ "tenant_ids" ] } p with
      | Ok pl -> Alcotest.(check int) "no set hint" 2 (List.length pl.warnings)
      | Error e -> Alcotest.fail e)

let test_saas_catalog_types () =
  (* saas.yaml has catalog: ../catalogs/saas.json with tenant_id text: no warnings *)
  let p = load "../fixtures/policies/saas.yaml" in
  match Rls_gen.plan opts p with
  | Ok pl -> Alcotest.(check (list string)) "no warnings" [] pl.warnings
  | Error e -> Alcotest.fail e

let test_deterministic () =
  let p = load "fixtures/saas_writes.yaml" in
  let o =
    {
      opts with
      set_fields = [ "org_ids" ];
      catalog = Some (load_catalog "fixtures/saas_writes_catalog.json");
    }
  in
  match (Rls_gen.generate o p, Rls_gen.generate o p) with
  | Ok (a, _), Ok (b, _) -> check_str "same output" a b
  | _ -> Alcotest.fail "generate failed"

let test_header_sanitized () =
  let p = load "../fixtures/policies/saas.yaml" in
  let p = { p with name = "evil\nDROP TABLE x;" } in
  match Rls_gen.generate opts p with
  | Error e -> Alcotest.fail e
  | Ok (sql, _) ->
      check_bool "no injected line" false
        (List.exists (fun l -> l = "DROP TABLE x;") (String.split_on_char '\n' sql));
      check_bool "sanitized comment" true
        (List.mem "-- Policy: evil DROP TABLE x;" (String.split_on_char '\n' sql))

(* Every golden file must be valid PostgreSQL 17 syntax. *)
let test_golden_parses () =
  List.iter
    (fun n ->
      let path = Filename.concat "golden" (n ^ ".sql") in
      let sql = In_channel.with_open_bin path In_channel.input_all in
      check_bool (n ^ " non-empty") true (String.length sql > 100);
      match Haltsql_pgquery.Pgquery_raw.parse_json sql with
      | Ok _ -> ()
      | Error (m, pos) -> Alcotest.failf "%s does not parse: %s at %d" path m pos)
    [ "saas"; "composite"; "hierarchical"; "writes"; "mixed_case"; "options" ]

(* -------------------------------------------------------------------- SCRAM *)

(* RFC 7677 section 3 example. *)
let test_scram_rfc7677 () =
  let st, first = Scram.client_first ~user:"user" ~nonce:"rOprNGfwEbeRWgbNEkqO" in
  check_str "client-first" "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" first;
  let server_first =
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
  in
  match Scram.client_final st ~password:"pencil" ~server_first with
  | Error e -> Alcotest.fail e
  | Ok (st, final) ->
      check_str "client-final"
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        final;
      Alcotest.(check (result unit string))
        "server-final ok" (Ok ())
        (Scram.verify_server_final st "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
      Alcotest.(check (result unit string))
        "tampered server-final"
        (Error
           "SCRAM: server signature mismatch (server did not prove it knows the password)")
        (Scram.verify_server_final st "v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
      Alcotest.(check (result unit string))
        "server error" (Error "SCRAM: server error: invalid-proof")
        (Scram.verify_server_final st "e=invalid-proof")

let test_scram_rejects () =
  let st, _ = Scram.client_first ~user:"" ~nonce:"abc" in
  let err sf =
    match Scram.client_final st ~password:"x" ~server_first:sf with
    | Ok _ -> "ok"
    | Error e -> e
  in
  check_str "nonce not extended" "SCRAM: server nonce does not extend the client nonce"
    (err "r=xyz123,s=c2FsdA==,i=4096");
  check_str "same nonce" "SCRAM: server nonce does not extend the client nonce"
    (err "r=abc,s=c2FsdA==,i=4096");
  check_str "bad iterations" "SCRAM: iteration count out of range"
    (err "r=abcd,s=c2FsdA==,i=0");
  check_str "bad salt" "SCRAM: invalid salt" (err "r=abcd,s=!!!,i=4096");
  check_str "malformed" "SCRAM: malformed server-first-message" (err "garbage");
  Alcotest.(check (result unit string))
    "final before exchange" (Error "SCRAM: exchange incomplete")
    (Scram.verify_server_final st "v=AAAA")

let test_constant_time_equal () =
  check_bool "eq" true (Scram.constant_time_equal "abc" "abc");
  check_bool "neq" false (Scram.constant_time_equal "abc" "abd");
  check_bool "len" false (Scram.constant_time_equal "abc" "abcd");
  check_bool "empty" true (Scram.constant_time_equal "" "")

let test_b64 () =
  List.iter
    (fun (raw, enc) ->
      check_str ("enc " ^ raw) enc (B64.encode raw);
      Alcotest.(check (option string)) ("dec " ^ enc) (Some raw) (B64.decode enc))
    [
      ("", "");
      ("f", "Zg==");
      ("fo", "Zm8=");
      ("foo", "Zm9v");
      ("foob", "Zm9vYg==");
      ("fooba", "Zm9vYmE=");
      ("foobar", "Zm9vYmFy");
    ];
  Alcotest.(check (option string)) "bad length" None (B64.decode "abc");
  Alcotest.(check (option string)) "bad char" None (B64.decode "ab!d");
  Alcotest.(check (option string)) "inner padding" None (B64.decode "Zg==Zg==")

(* ---------------------------------------------------------------------- DSN *)

let env_of kvs k = List.assoc_opt k kvs

let test_dsn () =
  let env = env_of [ ("USER", "osuser"); ("PGPASSWORD", "envpw") ] in
  (match
     Pg_wire.parse_dsn ~env
       "postgres://alice:p%40ss@db.example.com:6543/app?sslmode=verify-full&connect_timeout=3"
   with
  | Error e -> Alcotest.fail e
  | Ok d ->
      check_str "host" "db.example.com" d.host;
      Alcotest.(check int) "port" 6543 d.port;
      check_str "user" "alice" d.user;
      Alcotest.(check (option string)) "password" (Some "p@ss") d.password;
      check_str "db" "app" d.database;
      check_bool "sslmode" true (d.sslmode = Pg_wire.Verify_full);
      Alcotest.(check (float 0.)) "timeout" 3. d.connect_timeout;
      check_str "redacted" "postgres://alice@db.example.com:6543/app?sslmode=verify-full"
        (Pg_wire.dsn_to_string_redacted d));
  (match Pg_wire.parse_dsn ~env "postgresql://" with
  | Error e -> Alcotest.fail e
  | Ok d ->
      check_str "default host" "localhost" d.host;
      Alcotest.(check int) "default port" 5432 d.port;
      check_str "default user" "osuser" d.user;
      check_str "default db" "osuser" d.database;
      Alcotest.(check (option string)) "env password" (Some "envpw") d.password;
      check_bool "default sslmode" true (d.sslmode = Pg_wire.Prefer));
  (match Pg_wire.parse_dsn ~env "postgres://u@[::1]:5417/d?sslmode=disable" with
  | Error e -> Alcotest.fail e
  | Ok d ->
      check_str "ipv6" "::1" d.host;
      Alcotest.(check int) "ipv6 port" 5417 d.port;
      check_str "ipv6 redacted" "postgres://u@[::1]:5417/d?sslmode=disable"
        (Pg_wire.dsn_to_string_redacted d));
  let err s = match Pg_wire.parse_dsn ~env s with Ok _ -> "ok" | Error e -> e in
  check_str "scheme" "invalid DSN: expected postgres://user:password@host:port/dbname"
    (err "mysql://x");
  check_str "unknown param" "invalid DSN: unsupported parameter \"options\""
    (err "postgres://u@h/d?options=-c%20x");
  check_str "bad port" "invalid DSN: invalid port \"99999\""
    (err "postgres://u@h:99999/d");
  check_str "bad sslmode" "unsupported sslmode \"maybe\""
    (err "postgres://u@h/d?sslmode=maybe");
  check_str "bad escape" "invalid percent-escape" (err "postgres://u%zz@h/d");
  check_str "no user" "invalid DSN: no user name given"
    (match Pg_wire.parse_dsn ~env:(fun _ -> None) "postgres://h/d" with
    | Ok _ -> "ok"
    | Error e -> e)

(* ------------------------------------------------------- expression matching *)

let test_expression_matches () =
  let t1 = term "tenant_id" "haltsql.tenant_id" in
  let deparsed =
    "(tenant_id = NULLIF(current_setting('haltsql.tenant_id'::text, true), ''::text))"
  in
  check_bool "deparsed matches" true (Rls_check.expression_matches [ t1 ] deparsed);
  check_bool "other setting" false
    (Rls_check.expression_matches [ t1 ]
       "(tenant_id = NULLIF(current_setting('app.tenant_id'::text, true), ''::text))");
  check_bool "other column" false
    (Rls_check.expression_matches [ t1 ]
       "(owner_tenant_id = NULLIF(current_setting('haltsql.tenant_id'::text, true), \
        ''::text))");
  check_bool "OR true widened" false
    (Rls_check.expression_matches [ t1 ] (deparsed ^ " OR true"));
  check_bool "extra setting" false
    (Rls_check.expression_matches [ t1 ]
       (deparsed ^ " OR (tenant_id = current_setting('x.y'::text, true))"));
  check_bool "quoted column" true
    (Rls_check.expression_matches
       [ term "TenantId" "haltsql.tenant_id" ]
       "(\"TenantId\" = NULLIF(current_setting('haltsql.tenant_id'::text, true), \
        ''::text))");
  check_bool "IS NULL widened" false
    (Rls_check.expression_matches [ t1 ] (deparsed ^ " OR (tenant_id IS NULL)"));
  check_bool "NOT widened" false
    (Rls_check.expression_matches [ t1 ]
       "(NOT (tenant_id <> NULLIF(current_setting('haltsql.tenant_id'::text, true), \
        ''::text)))");
  check_bool "set form" true
    (Rls_check.expression_matches
       [ term ~is_set:true ~cast:"int8" "org_id" "haltsql.org_ids" ]
       "(org_id = ANY \
        ((array_remove(string_to_array(NULLIF(current_setting('haltsql.org_ids'::text, \
        true), ''::text), ','::text), ''::text))::bigint[]))");
  check_bool "empty terms" false (Rls_check.expression_matches [] "true")

(* ---------------------------------------------------------------------- CLI *)

let cli = "./cli/rls_cli.exe"

let run_cli args =
  let out = Filename.temp_file "rls_cli" ".out" in
  let err = Filename.temp_file "rls_cli" ".err" in
  let cmd =
    Printf.sprintf "%s %s > %s 2> %s" cli
      (String.concat " " (List.map Filename.quote args))
      (Filename.quote out) (Filename.quote err)
  in
  let code = Sys.command cmd in
  let read f = In_channel.with_open_bin f In_channel.input_all in
  let o = read out and e = read err in
  Sys.remove out;
  Sys.remove err;
  (code, o, e)

let test_cli () =
  let code, out, _ =
    run_cli [ "generate"; "-p"; "../fixtures/policies/saas.yaml"; "--json" ]
  in
  Alcotest.(check int) "generate --json exit" 0 code;
  let j = Yojson.Safe.from_string out in
  let open Yojson.Safe.Util in
  check_str "json policy" "saas" (j |> member "policy" |> to_string);
  check_bool "json sql" true (String.length (j |> member "sql" |> to_string) > 0);
  Alcotest.(check int) "json tables" 9 (j |> member "tables" |> to_list |> List.length);
  let code, _, err = run_cli [ "generate"; "-p"; "missing.yaml" ] in
  Alcotest.(check int) "missing policy exit" 2 code;
  check_str "missing policy msg" "haltsql: policy file not found: missing.yaml\n" err;
  let code, _, err =
    run_cli [ "generate"; "-p"; "../fixtures/policies/saas.yaml"; "--set-field"; "nope" ]
  in
  Alcotest.(check int) "bad set-field exit" 2 code;
  check_str "bad set-field msg"
    "haltsql: --set-field \"nope\" is not a tenancy context field of this policy \
     (fields: tenant_id)\n"
    err;
  let out_file = Filename.temp_file "rls" ".sql" in
  let code, out, _ =
    run_cli [ "generate"; "-p"; "../fixtures/policies/saas.yaml"; "-o"; out_file ]
  in
  Alcotest.(check int) "-o exit" 0 code;
  check_str "-o stdout empty" "" out;
  let written = In_channel.with_open_bin out_file In_channel.input_all in
  let golden = In_channel.with_open_bin "golden/saas.sql" In_channel.input_all in
  check_str "-o content = golden" golden written;
  Sys.remove out_file;
  let code, _, err =
    Unix.putenv "HALTSQL_DSN" "";
    run_cli [ "check"; "-p"; "../fixtures/policies/saas.yaml"; "--dsn"; "mysql://x" ]
  in
  Alcotest.(check int) "check bad dsn exit" 2 code;
  check_str "check bad dsn msg"
    "haltsql: invalid DSN: expected postgres://user:password@host:port/dbname\n" err;
  (* nothing listens on port 1: connection refused, exit 2, password never echoed *)
  let code, _, err =
    run_cli
      [
        "check";
        "-p";
        "../fixtures/policies/saas.yaml";
        "--dsn";
        "postgres://u:sup3rsecret@127.0.0.1:1/d?sslmode=disable&connect_timeout=2";
      ]
  in
  Alcotest.(check int) "check unreachable exit" 2 code;
  check_bool "no password in error" false
    (let re = "sup3rsecret" in
     let n = String.length err and m = String.length re in
     let rec go i = i + m <= n && (String.sub err i m = re || go (i + 1)) in
     go 0);
  check_bool "redacted dsn in error" true
    (String.length err > 0
    && String.sub err 0 (String.length "haltsql: cannot check postgres://u@127.0.0.1:1/d")
       = "haltsql: cannot check postgres://u@127.0.0.1:1/d")

let tests =
  [
    ("quote_ident", `Quick, test_quote_ident);
    ("quote_literal", `Quick, test_quote_literal);
    ("dollar_quote", `Quick, test_dollar_quote);
    ("predicates", `Quick, test_predicates);
    ("plan composite", `Quick, test_plan_composite);
    ("plan writes", `Quick, test_plan_writes);
    ("plan errors", `Quick, test_plan_errors);
    ("plan types", `Quick, test_plan_types);
    ("warnings", `Quick, test_warnings);
    ("saas catalog types", `Quick, test_saas_catalog_types);
    ("deterministic", `Quick, test_deterministic);
    ("header sanitized", `Quick, test_header_sanitized);
    ("golden parses", `Quick, test_golden_parses);
    ("scram rfc7677", `Quick, test_scram_rfc7677);
    ("scram rejects", `Quick, test_scram_rejects);
    ("constant_time_equal", `Quick, test_constant_time_equal);
    ("base64", `Quick, test_b64);
    ("dsn", `Quick, test_dsn);
    ("expression_matches", `Quick, test_expression_matches);
    ("cli", `Quick, test_cli);
  ]
