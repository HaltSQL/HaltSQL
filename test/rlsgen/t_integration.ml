(* Live test against the lab Postgres: create haltsql_rls_test, load
   lab/schemas/saas_shared.sql, apply the generated SQL (twice: idempotent), then act
   as the generated role and check isolation, column denial and write checks; finally
   `rls check` must report no drift, and exactly the injected drift afterwards.

   Skipped (with a message) when Postgres is not reachable. *)

open Lwt.Syntax
open Haltsql
open Haltsql_rlsgen

let db_name = "haltsql_rls_test"
let role = "haltsql_rls_it_agent"
let role2 = "HaltSQL \"IT\" agent"

let admin_dsn_string =
  match Sys.getenv_opt "HALTSQL_TEST_PG_DSN" with
  | Some s when s <> "" -> s
  | _ ->
      "postgres://postgres:haltlab@localhost:5417/postgres?sslmode=disable&connect_timeout=3"

let admin_dsn =
  match Pg_wire.parse_dsn admin_dsn_string with
  | Ok d -> d
  | Error e -> failwith ("HALTSQL_TEST_PG_DSN: " ^ e)

let test_dsn = { admin_dsn with database = db_name }

(* Probed once. *)
let available =
  lazy
    (match
       Lwt_main.run
         (Lwt.catch
            (fun () ->
              let* c = Pg_wire.connect admin_dsn in
              let* () = Pg_wire.close c in
              Lwt.return_ok ())
            (fun e -> Lwt.return_error (Printexc.to_string e)))
     with
    | Ok () -> true
    | Error e ->
        Printf.printf
          "SKIP rlsgen integration: Postgres not reachable at %s (%s); run `make -C lab \
           up`\n\
           %!"
          (Pg_wire.dsn_to_string_redacted admin_dsn)
          e;
        false)

let require_pg () = if not (Lazy.force available) then Alcotest.skip ()

let options () =
  let catalog =
    match Catalog_load.of_file "fixtures/saas_writes_catalog.json" with
    | Ok c -> c
    | Error _ -> failwith "catalog"
  in
  {
    Rls_gen.default_options with
    role;
    set_fields = [ "org_ids" ];
    catalog = Some catalog;
  }

let policy () =
  match Policy_load.of_file "fixtures/saas_writes.yaml" with
  | Ok p -> p
  | Error _ -> failwith "policy"

let plan () =
  match Rls_gen.plan (options ()) (policy ()) with Ok pl -> pl | Error e -> failwith e

let lit = Pg_quote.quote_literal

let seed_sql =
  {|
INSERT INTO app.currencies VALUES ('USD', 'US dollar', '$', 2);
INSERT INTO app.customers (id, tenant_id, name, email, phone, ssn, country, created_at) VALUES
  (1, 'A', 'a-cust', 'a@example.com', '555', '111', 'US', now()),
  (2, 'B', 'b-cust', 'b@example.com', NULL, NULL, 'US', now()),
  (3, NULL, 'legacy', NULL, NULL, NULL, 'US', now()),
  (4, '', 'blank', NULL, NULL, NULL, 'US', now());
INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, currency, note, created_at) VALUES
  (1, 'A', 1, 'open', 100, 'USD', NULL, now()),
  (2, 'A', 1, 'paid', 200, 'USD', NULL, now()),
  (3, 'B', 2, 'open', 300, 'USD', NULL, now()),
  (4, NULL, 3, 'open', 400, 'USD', NULL, now()),
  (5, '', 4, 'open', 500, 'USD', NULL, now());
SELECT pg_catalog.setval(pg_catalog.pg_get_serial_sequence('app.orders', 'id'), 100);
CREATE TABLE app.ledgers (id bigserial PRIMARY KEY, org_id bigint, amount_cents bigint NOT NULL);
INSERT INTO app.ledgers (org_id, amount_cents) VALUES (10, 1), (11, 2), (12, 3), (NULL, 4);
ALTER TABLE app.ledgers OWNER TO haltlab_owner;
CREATE TABLE app.secrets (id int PRIMARY KEY, tenant_id text, value text);
INSERT INTO app.secrets VALUES (1, 'A', 'shh');
ALTER TABLE app.secrets OWNER TO haltlab_owner;
|}

let drop_all () =
  Pg_wire.with_connection admin_dsn (fun c ->
      let* () =
        Pg_wire.exec c (Printf.sprintf "DROP DATABASE IF EXISTS %s WITH (FORCE)" db_name)
      in
      let* () = Pg_wire.exec c (Printf.sprintf "DROP ROLE IF EXISTS %s" role) in
      Pg_wire.exec c
        (Printf.sprintf "DROP ROLE IF EXISTS %s" (Pg_quote.quote_ident role2)))

let setup () =
  let* () = drop_all () in
  let* () =
    Pg_wire.with_connection admin_dsn (fun c ->
        Pg_wire.exec c (Printf.sprintf "CREATE DATABASE %s" db_name))
  in
  let schema =
    In_channel.with_open_bin "../../lab/schemas/saas_shared.sql" In_channel.input_all
  in
  let sql, _ = Result.get_ok (Rls_gen.generate (options ()) (policy ())) in
  Pg_wire.with_connection test_dsn (fun c ->
      let* () = Pg_wire.exec c schema in
      let* () = Pg_wire.exec c seed_sql in
      let* () = Pg_wire.exec c sql in
      (* idempotent: a second run must succeed and converge *)
      Pg_wire.exec c sql)

type outcome = Rows of string option list list | Failed of string

(* One transaction as the agent role, with the given settings; always rolled back. *)
let as_agent_on ?(role = role) c ?(settings = []) sql =
  let* () = Pg_wire.exec c "BEGIN" in
  Lwt.finalize
    (fun () ->
      Lwt.catch
        (fun () ->
          let* () =
            Lwt_list.iter_s
              (fun (k, v) ->
                Pg_wire.exec c
                  (Printf.sprintf "SELECT pg_catalog.set_config(%s, %s, true)" (lit k)
                     (lit v)))
              settings
          in
          let* () =
            Pg_wire.exec c
              (Printf.sprintf "SET LOCAL ROLE %s" (Pg_quote.quote_ident role))
          in
          let* rows = Pg_wire.query c sql in
          Lwt.return (Rows rows))
        (function
          | Pg_wire.Pg_error { code; _ } -> Lwt.return (Failed code) | e -> Lwt.reraise e))
    (fun () -> Pg_wire.exec c "ROLLBACK")

let as_agent ?role ?settings sql =
  Lwt_main.run
    (Pg_wire.with_connection test_dsn (fun c -> as_agent_on ?role c ?settings sql))

let outcome =
  let pp ppf = function
    | Rows rows ->
        Format.fprintf ppf "Rows [%s]"
          (String.concat "; "
             (List.map
                (fun r ->
                  "("
                  ^ String.concat ", " (List.map (Option.value ~default:"NULL") r)
                  ^ ")")
                rows))
    | Failed code -> Format.fprintf ppf "Failed %s" code
  in
  Alcotest.testable pp ( = )

let rows l = Rows (List.map (List.map Option.some) l)
let ids l = rows (List.map (fun i -> [ string_of_int i ]) l)
let a = [ ("haltsql.tenant_id", "A") ]
let b = [ ("haltsql.tenant_id", "B") ]
let check = Alcotest.check outcome

(* ------------------------------------------------------------------- tests *)

let test_setup () =
  require_pg ();
  Lwt_main.run (setup ())

let test_tenant_isolation () =
  require_pg ();
  check "A sees only A"
    (ids [ 1; 2 ])
    (as_agent ~settings:a "SELECT id FROM app.orders ORDER BY id");
  check "B sees only B" (ids [ 3 ])
    (as_agent ~settings:b "SELECT id FROM app.orders ORDER BY id");
  check "A customers"
    (rows [ [ "1"; "a-cust" ] ])
    (as_agent ~settings:a "SELECT id, name FROM app.customers ORDER BY id");
  check "unknown tenant sees nothing" (rows [ [ "0" ] ])
    (as_agent ~settings:[ ("haltsql.tenant_id", "C") ] "SELECT count(*) FROM app.orders");
  check "global table readable" (rows [ [ "USD" ] ])
    (as_agent "SELECT code FROM app.currencies")

let test_missing_setting () =
  require_pg ();
  check "never set: no rows" (rows [ [ "0" ] ])
    (as_agent "SELECT count(*) FROM app.orders");
  check "empty string: no rows (blank tenant row stays hidden)" (rows [ [ "0" ] ])
    (as_agent ~settings:[ ("haltsql.tenant_id", "") ] "SELECT count(*) FROM app.orders");
  (* After a SET LOCAL transaction ends, current_setting(..., true) returns '' (not NULL)
     for the rest of the session; NULLIF keeps that fail-closed. *)
  let r =
    Lwt_main.run
      (Pg_wire.with_connection test_dsn (fun c ->
           let* first = as_agent_on c ~settings:a "SELECT count(*) FROM app.orders" in
           let* raw =
             Pg_wire.query c "SELECT current_setting('haltsql.tenant_id', true) IS NULL"
           in
           let* second = as_agent_on c "SELECT count(*) FROM app.orders" in
           Lwt.return (first, raw, second)))
  in
  let first, raw, second = r in
  check "with setting" (rows [ [ "2" ] ]) first;
  Alcotest.(check (list (list (option string))))
    "setting is '' not NULL" [ [ Some "f" ] ] raw;
  check "after reset: no rows" (rows [ [ "0" ] ]) second;
  check "set field missing: no ledgers" (rows [ [ "0" ] ])
    (as_agent "SELECT count(*) FROM app.ledgers")

let test_set_field () =
  require_pg ();
  check "org set 10,12"
    (rows [ [ "1" ]; [ "3" ] ])
    (as_agent
       ~settings:[ ("haltsql.org_ids", "10,12") ]
       "SELECT amount_cents FROM app.ledgers ORDER BY amount_cents");
  check "org set 11" (rows [ [ "2" ] ])
    (as_agent
       ~settings:[ ("haltsql.org_ids", "11") ]
       "SELECT amount_cents FROM app.ledgers");
  check "empty elements ignored" (rows [ [ "2" ] ])
    (as_agent
       ~settings:[ ("haltsql.org_ids", ",11,") ]
       "SELECT amount_cents FROM app.ledgers");
  check "non-numeric setting fails closed" (Failed "22P02")
    (as_agent
       ~settings:[ ("haltsql.org_ids", "abc") ]
       "SELECT amount_cents FROM app.ledgers")

let test_column_denial () =
  require_pg ();
  check "denied column" (Failed "42501")
    (as_agent ~settings:a "SELECT email FROM app.customers");
  check "star includes denied columns" (Failed "42501")
    (as_agent ~settings:a "SELECT * FROM app.customers");
  check "table outside the policy" (Failed "42501")
    (as_agent ~settings:a "SELECT id FROM app.secrets");
  check "insert into read-only table" (Failed "42501")
    (as_agent ~settings:a
       "INSERT INTO app.customers (tenant_id, name, country, created_at) VALUES ('A', \
        'x', 'US', now())");
  check "delete on read-only table" (Failed "42501")
    (as_agent ~settings:a "DELETE FROM app.customers")

let test_writes () =
  require_pg ();
  check "insert own tenant" (ids [ 101 ])
    (as_agent ~settings:a
       "INSERT INTO app.orders (tenant_id, customer_id, status, total_cents, currency, \
        created_at) VALUES ('A', 1, 'new', 1, 'USD', now()) RETURNING id");
  check "insert other tenant" (Failed "42501")
    (as_agent ~settings:a
       "INSERT INTO app.orders (tenant_id, customer_id, status, total_cents, currency, \
        created_at) VALUES ('B', 2, 'new', 1, 'USD', now())");
  check "insert without setting" (Failed "42501")
    (as_agent
       "INSERT INTO app.orders (tenant_id, customer_id, status, total_cents, currency, \
        created_at) VALUES ('A', 1, 'new', 1, 'USD', now())");
  check "update own row" (ids [ 1 ])
    (as_agent ~settings:a
       "UPDATE app.orders SET status = 'shipped' WHERE id = 1 RETURNING id");
  check "update other tenant's row: invisible" (ids [])
    (as_agent ~settings:a "UPDATE app.orders SET status = 'x' WHERE id = 3 RETURNING id");
  check "move row to another tenant" (Failed "42501")
    (as_agent ~settings:a "UPDATE app.orders SET tenant_id = 'B' WHERE id = 1");
  check "update column outside the policy" (Failed "42501")
    (as_agent ~settings:a "UPDATE app.orders SET total_cents = 0 WHERE id = 1");
  check "delete other tenant's row: invisible" (ids [])
    (as_agent ~settings:a "DELETE FROM app.orders WHERE id = 3 RETURNING id");
  check "delete own row" (ids [ 2 ])
    (as_agent ~settings:a "DELETE FROM app.orders WHERE id = 2 RETURNING id")

let run_check () =
  Lwt_main.run (Pg_wire.with_connection test_dsn (fun c -> Rls_check.check c (plan ())))

let finding_strings fs =
  List.map
    (fun (f : Rls_check.finding) ->
      Printf.sprintf "%s %s %s: %s"
        (Rls_check.severity_to_string f.severity)
        f.kind f.obj f.message)
    fs

let test_check_no_drift () =
  require_pg ();
  Alcotest.(check (list string)) "no drift" [] (finding_strings (run_check ()));
  (* the CLI: password from PGPASSWORD, never in argv *)
  Option.iter (Unix.putenv "PGPASSWORD") test_dsn.password;
  let dsn =
    Printf.sprintf "postgres://%s@%s:%d/%s?sslmode=disable" test_dsn.user test_dsn.host
      test_dsn.port db_name
  in
  let code, out, _ =
    T_unit.run_cli
      [
        "check";
        "-p";
        "fixtures/saas_writes.yaml";
        "--catalog";
        "fixtures/saas_writes_catalog.json";
        "--set-field";
        "org_ids";
        "--role";
        role;
        "--dsn";
        dsn;
        "--json";
      ]
  in
  Alcotest.(check int) "cli check exit" 0 code;
  let j = Yojson.Safe.from_string out in
  Alcotest.(check bool)
    "cli drift false" false
    Yojson.Safe.Util.(j |> member "drift" |> to_bool);
  Alcotest.(check int)
    "cli findings" 0
    Yojson.Safe.Util.(j |> member "findings" |> to_list |> List.length);
  (* wrong --role: role_missing, exit 1 *)
  let code, out, _ =
    T_unit.run_cli
      [
        "check";
        "-p";
        "fixtures/saas_writes.yaml";
        "--set-field";
        "org_ids";
        "--role";
        "haltsql_rls_it_nobody";
        "--dsn";
        dsn;
      ]
  in
  Alcotest.(check int) "cli drift exit" 1 code;
  Alcotest.(check string)
    "cli drift text"
    "drift: 1 finding(s) for role haltsql_rls_it_nobody (policy rls-it-saas-writes)\n\
    \  critical role_missing       haltsql_rls_it_nobody: role does not exist; apply the \
     output of `haltsql rls generate`\n"
    out

let test_auth_failures () =
  require_pg ();
  let expect_pg_error name dsn code =
    match Lwt_main.run (Pg_wire.with_connection dsn (fun _ -> Lwt.return_unit)) with
    | () -> Alcotest.failf "%s: connected" name
    | exception Pg_wire.Pg_error e -> Alcotest.(check string) name code e.code
  in
  expect_pg_error "wrong password (SCRAM)"
    { admin_dsn with password = Some "definitely-wrong" }
    "28P01";
  (match
     Lwt_main.run
       (Pg_wire.with_connection { admin_dsn with password = None } (fun _ ->
            Lwt.return_unit))
   with
  | () -> Alcotest.fail "connected without password"
  | exception Pg_wire.Protocol_error m ->
      Alcotest.(check string)
        "no password" "server requested a password but none was given (set PGPASSWORD)" m);
  match
    Lwt_main.run
      (Pg_wire.with_connection { admin_dsn with sslmode = Pg_wire.Require } (fun c ->
           Pg_wire.query c "SELECT 1"))
  with
  | rows ->
      Alcotest.(check (list (list (option string)))) "TLS server" [ [ Some "1" ] ] rows
  | exception Pg_wire.Protocol_error m ->
      Alcotest.(check string)
        "sslmode=require without server TLS"
        "server does not support TLS but sslmode=require" m

let test_check_drift () =
  require_pg ();
  Lwt_main.run
    (Pg_wire.with_connection test_dsn (fun c ->
         Pg_wire.exec c
           (Printf.sprintf
              "GRANT SELECT (email) ON app.customers TO %s;\n\
               GRANT SELECT ON app.orgs TO %s;\n\
               GRANT SELECT ON app.secrets TO PUBLIC;\n\
               ALTER TABLE app.payments DISABLE ROW LEVEL SECURITY;\n\
               DROP POLICY haltsql_tenant_select ON app.invoices;\n\
               CREATE POLICY rogue ON app.orders FOR SELECT TO PUBLIC USING (true);\n\
               DROP POLICY haltsql_tenant_update ON app.orders;\n\
               CREATE POLICY haltsql_tenant_update ON app.orders FOR UPDATE TO %s USING \
               (tenant_id = current_setting('haltsql.tenant_id', true) OR true);\n\
               CREATE POLICY haltsql_tenant_insert ON app.users FOR INSERT TO %s WITH \
               CHECK (true);\n\
               GRANT CREATE ON SCHEMA app TO %s;"
              role role role role role)));
  Alcotest.(check (list string))
    "drift"
    [
      "critical over_broad_grant app: role has CREATE on the schema";
      "critical over_broad_grant app.customers: role has SELECT on columns not in the \
       policy: email";
      "critical policy_missing app.invoices: policy haltsql_tenant_select is missing";
      "critical foreign_policy app.orders: permissive policy rogue also applies to the \
       role and widens the rows it can see";
      "critical policy_mismatch app.orders: policy haltsql_tenant_update: USING \
       expression differs, WITH CHECK expression differs";
      "critical over_broad_grant app.orgs: role has table-level SELECT (policy allows \
       only listed columns)";
      "critical rls_disabled app.payments: row-level security is not enabled";
      "critical over_broad_grant app.secrets: table is not in the policy but the role \
       has SELECT on it";
      "warning unexpected_policy app.users: policy haltsql_tenant_insert exists but the \
       policy does not allow INSERT";
    ]
    (finding_strings (run_check ()));
  (* re-applying the generated SQL repairs everything it manages (grants, RLS, all
     four haltsql_tenant_* policies, schema CREATE); a foreign policy and a PUBLIC
     grant on a table outside the policy remain visible *)
  let sql, _ = Result.get_ok (Rls_gen.generate (options ()) (policy ())) in
  Lwt_main.run (Pg_wire.with_connection test_dsn (fun c -> Pg_wire.exec c sql));
  Alcotest.(check (list string))
    "after re-apply"
    [
      "critical foreign_policy app.orders: permissive policy rogue also applies to the \
       role and widens the rows it can see";
      "critical over_broad_grant app.secrets: table is not in the policy but the role \
       has SELECT on it";
    ]
    (finding_strings (run_check ()));
  (* --drop-existing removes foreign policies on managed tables *)
  let sql, _ =
    Result.get_ok
      (Rls_gen.generate { (options ()) with drop_existing = true } (policy ()))
  in
  Lwt_main.run
    (Pg_wire.with_connection test_dsn (fun c ->
         let* () = Pg_wire.exec c sql in
         Pg_wire.exec c "REVOKE SELECT ON app.secrets FROM PUBLIC"));
  Alcotest.(check (list string))
    "after --drop-existing" []
    (finding_strings (run_check ()))

(* Quoted role name, owner role, FORCE, dotted prefix: applied for a second role.
   (Policy names are per table, so this replaces the first role's policies.) *)
let test_options_variant () =
  require_pg ();
  let o =
    {
      (options ()) with
      role = role2;
      setting_prefix = "app.ctx";
      owner_role = Some "haltlab_owner";
      force_rls = true;
    }
  in
  let pl = Result.get_ok (Rls_gen.plan o (policy ())) in
  let sql = Rls_gen.render pl in
  Lwt_main.run
    (Pg_wire.with_connection test_dsn (fun c ->
         let* () = Pg_wire.exec c sql in
         Pg_wire.exec c sql));
  let settings = [ ("app.ctx.tenant_id", "A") ] in
  check "quoted role: A only"
    (ids [ 1; 2 ])
    (as_agent ~role:role2 ~settings "SELECT id FROM app.orders ORDER BY id");
  check "old prefix ignored" (rows [ [ "0" ] ])
    (as_agent ~role:role2 ~settings:a "SELECT count(*) FROM app.orders");
  check "first role lost its policies (shared names)" (rows [ [ "0" ] ])
    (as_agent ~settings:a "SELECT count(*) FROM app.orders");
  check "owner is subject to FORCEd RLS" (rows [ [ "0" ] ])
    (Lwt_main.run
       (Pg_wire.with_connection test_dsn (fun c ->
            let* () = Pg_wire.exec c "BEGIN" in
            Lwt.finalize
              (fun () ->
                let* () = Pg_wire.exec c "SET LOCAL ROLE haltlab_owner" in
                let* r = Pg_wire.query c "SELECT count(*) FROM app.orders" in
                Lwt.return (Rows r))
              (fun () -> Pg_wire.exec c "ROLLBACK"))));
  let fs =
    Lwt_main.run (Pg_wire.with_connection test_dsn (fun c -> Rls_check.check c pl))
  in
  Alcotest.(check (list string)) "variant: no drift" [] (finding_strings fs)

let test_teardown () =
  require_pg ();
  Lwt_main.run (drop_all ())

let tests =
  [
    ("setup (load schema, apply generated SQL twice)", `Slow, test_setup);
    ("tenant isolation", `Slow, test_tenant_isolation);
    ("missing setting sees nothing", `Slow, test_missing_setting);
    ("set-valued field", `Slow, test_set_field);
    ("denied columns and tables", `Slow, test_column_denial);
    ("writes", `Slow, test_writes);
    ("auth failures fail closed", `Slow, test_auth_failures);
    ("rls check: no drift", `Slow, test_check_no_drift);
    ("rls check: injected drift", `Slow, test_check_drift);
    ("quoted role, owner, FORCE, prefix", `Slow, test_options_variant);
    ("teardown", `Slow, test_teardown);
  ]
