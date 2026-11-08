(* Tests for haltsql.catalog_tools and the schema/policy-draft CLI commands. *)

open Haltsql
module Ct = Haltsql_catalog_tools
module Dsn = Ct.Pg_dsn
module Pii = Ct.Pii
module Imp = Ct.Pii_import
module Snap = Ct.Snapshot
module Pull = Ct.Schema_pull
module Draft = Ct.Policy_draft

let examples = "../../examples/metadata"
let ex f = Filename.concat examples f

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let check_contains what s sub =
  if not (contains s sub) then
    Alcotest.failf "%s: expected to contain %S in:\n%s" what sub s

let check_not_contains what s sub =
  if contains s sub then Alcotest.failf "%s: must not contain %S in:\n%s" what sub s

let get_ok what = function Ok x -> x | Error e -> Alcotest.failf "%s: %s" what e

let get_error what = function
  | Ok _ -> Alcotest.failf "%s: expected an error" what
  | Error e -> e

let no_env _ = None

let tmpdir () =
  Filename.temp_dir ~temp_dir:(Filename.get_temp_dir_name ()) "haltsql_schema_test" ""

let write path s = Out_channel.with_open_bin path (fun oc -> output_string oc s)
let read path = In_channel.with_open_bin path In_channel.input_all

(* ------------------------------------------------------------ DSN *)

let test_dsn_url () =
  let d =
    get_ok "url"
      (Dsn.parse ~env:no_env
         "postgresql://ro%40corp:p%40ss%2Fw:rd@db.example.com:6432/app%20db?sslmode=verify-full&sslrootcert=/etc/ca.pem&connect_timeout=5&application_name=x")
  in
  Alcotest.(check string) "user" "ro@corp" d.user;
  Alcotest.(check (option string)) "password" (Some "p@ss/w:rd") d.password;
  Alcotest.(check string) "host" "db.example.com" d.host;
  Alcotest.(check int) "port" 6432 d.port;
  Alcotest.(check string) "db" "app db" d.dbname;
  Alcotest.(check string) "sslmode" "verify-full" (Dsn.sslmode_to_string d.sslmode);
  Alcotest.(check (option string)) "rootcert" (Some "/etc/ca.pem") d.sslrootcert;
  Alcotest.(check (option (float 0.))) "timeout" (Some 5.) d.connect_timeout;
  Alcotest.(check string)
    "redacted" "postgres://ro%40corp@db.example.com:6432/app%20db?sslmode=verify-full"
    (Dsn.redacted d);
  check_not_contains "redacted" (Dsn.redacted d) "rd"

let test_dsn_ipv6_and_defaults () =
  let d = get_ok "v6" (Dsn.parse ~env:no_env "postgres://u@[::1]:5417/x") in
  Alcotest.(check string) "host" "::1" d.host;
  Alcotest.(check int) "port" 5417 d.port;
  Alcotest.(check string)
    "loopback default sslmode" "prefer"
    (Dsn.sslmode_to_string d.sslmode);
  Alcotest.(check string)
    "redacted v6" "postgres://u@[::1]:5417/x?sslmode=prefer" (Dsn.redacted d);
  let d = get_ok "remote" (Dsn.parse ~env:no_env "postgres://u@db.internal/x") in
  Alcotest.(check string)
    "remote default sslmode" "require"
    (Dsn.sslmode_to_string d.sslmode);
  Alcotest.(check int) "default port" 5432 d.port;
  let env = function
    | "PGHOST" -> Some "pg.local"
    | "PGUSER" -> Some "envuser"
    | "PGPASSWORD" -> Some "envpw"
    | "PGSSLMODE" -> Some "disable"
    | _ -> None
  in
  let d = get_ok "env" (Dsn.parse ~env "") in
  Alcotest.(check string) "env host" "pg.local" d.host;
  Alcotest.(check string) "env user" "envuser" d.user;
  Alcotest.(check string) "dbname defaults to user" "envuser" d.dbname;
  Alcotest.(check (option string)) "env password" (Some "envpw") d.password;
  Alcotest.(check string) "env sslmode" "disable" (Dsn.sslmode_to_string d.sslmode)

let test_dsn_keywords () =
  let d =
    get_ok "kw"
      (Dsn.parse ~env:no_env
         "host=10.0.0.5 port=5433 user=ro password='it\\'s a \\\\ sec' dbname=app \
          sslmode=require")
  in
  Alcotest.(check string) "host" "10.0.0.5" d.host;
  Alcotest.(check int) "port" 5433 d.port;
  Alcotest.(check string) "user" "ro" d.user;
  Alcotest.(check string) "db" "app" d.dbname;
  Alcotest.(check string) "sslmode" "require" (Dsn.sslmode_to_string d.sslmode);
  Alcotest.(check (option string)) "quoted password" (Some "it's a \\ sec") d.password

let test_dsn_errors () =
  let e =
    get_error "unknown"
      (Dsn.parse ~env:no_env "postgres://u:hunter22@h/db?sslmod=disable")
  in
  Alcotest.(check string) "unknown param" "unknown DSN parameter \"sslmod\"" e;
  let e =
    get_error "sslmode" (Dsn.parse ~env:no_env "postgres://u:hunter22@h/db?sslmode=maybe")
  in
  check_contains "sslmode" e "invalid sslmode \"maybe\"";
  let e = get_error "port" (Dsn.parse ~env:no_env "postgres://u:hunter22@h:99999/db") in
  Alcotest.(check string) "port" "invalid port \"99999\"" e;
  let e = get_error "pct" (Dsn.parse ~env:no_env "postgres://u:hunter%2@h/db") in
  Alcotest.(check string) "pct" "invalid percent-encoding in password" e;
  List.iter (fun e -> check_not_contains "no password in errors" e "hunter") [ e ];
  ignore (get_error "multi-host" (Dsn.parse ~env:no_env "postgres://h1,h2/db"));
  ignore (get_error "kw" (Dsn.parse ~env:no_env "host=x bogus"))

(* ------------------------------------------------------------ SCRAM *)

let hex s =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq s)))

let test_pbkdf2 () =
  (* RFC 7914 section 11: PBKDF2-HMAC-SHA256 (P="passwd", S="salt", c=1), first block. *)
  Alcotest.(check string)
    "rfc7914" "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    (hex (Ct.Scram.pbkdf2_sha256 ~password:"passwd" ~salt:"salt" ~iterations:1))

let rfc7677_server_first =
  "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"

let test_scram_rfc7677 () =
  let nonce = "rOprNGfwEbeRWgbNEkqO" in
  let cf = Ct.Scram.client_first ~user:"user" ~nonce in
  Alcotest.(check string) "client-first" "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" cf.message;
  let fin =
    get_ok "final"
      (Ct.Scram.client_final ~password:"pencil" ~client_first:cf ~client_nonce:nonce
         ~server_first:rfc7677_server_first)
  in
  Alcotest.(check string)
    "client-final"
    "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
    fin.final_message;
  get_ok "server-final"
    (Ct.Scram.verify_server_final fin "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
  let e =
    get_error "tampered"
      (Ct.Scram.verify_server_final fin "v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
  in
  check_contains "tampered" e "server signature mismatch";
  let e = get_error "e=" (Ct.Scram.verify_server_final fin "e=invalid-proof") in
  check_contains "server error" e "invalid-proof";
  let e =
    get_error "nonce"
      (Ct.Scram.client_final ~password:"pencil" ~client_first:cf ~client_nonce:nonce
         ~server_first:"r=SOMEOTHERNONCE,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
  in
  check_contains "nonce" e "nonce";
  let e =
    get_error "iterations"
      (Ct.Scram.client_final ~password:"pencil" ~client_first:cf ~client_nonce:nonce
         ~server_first:
           (nonce ^ "x" |> fun r -> "r=" ^ r ^ ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0"))
  in
  check_contains "iterations" e "iteration";
  Alcotest.(check bool) "ct equal" true (Ct.Scram.equal_ct "abc" "abc");
  Alcotest.(check bool) "ct differ" false (Ct.Scram.equal_ct "abc" "abd");
  Alcotest.(check bool) "ct length" false (Ct.Scram.equal_ct "abc" "abcd")

(* ------------------------------------------------------------ matcher *)

let test_matcher () =
  Alcotest.(check (list string))
    "tokens"
    [ "urn"; "li"; "tag"; "personal"; "data" ]
    (Pii.Matcher.tokens "urn:li:tag:PersonalData");
  Alcotest.(check (list string))
    "tokens acronym run" [ "pii"; "data"; "v2" ]
    (Pii.Matcher.tokens "PIIData_v2");
  let m = Pii.Matcher.find_match Pii.Matcher.default_terms in
  Alcotest.(check (option string)) "contains_pii" (Some "pii") (m "contains_pii");
  Alcotest.(check (option string)) "urn tag" (Some "pii") (m "urn:li:tag:PII");
  Alcotest.(check (option string)) "piiset" None (m "piiset");
  Alcotest.(check (option string)) "phone number" (Some "phone") (m "Phone Number");
  Alcotest.(check (option string))
    "acronym" (Some "pii")
    (m "Personally Identifiable Information");
  Alcotest.(check (option string))
    "acronym phi" (Some "phi")
    (m "Protected Health Information");
  Alcotest.(check (option string)) "sensitivity != sensitive" None (m "sensitivity");
  Alcotest.(check (option string))
    "multiword term" (Some "credit card")
    (Pii.Matcher.find_match [ "credit card" ] "is_credit_card_number");
  Alcotest.(check (option string))
    "short terms: no acronym" None
    (Pii.Matcher.find_match [ "ip" ] "item_price")

(* ------------------------------------------------------------ importers *)

type exp = string * string * string * string list (* schema, table, column, classes *)

let entries (m : Pii.t) : exp list =
  List.map (fun (e : Pii.entry) -> (e.schema, e.table, e.column, e.classifications)) m

let exp_t = Alcotest.(list (pair (pair string string) (pair string (list string))))
let norm l = List.map (fun (s, t, c, cl) -> ((s, t), (c, cl))) l

let check_import ?config src file ~scanned (expected : exp list) =
  let r = get_ok file (Imp.import_file ?config src (ex file)) in
  Alcotest.(check int) (file ^ " scanned") scanned r.scanned_columns;
  Alcotest.check exp_t (file ^ " manifest") (norm expected) (norm (entries r.manifest));
  List.iter
    (fun (e : Pii.entry) ->
      Alcotest.(check (list string)) "source" [ Imp.source_to_string src ] e.sources)
    r.manifest;
  r

let test_dbt_manifest () =
  ignore
    (check_import Imp.Dbt "dbt_manifest.json" ~scanned:18
       [
         ("app", "audit_events", "ip", [ "personal_data" ]);
         ("app", "customers", "email", [ "pii" ]);
         ("app", "customers", "phone", [ "governance.sensitivity=restricted" ]);
         ("app", "customers", "ssn", [ "classification=confidential"; "gdpr" ]);
         ("app", "payments", "card_token", [ "pci" ]);
         ("app", "users", "email", [ "contains_pii" ]);
         ("app", "users", "full_name", [ "pii_name" ]);
         ("app", "users", "password_hash", [ "security=secret" ]);
       ])

let test_dbt_custom_tags () =
  (* Only "gdpr" counts: email (pii) and phone (restricted) are no longer PII. *)
  ignore
    (check_import
       ~config:{ Pii.Matcher.tags = [ "gdpr" ]; terms = [] }
       Imp.Dbt "dbt_manifest.json" ~scanned:18
       [ ("app", "customers", "ssn", [ "gdpr" ]) ])

let test_dbt_catalog () =
  ignore
    (check_import Imp.Dbt "dbt_catalog.json" ~scanned:4
       [
         ("app", "customers", "email", [ "comment:email" ]);
         ("app", "customers", "phone", [ "comment:pii" ]);
       ])

let test_datahub_mce () =
  ignore
    (check_import Imp.Datahub "datahub_mce.json" ~scanned:7
       [
         ("app", "customers", "email", [ "PII" ]);
         ("app", "customers", "phone", [ "PersonalInformation.PhoneNumber" ]);
         ("app", "customers", "ssn", [ "Sensitive" ]);
         ("app", "users", "email", [ "gdpr" ]);
       ])

let test_datahub_graphql () =
  ignore
    (check_import Imp.Datahub "datahub_graphql.json" ~scanned:3
       [
         ("app", "payments", "card_last4", [ "Payment Card Data (Sensitive)" ]);
         ("app", "payments", "card_token", [ "PCI"; "pci" ]);
       ])

let test_unity () =
  ignore
    (check_import Imp.Unity "unity_column_tags.json" ~scanned:5
       [
         ("app", "customers", "email", [ "pii"; "pii=email" ]);
         ("app", "customers", "phone", [ "class.phone_number" ]);
         ("app", "customers", "ssn", [ "data_classification=Restricted" ]);
         ("app", "users", "password_hash", [ "secret" ]);
       ]);
  ignore
    (check_import Imp.Unity "unity_statement_result.json" ~scanned:2
       [ ("app", "audit_events", "ip", [ "pii"; "pii=ip_address" ]) ]);
  ignore
    (check_import Imp.Unity "unity_table.json" ~scanned:3
       [ ("app", "payments", "card_token", [ "pci"; "sensitivity=restricted" ]) ])

let test_atlan () =
  ignore
    (check_import Imp.Atlan "atlan_assets.json" ~scanned:3
       [
         ("app", "customers", "email", [ "Email Address"; "PII" ]);
         ("app", "users", "full_name", [ "Confidential" ]);
       ])

let test_collibra () =
  ignore
    (check_import Imp.Collibra "collibra_assets.json" ~scanned:4
       [
         ("app", "customers", "email", [ "Personally Identifiable Information" ]);
         ("app", "customers", "phone", [ "Phone Number"; "Restricted" ]);
         ("app", "invoices", "number", [ "Customer Personal Reference" ]);
       ])

(* examples/metadata/openmetadata_*.json are real GET /api/v1/tables responses captured
   from OpenMetadata 2.0.7, labelled by test/catalog_live/openmetadata/seed.py. *)
let om_expected =
  [
    ("app", "audit_events", "ip", [ "PersonalData.Personal" ]);
    ("app", "customers", "email", [ "PII.Sensitive" ]);
    ("app", "customers", "phone", [ "PersonalData.Personal" ]);
    ("app", "customers", "ssn", [ "PII.Sensitive"; "PersonalData.SpecialCategory" ]);
    ("app", "payments", "card_last4", [ "PII.NonSensitive" ]);
    ("app", "payments", "card_token", [ "PII.Sensitive" ]);
    ("app", "users", "email", [ "PII.Sensitive" ]);
    ("app", "users", "full_name", [ "Business.PersonalInformation" ]);
    ("app", "users", "password_hash", [ "PII.Sensitive" ]);
  ]

let test_openmetadata () =
  let r =
    check_import Imp.Openmetadata "openmetadata_tables.json" ~scanned:63 om_expected
  in
  let flagged ~table ~column = Pii.find r.manifest ~schema:"app" ~table ~column <> None in
  (* Tier.Tier1 (column and table level), a non-PII classification, a description
     mentioning "personal email", and untagged columns are not PII. *)
  Alcotest.(check bool) "Tier.Tier1 column" false (flagged ~table:"orders" ~column:"note");
  Alcotest.(check bool)
    "DataDomain.Finance" false
    (flagged ~table:"invoices" ~column:"amount_cents");
  Alcotest.(check bool) "description" false (flagged ~table:"orgs" ~column:"name");
  Alcotest.(check bool)
    "table-level Tier1" false
    (flagged ~table:"customers" ~column:"country");
  (* The same document as a bare list and as a single table. *)
  let j = Yojson.Safe.from_file (ex "openmetadata_tables.json") in
  let data = match j with `Assoc kvs -> List.assoc "data" kvs | _ -> assert false in
  let r2 = get_ok "list" (Imp.import Imp.Openmetadata data) in
  Alcotest.check exp_t "list" (norm om_expected) (norm (entries r2.manifest));
  let users =
    match data with
    | `List l ->
        List.find (fun t -> Yojson.Safe.Util.(member "name" t |> to_string) = "users") l
    | _ -> assert false
  in
  let r3 = get_ok "single" (Imp.import Imp.Openmetadata users) in
  Alcotest.(check int) "single scanned" 8 r3.scanned_columns;
  Alcotest.(check int) "single entries" 3 (List.length r3.manifest);
  (* Glossary terms are matched with the glossary-term config, not the tag config. *)
  let r4 =
    get_ok "terms only"
      (Imp.import
         ~config:{ Pii.Matcher.tags = []; terms = [ "personal" ] }
         Imp.Openmetadata j)
  in
  Alcotest.check exp_t "glossary via terms"
    (norm [ ("app", "users", "full_name", [ "Business.PersonalInformation" ]) ])
    (norm (entries r4.manifest));
  (* A tag on a STRUCT child flags the top-level column. *)
  ignore
    (check_import Imp.Openmetadata "openmetadata_struct_table.json" ~scanned:3
       [ ("events", "page_views", "context", [ "PII.Sensitive" ]) ]);
  (* FQN fallback with a quoted part, when the databaseSchema reference is missing. *)
  let r5 =
    get_ok "fqn"
      (Imp.import Imp.Openmetadata
         (Yojson.Safe.from_string
            {|{"fullyQualifiedName":"svc.db.\"my.schema\".t","columns":[{"name":"c","tags":[{"tagFQN":"PII.Sensitive","source":"Classification"}]}]}|}))
  in
  Alcotest.check exp_t "quoted fqn"
    (norm [ ("my.schema", "t", "c", [ "PII.Sensitive" ]) ])
    (norm (entries r5.manifest))

let test_import_wrong_format () =
  let e = get_error "atlan as dbt" (Imp.import_file Imp.Dbt (ex "atlan_assets.json")) in
  check_contains "wrong format" e "no column metadata found; is this a dbt export";
  let e = get_error "not json" (Imp.import Imp.Unity (`String "x")) in
  check_contains "unity" e "no column metadata found"

let test_pii_json () =
  let m =
    Pii.merge
      [
        [
          {
            Pii.schema = "app";
            table = "Mixed";
            column = "E";
            classifications = [ "pii" ];
            sources = [ "dbt" ];
          };
        ];
        [
          {
            Pii.schema = "app";
            table = "Mixed";
            column = "E";
            classifications = [ "gdpr"; "pii" ];
            sources = [ "unity" ];
          };
        ];
      ]
  in
  let j = Pii.to_json m in
  Alcotest.(check string)
    "json"
    {|{"tables":{"app.\"Mixed\"":{"columns":{"E":{"classifications":["gdpr","pii"],"source":"dbt, unity"}}}}}|}
    (Yojson.Safe.to_string j);
  let back = get_ok "roundtrip" (Pii.of_json j) in
  Alcotest.check exp_t "roundtrip" (norm (entries m)) (norm (entries back));
  Alcotest.(check (list string)) "sources" [ "dbt"; "unity" ] (List.hd back).sources;
  (match Pii.find back ~schema:"APP" ~table:"mixed" ~column:"e" with
  | Some e -> Alcotest.(check string) "case-insensitive find" "E" e.column
  | None -> Alcotest.fail "find");
  let e =
    get_error "unknown key" (Pii.of_json (`Assoc [ ("tables", `Assoc []); ("x", `Null) ]))
  in
  Alcotest.(check string) "unknown key" "unknown key \"x\" in PII manifest" e;
  let e =
    get_error "bad classes"
      (Pii.of_json
         (Yojson.Safe.from_string
            {|{"tables":{"a.b":{"columns":{"c":{"classifications":"pii"}}}}}|}))
  in
  check_contains "bad classes" e "expected a list of strings"

(* ------------------------------------------------------------ snapshot building *)

let row ?(part = false) ns rel kind col ty : Pull.row =
  {
    nspname = ns;
    relname = rel;
    relkind = kind;
    relispartition = part;
    attname = (if col = "" then None else Some col);
    atttype = (if ty = "" then None else Some ty);
  }

let sample_rows =
  [
    row "app" "Mixed Case" 'r' "Id" "integer";
    row "app" "Mixed Case" 'r' "tenant_id" "text";
    row "app" "currencies" 'r' "code" "character(3)";
    row "app" "currencies" 'r' "name" "text";
    row "app" "customer_stats" 'm' "tenant_id" "text";
    row "app" "customer_stats" 'm' "n" "bigint";
    row "app" "customers" 'r' "id" "bigint";
    row "app" "customers" 'r' "tenant_id" "text";
    row "app" "customers" 'r' "name" "text";
    row "app" "customers" 'r' "email" "text";
    row "app" "customers" 'r' "phone" "text";
    row "app" "customers" 'r' "ssn" "text";
    row "app" "customers" 'r' "country" "character(2)";
    row "app" "customers" 'r' "created_at" "timestamp with time zone";
    row "app" "empty" 'r' "" "";
    row "app" "evil" 'r' "evil\nmode: shadow" "text";
    row "app" "evil" 'r' "tenant_id" "text";
    row "app" "orders" 'p' "id" "bigint";
    row "app" "orders" 'p' "tenant_id" "text";
    row "app" "orders_2026" 'r' ~part:true "id" "bigint";
    row "app" "orders_2026" 'r' ~part:true "tenant_id" "text";
    row "app" "orders_id_seq" 'S' "last_value" "bigint";
    row "app" "secrets" 'r' "api_token" "text";
    row "app" "secrets" 'r' "password" "text";
  ]

let sample_snapshot () =
  Pull.build ~database:"saas" ~server_version:"17.2" ~schemas:[ "app"; "nope" ]
    sample_rows

let test_build_snapshot () =
  let snap, warnings = sample_snapshot () in
  Alcotest.(check (list string))
    "warnings"
    [
      "skipped table app.empty: it has no columns";
      "schema nope has no relations (or does not exist)";
    ]
    warnings;
  Alcotest.(check (list (pair string string)))
    "order"
    [
      ("app", "Mixed Case");
      ("app", "currencies");
      ("app", "customer_stats");
      ("app", "customers");
      ("app", "evil");
      ("app", "orders");
      ("app", "orders_2026");
      ("app", "orders_id_seq");
      ("app", "secrets");
    ]
    (List.map (fun (t : Catalog.table) -> (t.schema, t.name)) snap.catalog.tables);
  let kind s n =
    Option.map Snap.relkind_to_string (Snap.relkind snap ~schema:"app" ~name:n)
    |> fun k ->
    ignore s;
    k
  in
  Alcotest.(check (option string))
    "partitioned" (Some "partitioned table") (kind () "orders");
  Alcotest.(check (option string)) "partition" (Some "partition") (kind () "orders_2026");
  Alcotest.(check (option string))
    "matview" (Some "materialized view") (kind () "customer_stats");
  Alcotest.(check (option string)) "sequence" (Some "sequence") (kind () "orders_id_seq");
  let j = Snap.to_json snap in
  let s = Yojson.Safe.to_string j in
  check_contains "quoted key" s
    {|"app.\"Mixed Case\"":{"columns":[{"name":"Id","type":"integer"}|};
  check_contains "metadata" s
    {|"metadata":{"source":"haltsql schema pull","database":"saas","server_version":"17.2","schemas":["app","nope"],"relations":{"app.\"Mixed Case\"":"table"|};
  (* It loads with the core catalog loader, typed (so the analyzer trusts it). *)
  let cat =
    get_ok "catalog_load"
      (Result.map_error
         (fun es -> String.concat "; " (List.map Load_error.to_string es))
         (Catalog_load.of_json j))
  in
  (match Catalog.find cat ~schema:"app" ~name:"Mixed Case" with
  | Some t ->
      Alcotest.(check (list (pair string (option string))))
        "mixed case columns"
        [ ("Id", Some "integer"); ("tenant_id", Some "text") ]
        (List.map (fun (c : Catalog.column) -> (c.col_name, c.col_type)) t.columns)
  | None -> Alcotest.fail "Mixed Case missing");
  let back = get_ok "snapshot roundtrip" (Snap.of_json j) in
  Alcotest.(check string)
    "stable output" (Yojson.Safe.to_string j)
    (Yojson.Safe.to_string (Snap.to_json back));
  let e =
    get_error "bad relkind"
      (Snap.of_json
         (Yojson.Safe.from_string
            {|{"metadata":{"relations":{"a.b":"index"}},"tables":{"a.b":{"columns":[{"name":"x","type":"int4"}]}}}|}))
  in
  check_contains "bad relkind" e "unknown relation kind \"index\""

(* ------------------------------------------------------------ drafter *)

let sample_pii : Pii.t =
  Pii.merge
    [
      [
        {
          Pii.schema = "app";
          table = "customers";
          column = "email";
          classifications = [ "pii" ];
          sources = [ "dbt" ];
        };
        {
          Pii.schema = "app";
          table = "customers";
          column = "ssn";
          classifications = [ "gdpr" ];
          sources = [ "dbt" ];
        };
        {
          Pii.schema = "app";
          table = "evil";
          column = "evil\nmode: shadow";
          classifications = [ "x\ny" ];
          sources = [ "unity" ];
        };
        {
          Pii.schema = "app";
          table = "ghost";
          column = "c";
          classifications = [ "pii" ];
          sources = [ "unity" ];
        };
      ];
      [
        {
          Pii.schema = "app";
          table = "customers";
          column = "ssn";
          classifications = [ "pii" ];
          sources = [ "unity" ];
        };
      ];
    ]

let ctx = Context.make [ ("tenant_id", Context.One "acme") ]

let codes (v : Verdict.t) =
  List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) v.reasons

let draft_into dir =
  let snap, _ = sample_snapshot () in
  let catalog_path = Filename.concat dir "catalog.json" in
  write catalog_path (Yojson.Safe.pretty_to_string (Snap.to_json snap));
  let pdir = Filename.concat dir "policies" in
  Unix.mkdir pdir 0o755;
  let policy_path = Filename.concat pdir "draft.yaml" in
  let cfg =
    {
      (Draft.default_config ~tenant_column:"tenant_id"
         ~catalog_ref:(Draft.relative_path ~from_dir:pdir catalog_path))
      with
      name = "saas-draft";
      pii_sources = [ "pii.json" ];
    }
  in
  let r = get_ok "draft" (Draft.draft ~base_dir:pdir cfg snap sample_pii) in
  write policy_path r.yaml;
  (r, policy_path)

let test_relative_path () =
  Alcotest.(check string)
    "sibling" "../catalog/c.json"
    (Draft.relative_path ~from_dir:"/a/policies" "/a/catalog/c.json");
  Alcotest.(check string)
    "same dir" "c.json"
    (Draft.relative_path ~from_dir:"/a" "/a/c.json");
  Alcotest.(check string)
    "dotdot" "../../x/c.json"
    (Draft.relative_path ~from_dir:"/a/b/c" "/a/x/./c.json")

let test_draft () =
  let dir = tmpdir () in
  let r, policy_path = draft_into dir in
  let y = r.yaml in
  Alcotest.(check (list string))
    "warnings"
    [ "PII column app.ghost.c is not in the catalog" ]
    r.warnings;
  List.iter (check_contains "yaml" y)
    [
      "catalog: \"../catalog.json\"\n";
      "search_path: [app]\n";
      "statements:\n  allow: [select]\n";
      "require_limit:\n  max: 1000\n";
      "tenancy:\n  mode: bound\n  keys:\n    tenant: \"${ctx.tenant_id}\"\n";
      "  # excluded email (dbt: pii; name matches \"email\")\n\
      \  # excluded phone (name matches \"phone\")\n\
      \  # excluded ssn (dbt+unity: gdpr, pii; name matches \"ssn\")\n\
      \  app.customers:\n\
      \    columns: [id, tenant_id, name, country, created_at]\n\
      \    tenant_column: tenant_id\n";
      "  # GLOBAL: no tenant_id column\n  app.currencies:\n    columns: [code, name]\n";
      "  # materialized view\n\
      \  app.customer_stats:\n\
      \    columns: [tenant_id, \"n\"]\n\
      \    tenant_column: tenant_id\n";
      "  # partitioned table\n  app.orders:\n";
      "  \"app.\\\"Mixed Case\\\"\":\n    columns: [\"\\\"Id\\\"\", tenant_id]\n";
      "  # excluded \"evil?mode: shadow\" (unity: x?y)\n\
      \  app.evil:\n\
      \    columns: [tenant_id]\n";
      "# Not drafted:\n\
       #   app.orders_2026: partition (query the partitioned parent table)\n\
       #   app.orders_id_seq: sequence\n\
       #   app.secrets: every column is excluded as PII\n";
      "functions:\n  presets: [aggregates, math, string, datetime]\nmode: enforce\n";
    ];
  check_not_contains "no injected key" y "\nmode: shadow";
  let p =
    match Policy_load.of_file policy_path with
    | Ok p -> p
    | Error es ->
        Alcotest.failf "policy load: %s"
          (String.concat "; " (List.map Load_error.to_string es))
  in
  Alcotest.(check bool) "enforce" true (p.mode = Policy.Enforce);
  Alcotest.(check string) "name" "saas-draft" p.name;
  Alcotest.(check int) "tables" 6 (List.length p.tables);
  (* The analyzer trusts the typed catalog: SELECT * expands to the excluded columns. *)
  let v =
    Haltsql.verify p ctx "SELECT * FROM app.customers WHERE tenant_id = $1 LIMIT 10"
  in
  Alcotest.(check (list string))
    "star denied" [ "E_COLUMN_DENIED" ]
    (List.sort_uniq compare (codes v));
  let v =
    Haltsql.verify p ctx "SELECT id, name FROM customers WHERE tenant_id = $1 LIMIT 10"
  in
  Alcotest.(check bool) "allowed" true v.allowed;
  Alcotest.(check int) "bind param" 1 (List.length v.bind_params);
  let v =
    Haltsql.verify p ctx "SELECT email FROM app.customers WHERE tenant_id = $1 LIMIT 10"
  in
  Alcotest.(check (list string)) "email denied" [ "E_COLUMN_DENIED" ] (codes v);
  let v = Haltsql.verify p ctx "SELECT id FROM app.customers LIMIT 10" in
  Alcotest.(check (list string)) "tenant required" [ "E_TENANT_MISSING" ] (codes v);
  let v = Haltsql.verify p ctx "SELECT * FROM app.currencies LIMIT 5" in
  Alcotest.(check bool) "global star allowed" true v.allowed;
  let v = Haltsql.verify p ctx "SELECT id FROM app.orders_2026 LIMIT 1" in
  Alcotest.(check (list string)) "partition denied" [ "E_TABLE_DENIED" ] (codes v);
  let v = Haltsql.verify p ctx "SELECT id FROM app.customers WHERE tenant_id = $1" in
  Alcotest.(check (list string)) "limit required" [ "E_LIMIT_REQUIRED" ] (codes v)

let test_draft_options () =
  let snap, _ = sample_snapshot () in
  let dir = tmpdir () in
  write (Filename.concat dir "c.json") (Yojson.Safe.to_string (Snap.to_json snap));
  let base = Draft.default_config ~tenant_column:"tenant_id" ~catalog_ref:"c.json" in
  (* No heuristics, partitions included, custom key/field. *)
  let cfg =
    {
      base with
      name_patterns = [];
      include_partitions = true;
      tenancy_key = "org";
      context_field = "org_id";
      require_limit = 50;
    }
  in
  let r = get_ok "draft" (Draft.draft ~base_dir:dir cfg snap Pii.empty) in
  List.iter
    (check_contains "yaml" r.yaml)
    [
      "    org: \"${ctx.org_id}\"\n";
      "  max: 50\n";
      "  app.customers:\n\
      \    columns: [id, tenant_id, name, email, phone, ssn, country, created_at]\n";
      "  # partition\n  app.orders_2026:\n";
      "  app.secrets:\n    columns: [api_token, password]\n";
    ];
  (* Invalid inputs are rejected before drafting. *)
  let e =
    get_error "key"
      (Draft.draft ~base_dir:dir { base with tenancy_key = "bad key" } snap Pii.empty)
  in
  Alcotest.(check string)
    "bad key" "invalid tenancy key \"bad key\" (use letters, digits and _)" e;
  let e =
    get_error "field"
      (Draft.draft ~base_dir:dir { base with context_field = "x}" } snap Pii.empty)
  in
  check_contains "bad field" e "invalid context field";
  (* A catalog reference that does not resolve makes the draft fail to load: fail closed. *)
  let e =
    get_error "ref"
      (Draft.draft ~base_dir:dir
         { base with catalog_ref = "missing.json" }
         snap Pii.empty)
  in
  check_contains "missing catalog" e "the drafted policy does not load";
  (* Restricting to a schema with no tables gives an empty but valid policy. *)
  let r =
    get_ok "empty"
      (Draft.draft ~base_dir:dir { base with schemas = [ "billing" ] } snap Pii.empty)
  in
  check_contains "empty tables" r.yaml "tables: {}\n";
  Alcotest.(check (list string))
    "empty warnings"
    [
      "schema billing has no relations in the catalog";
      "no drafted table has a \"tenant_id\" column; every table is global";
    ]
    r.warnings

(* ------------------------------------------------------------ CLI *)

(* [env]: extra variables; inherited FAKE_CATALOG_* variables are dropped. *)
let run_proc ?(env = []) prog args =
  let argv = Array.of_list (prog :: args) in
  let out_r, out_w = Unix.pipe () and err_r, err_w = Unix.pipe () in
  let environment =
    Array.append
      (Array.of_list
         (List.filter
            (fun kv -> not (String.starts_with ~prefix:"FAKE_CATALOG_" kv))
            (Array.to_list (Unix.environment ()))))
      (Array.of_list (List.map (fun (k, v) -> k ^ "=" ^ v) env))
  in
  let pid = Unix.create_process_env prog argv environment Unix.stdin out_w err_w in
  Unix.close out_w;
  Unix.close err_w;
  let read_all fd =
    let ic = Unix.in_channel_of_descr fd in
    let s = In_channel.input_all ic in
    close_in ic;
    s
  in
  let out = read_all out_r in
  let err = read_all err_r in
  let rec wait () =
    try snd (Unix.waitpid [] pid) with Unix.Unix_error (Unix.EINTR, _, _) -> wait ()
  in
  let st = wait () in
  let code = match st with Unix.WEXITED c -> c | _ -> 255 in
  (code, out, err)

let abs p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p
let cli args = run_proc (abs (Sys.getenv "SCHEMA_CLI")) args
let cli_env env args = run_proc ~env (abs (Sys.getenv "SCHEMA_CLI")) args
let haltsql args = run_proc (abs (Sys.getenv "HALTSQL_BIN")) args

(* ------------------------------------------------------------ non-authoritative *)

let load_errors = function
  | Ok _ -> Alcotest.fail "expected a load error"
  | Error es -> String.concat "; " (List.map Load_error.to_string es)

let policy_yaml catalog =
  Printf.sprintf
    "apiVersion: haltsql.dev/v1\n\
     kind: Policy\n\
     metadata: {name: p}\n\
     search_path: [app]\n\
     catalog: %s\n\
     tables:\n\
    \  app.currencies: {columns: [code, name]}\n"
    catalog

(* (a) A policy whose catalog: is a non-authoritative snapshot does not load. *)
let test_non_authoritative_refused () =
  let dir = tmpdir () in
  let snap, _ = sample_snapshot () in
  let fetched = { snap with authoritative = false } in
  write
    (Filename.concat dir "fetched.json")
    (Yojson.Safe.pretty_to_string (Snap.to_json fetched));
  write
    (Filename.concat dir "pulled.json")
    (Yojson.Safe.pretty_to_string (Snap.to_json snap));
  let load y =
    Policy_load.of_string ~file:"p.yaml" ~base_dir:dir Docload.Yaml (policy_yaml y)
  in
  let m = load_errors (load "fetched.json") in
  check_contains "refused" m "not authoritative";
  check_contains "hint" m "haltsql schema pull";
  check_contains "path" m "metadata.authoritative";
  (match load "pulled.json" with
  | Ok _ -> ()
  | Error es ->
      Alcotest.failf "pulled: %s" (String.concat "; " (List.map Load_error.to_string es)));
  (* Inline catalogs too, and the flag must be a boolean. *)
  let inline v =
    Printf.sprintf
      "{metadata: {authoritative: %s}, tables: {app.currencies: {columns: [{name: code, \
       type: text}, {name: name, type: text}]}}}"
      v
  in
  check_contains "inline refused"
    (load_errors (load (inline "false")))
    "not authoritative";
  check_contains "not a bool" (load_errors (load (inline "\"no\""))) "boolean";
  ignore
    (get_ok "inline true" (Result.map_error (fun _ -> "error") (load (inline "true"))));
  (* Pulled snapshots are unchanged: no authoritative key at all. *)
  check_not_contains "pulled has no flag"
    (Yojson.Safe.to_string (Snap.to_json snap))
    "authoritative";
  let code, out, err = haltsql [ "validate"; Filename.concat dir "fetched.json" ] in
  Alcotest.(check bool) "validate fails" true (code <> 0);
  check_contains "validate msg" (out ^ err) "haltsql schema pull"

(* (b) A draft from a non-authoritative snapshot has no catalog:, and SELECT * is
   denied while explicit allowed columns are not. *)
let test_draft_non_authoritative () =
  let snap, _ = sample_snapshot () in
  let snap = { snap with authoritative = false } in
  let dir = tmpdir () in
  let cfg =
    {
      (Draft.default_config ~tenant_column:"tenant_id" ~catalog_ref:"") with
      name = "fetched-draft";
    }
  in
  let r = get_ok "draft" (Draft.draft ~base_dir:dir cfg snap sample_pii) in
  let y = r.yaml in
  check_not_contains "no catalog key" y "\ncatalog:";
  check_contains "header" y
    "# Structure: from a data catalog (`haltsql schema fetch`), NOT from the database.\n";
  check_contains "header star" y "SELECT *, t.* and whole-row references";
  check_contains "columns still drafted" y
    "  app.customers:\n    columns: [id, tenant_id, name, country, created_at]\n";
  let path = Filename.concat dir "p.yaml" in
  write path y;
  let p =
    match Policy_load.of_file path with
    | Ok p -> p
    | Error es ->
        Alcotest.failf "load: %s" (String.concat "; " (List.map Load_error.to_string es))
  in
  let star = "SELECT * FROM app.customers WHERE tenant_id = $1 LIMIT 10" in
  Alcotest.(check (list string))
    "star denied" [ "E_COLUMN_DENIED" ]
    (List.sort_uniq compare (codes (Haltsql.verify p ctx star)));
  (* Even on a table with nothing excluded: the column list may be incomplete. *)
  let v = Haltsql.verify p ctx "SELECT * FROM app.currencies LIMIT 5" in
  Alcotest.(check (list string)) "global star denied" [ "E_COLUMN_DENIED" ] (codes v);
  let v =
    Haltsql.verify p ctx
      "SELECT id, name FROM app.customers WHERE tenant_id = $1 LIMIT 10"
  in
  Alcotest.(check bool) "explicit allowed" true v.allowed;
  (* The same through `haltsql verify`. *)
  let verify sql =
    haltsql [ "verify"; "-p"; path; "-c"; {|{"tenant_id": "acme"}|}; "-s"; sql; "--json" ]
  in
  let code, out, _ = verify star in
  Alcotest.(check int) "cli star exit" 1 code;
  check_contains "cli star reason" out "E_COLUMN_DENIED";
  let code, _, _ =
    verify "SELECT id, name FROM app.customers WHERE tenant_id = $1 LIMIT 10"
  in
  Alcotest.(check int) "cli explicit exit" 0 code

let test_cli_import () =
  let dir = tmpdir () in
  let out = Filename.concat dir "pii.json" in
  let code, stdout, _ =
    cli
      [ "schema"; "import"; "--from"; "dbt"; ex "dbt_manifest.json"; "-o"; out; "--json" ]
  in
  Alcotest.(check int) "exit" 0 code;
  let j = Yojson.Safe.from_string stdout in
  Alcotest.(check string)
    "summary"
    (Printf.sprintf
       {|{"output":%S,"source":"dbt","scanned_columns":18,"pii_columns":8,"warnings":[]}|}
       out)
    (Yojson.Safe.to_string j);
  let m = get_ok "manifest" (Pii.of_file out) in
  Alcotest.(check int) "entries" 8 (List.length m);
  check_contains "metadata" (read out) {|"generated_by": "haltsql schema import"|};
  (* stdout mode with custom tags *)
  let code, stdout, _ =
    cli
      [
        "schema";
        "import";
        "--from";
        "unity";
        ex "unity_column_tags.json";
        "--pii-tag";
        "secret";
      ]
  in
  Alcotest.(check int) "exit stdout" 0 code;
  let m = get_ok "stdout manifest" (Pii.of_json (Yojson.Safe.from_string stdout)) in
  Alcotest.check exp_t "custom tag"
    (norm [ ("app", "users", "password_hash", [ "secret" ]) ])
    (norm (entries m));
  (* wrong format: exit 1; missing file: exit 2; bad --from: exit 2 *)
  let code, _, err =
    cli [ "schema"; "import"; "--from"; "collibra"; ex "dbt_manifest.json" ]
  in
  Alcotest.(check int) "wrong format exit" 1 code;
  check_contains "wrong format msg" err "no column metadata found";
  let code, stdout, _ =
    cli [ "schema"; "import"; "--from"; "openmetadata"; ex "openmetadata_tables.json" ]
  in
  Alcotest.(check int) "openmetadata exit" 0 code;
  let m = get_ok "om manifest" (Pii.of_json (Yojson.Safe.from_string stdout)) in
  Alcotest.check exp_t "openmetadata cli" (norm om_expected) (norm (entries m));
  let code, _, err = cli [ "schema"; "import"; "--from"; "dbt"; "/nonexistent/x.json" ] in
  Alcotest.(check int) "missing exit" 2 code;
  check_contains "missing msg" err "file not found";
  let code, _, _ =
    cli [ "schema"; "import"; "--from"; "snowflake"; ex "dbt_manifest.json" ]
  in
  Alcotest.(check int) "bad source exit" 2 code

let test_cli_draft_and_lint () =
  let dir = tmpdir () in
  let snap, _ = sample_snapshot () in
  let catalog = Filename.concat dir "catalog.json" in
  write catalog (Yojson.Safe.pretty_to_string (Snap.to_json snap));
  let pii = Filename.concat dir "pii.json" in
  write pii (Yojson.Safe.to_string (Pii.to_json sample_pii));
  let policy = Filename.concat dir "out/saas.yaml" in
  let code, stdout, err =
    cli
      [
        "policy";
        "draft";
        "--catalog";
        catalog;
        "--pii";
        pii;
        "--tenant-column";
        "tenant_id";
        "--schema";
        "app";
        "-o";
        policy;
        "--json";
      ]
  in
  Alcotest.(check int) "exit" 0 code;
  check_contains "warning on stderr" err
    "haltsql: warning: PII column app.ghost.c is not in the catalog";
  Alcotest.(check string)
    "summary"
    (Printf.sprintf
       {|{"output":%S,"tables":6,"tenant_scoped":5,"global":1,"excluded_columns":4,"skipped_relations":3,"warnings":["PII column app.ghost.c is not in the catalog"]}|}
       policy)
    (Yojson.Safe.to_string (Yojson.Safe.from_string stdout));
  let y = read policy in
  check_contains "name from file" y "  name: saas\n";
  check_contains "relative catalog" y "catalog: \"../catalog.json\"\n";
  (* haltsql lint-policy accepts it with no errors. *)
  let code, stdout, _ = haltsql [ "lint-policy"; policy; "--json" ] in
  Alcotest.(check int) "lint exit" 0 code;
  let findings =
    match Yojson.Safe.from_string stdout with
    | `Assoc kvs -> (
        match List.assoc_opt "findings" kvs with Some (`List l) -> l | _ -> [])
    | _ -> []
  in
  let sev f = match f with `Assoc kvs -> List.assoc_opt "severity" kvs | _ -> None in
  Alcotest.(check bool)
    "no lint errors" false
    (List.exists (fun f -> sev f = Some (`String "error")) findings);
  let code, stdout, _ = haltsql [ "validate"; policy ] in
  Alcotest.(check int) "validate exit" 0 code;
  check_contains "validate ok" stdout "ok";
  (* stdout mode; missing catalog is a usage error *)
  let code, stdout, _ =
    cli
      [
        "policy";
        "draft";
        "--catalog";
        catalog;
        "--tenant-column";
        "tenant_id";
        "--catalog-ref";
        catalog;
      ]
  in
  Alcotest.(check int) "stdout exit" 0 code;
  check_contains "stdout yaml" stdout "apiVersion: haltsql.dev/v1\n";
  let code, _, err =
    cli [ "policy"; "draft"; "--catalog"; "/nope.json"; "--tenant-column"; "t" ]
  in
  Alcotest.(check int) "missing catalog exit" 2 code;
  check_contains "missing catalog msg" err "catalog file not found";
  let code, _, _ = cli [ "policy"; "draft"; "--catalog"; catalog ] in
  Alcotest.(check int) "missing tenant column exit" 2 code

let test_cli_help () =
  List.iter
    (fun args ->
      let code, out, _ = cli (args @ [ "--help=plain" ]) in
      Alcotest.(check int) "help exit" 0 code;
      check_contains "examples" out "EXAMPLES")
    [
      [ "schema"; "pull" ];
      [ "schema"; "import" ];
      [ "schema"; "fetch" ];
      [ "policy"; "draft" ];
    ]

let test_cli_pull_errors () =
  (* Nothing listens on port 1: connection error, exit 2, password never printed. *)
  let code, _, err =
    cli
      [
        "schema";
        "pull";
        "--dsn";
        "postgres://u:sup3rs3cretpw@127.0.0.1:1/db?sslmode=disable";
        "--timeout";
        "3";
      ]
  in
  Alcotest.(check int) "exit" 2 code;
  check_contains "message" err
    "schema pull from postgres://u@127.0.0.1:1/db?sslmode=disable failed";
  check_not_contains "no password" err "sup3rs3cretpw";
  let code, _, err =
    cli [ "schema"; "pull"; "--dsn"; "postgres://u:sup3rs3cretpw@h/db?bogus=1" ]
  in
  Alcotest.(check int) "bad dsn exit" 2 code;
  check_contains "bad dsn" err "unknown DSN parameter \"bogus\"";
  check_not_contains "no password" err "sup3rs3cretpw"

let test_cli_fetch () =
  let dir = tmpdir () in
  let pii = Filename.concat dir "pii.json"
  and snap = Filename.concat dir "out/fetched.json" in
  let env = [ ("FAKE_CATALOG_DOC", abs (ex "dbt_manifest.json")) ] in
  let fetch ?(env = env) args =
    cli_env env ([ "schema"; "fetch"; "--from"; "fake" ] @ args)
  in
  let code, stdout, err =
    fetch
      [
        "--url";
        "https://catalog.example.com/api/";
        "--schema";
        "app";
        "--database";
        "saas";
        "-o";
        pii;
        "--snapshot-out";
        snap;
        "--json";
      ]
  in
  Alcotest.(check int) "exit" 0 code;
  check_contains "no-token warning" err "FAKE_CATALOG_TOKEN is not set";
  let j = Yojson.Safe.from_string stdout in
  let field k = match j with `Assoc kvs -> List.assoc_opt k kvs | _ -> None in
  Alcotest.(check (option string))
    "summary source" (Some "fake")
    (Option.map Yojson.Safe.Util.to_string (field "source"));
  Alcotest.(check (option string))
    "summary snapshot" (Some snap)
    (Option.map Yojson.Safe.Util.to_string (field "snapshot"));
  Alcotest.(check (option int))
    "pii columns" (Some 8)
    (Option.map Yojson.Safe.Util.to_int (field "pii_columns"));
  let m = read pii in
  check_contains "manifest source" m {|"source": "fake"|};
  check_contains "manifest url" m {|"url": "https://catalog.example.com/api/"|};
  check_contains "manifest generated_by" m {|"generated_by": "haltsql schema fetch"|};
  ignore (get_ok "manifest loads" (Pii.of_file pii));
  let s = read snap in
  check_contains "snapshot flag" s {|"authoritative": false|};
  (match Catalog_load.of_file snap with
  | Ok _ -> Alcotest.fail "fetched snapshot loads as a policy catalog"
  | Error _ -> ());
  (* policy draft accepts it, warns, and drafts without catalog: *)
  let policy = Filename.concat dir "policy.yaml" in
  let code, _, err =
    cli
      [
        "policy";
        "draft";
        "--catalog";
        snap;
        "--pii";
        pii;
        "--tenant-column";
        "tenant_id";
        "--schema";
        "app";
        "-o";
        policy;
      ]
  in
  Alcotest.(check int) "draft exit" 0 code;
  check_contains "draft warning" err "non-authoritative snapshot";
  let y = read policy in
  check_not_contains "no catalog:" y "\ncatalog:";
  let verify sql =
    haltsql [ "verify"; "-p"; policy; "-c"; {|{"tenant_id": "acme"}|}; "-s"; sql ]
  in
  let code, _, _ = verify "SELECT * FROM app.customers WHERE tenant_id = $1 LIMIT 5" in
  Alcotest.(check int) "star denied" 1 code;
  let code, _, _ = verify "SELECT id FROM app.customers WHERE tenant_id = $1 LIMIT 5" in
  Alcotest.(check int) "explicit allowed" 0 code;
  (* stdout manifest, token from a file *)
  let tf = Filename.concat dir "token" in
  write tf "  tok-FILE-SECRET\n";
  Unix.chmod tf 0o600;
  let code, stdout, err =
    fetch [ "--url"; "https://catalog.example.com"; "--token-file"; tf ]
  in
  Alcotest.(check int) "stdout exit" 0 code;
  check_not_contains "no warning" err "not set";
  check_not_contains "token not printed" (stdout ^ err) "tok-FILE-SECRET";
  ignore (get_ok "stdout manifest" (Pii.of_json (Yojson.Safe.from_string stdout)));
  (* usage errors: exit 2 *)
  let expect2 what args msg =
    let code, _, err = fetch args in
    Alcotest.(check int) (what ^ " exit") 2 code;
    check_contains what err msg
  in
  expect2 "http" [ "--url"; "http://catalog.example.com" ] "use https";
  expect2 "token env unset"
    [ "--url"; "https://c.example.com"; "--token-env"; "HALTSQL_TEST_UNSET_VAR" ]
    "HALTSQL_TEST_UNSET_VAR";
  expect2 "both token sources"
    [ "--url"; "https://c.example.com"; "--token-env"; "X"; "--token-file"; tf ]
    "mutually exclusive";
  write tf "\n";
  expect2 "empty token file"
    [ "--url"; "https://c.example.com"; "--token-file"; tf ]
    "empty";
  expect2 "timeout" [ "--url"; "https://c.example.com"; "--timeout"; "0" ] "--timeout";
  expect2 "max pages"
    [ "--url"; "https://c.example.com"; "--max-pages"; "0" ]
    "--max-pages";
  (* network failure: exit 2, the token never printed *)
  let code, _, err =
    fetch
      ~env:[ ("FAKE_CATALOG_TOKEN", "tok-ENV-SECRET") ]
      [ "--url"; "http://127.0.0.1:1" ]
  in
  Alcotest.(check int) "network exit" 2 code;
  check_contains "network msg" err "schema fetch from http://127.0.0.1:1 (fake) failed";
  check_not_contains "network token" err "tok-ENV-SECRET";
  (* a document without column metadata: exit 1 *)
  let empty = Filename.concat dir "empty.json" in
  write empty {|{"nodes": {}}|};
  let code, _, _ =
    fetch ~env:[ ("FAKE_CATALOG_DOC", empty) ] [ "--url"; "https://c.example.com" ]
  in
  Alcotest.(check int) "no metadata exit" 1 code;
  (* unknown provider; and the real build, which has no providers yet *)
  let code, _, err =
    cli [ "schema"; "fetch"; "--from"; "nope"; "--url"; "https://c.example.com" ]
  in
  Alcotest.(check int) "unknown exit" 2 code;
  check_contains "unknown msg" err "available: fake";
  let code, _, err =
    cli
      [
        "schema-noproviders";
        "fetch";
        "--from";
        "openmetadata";
        "--url";
        "https://c.example.com";
      ]
  in
  Alcotest.(check int) "none exit" 2 code;
  check_contains "none msg" err
    "no live catalog providers are built into this haltsql yet";
  check_contains "none hint" err "haltsql schema import"

(* ------------------------------------------------------------ fake servers *)

(* A one-connection fake Postgres server on 127.0.0.1 for protocol edge cases. *)
let with_fake_server handler client =
  let open Lwt.Syntax in
  Lwt_main.run
    (let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
     Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
     let* () = Lwt_unix.bind fd (Unix.ADDR_INET (Unix.inet_addr_loopback, 0)) in
     Lwt_unix.listen fd 1;
     let port =
       match Lwt_unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> assert false
     in
     let serve =
       Lwt.catch
         (fun () ->
           let* c, _ = Lwt_unix.accept fd in
           Lwt.finalize (fun () -> handler c) (fun () -> Lwt_unix.close c))
         (fun _ -> Lwt.return_unit)
     in
     let* r =
       Lwt.catch
         (fun () -> Lwt.map Result.ok (client port))
         (function Ct.Pg_wire.Error m -> Lwt.return (Error m) | e -> Lwt.fail e)
     in
     Lwt.cancel serve;
     let* () = Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) in
     Lwt.return r)

let rec read_exact fd buf off n =
  let open Lwt.Syntax in
  if n = 0 then Lwt.return_unit
  else
    let* k = Lwt_unix.read fd buf off n in
    if k = 0 then Lwt.fail End_of_file else read_exact fd buf (off + k) (n - k)

let read_bytes fd n =
  let open Lwt.Syntax in
  let b = Bytes.create n in
  let* () = read_exact fd b 0 n in
  Lwt.return (Bytes.to_string b)

let read_startup fd =
  let open Lwt.Syntax in
  let* len = read_bytes fd 4 in
  read_bytes fd (Int32.to_int (String.get_int32_be len 0) - 4)

let read_client_msg fd =
  let open Lwt.Syntax in
  let* hdr = read_bytes fd 5 in
  read_bytes fd (Int32.to_int (String.get_int32_be hdr 1) - 4)

let send_msg fd typ body =
  let b = Buffer.create 16 in
  Buffer.add_char b typ;
  Buffer.add_int32_be b (Int32.of_int (4 + String.length body));
  Buffer.add_string b body;
  let s = Buffer.contents b in
  Lwt.map ignore (Lwt_unix.write_string fd s 0 (String.length s))

let i32 n =
  let b = Buffer.create 4 in
  Buffer.add_int32_be b (Int32.of_int n);
  Buffer.contents b

let fake_dsn port mode =
  {
    (get_ok "dsn"
       (Dsn.parse ~env:no_env (Printf.sprintf "postgres://u:pw@127.0.0.1:%d/db" port)))
    with
    sslmode = mode;
  }

let connect_and_close dsn =
  let open Lwt.Syntax in
  let* c = Ct.Pg_wire.connect ~timeout:5. dsn in
  let tls = Ct.Pg_wire.tls c in
  let* () = Ct.Pg_wire.close c in
  Lwt.return tls

let test_fake_scram_skip () =
  (* The server asks for SCRAM, then claims success without sending SASLFinal: a man in
     the middle that does not know the password. The client must refuse. *)
  let open Lwt.Syntax in
  let r =
    with_fake_server
      (fun c ->
        let* _ = read_startup c in
        let* () = send_msg c 'R' (i32 10 ^ "SCRAM-SHA-256\000\000") in
        let* _ = read_client_msg c in
        let* () = send_msg c 'R' (i32 0) in
        send_msg c 'Z' "I")
      (fun port -> connect_and_close (fake_dsn port Dsn.Disable))
  in
  Alcotest.(check (result bool string))
    "scram skip refused"
    (Error "server ended SCRAM authentication without proving the password") r

let test_fake_tls_refused () =
  let open Lwt.Syntax in
  let refuse_tls c =
    let* req = read_bytes c 8 in
    Alcotest.(check string) "SSLRequest" (i32 8 ^ i32 80877103) req;
    let* _ = Lwt_unix.write_string c "N" 0 1 in
    Lwt.return_unit
  in
  let r =
    with_fake_server refuse_tls (fun port ->
        connect_and_close (fake_dsn port Dsn.Verify_full))
  in
  Alcotest.(check (result bool string))
    "verify-full refused"
    (Error "server does not support TLS, but sslmode=verify-full requires it") r;
  (* prefer: falls back to plaintext and trust authentication works. *)
  let r =
    with_fake_server
      (fun c ->
        let* () = refuse_tls c in
        let* startup = read_startup c in
        Alcotest.(check bool)
          "read-only startup" true
          (contains startup "default_transaction_read_only\000on\000");
        let* () = send_msg c 'R' (i32 0) in
        let* () = send_msg c 'S' "server_version\00017.2\000" in
        let* () = send_msg c 'Z' "I" in
        Lwt.map ignore (read_client_msg c))
      (fun port -> connect_and_close (fake_dsn port Dsn.Prefer))
  in
  Alcotest.(check (result bool string)) "prefer falls back to plaintext" (Ok false) r

let test_fake_server_error () =
  let open Lwt.Syntax in
  let r =
    with_fake_server
      (fun c ->
        let* _ = read_startup c in
        send_msg c 'E'
          "SFATAL\000VFATAL\000C28000\000Mno pg_hba.conf entry for host\000\000")
      (fun port -> connect_and_close (fake_dsn port Dsn.Disable))
  in
  Alcotest.(check (result bool string))
    "error propagated" (Error "FATAL 28000: no pg_hba.conf entry for host") r;
  (* A huge declared message length is rejected instead of allocated. *)
  let r =
    with_fake_server
      (fun c ->
        let* _ = read_startup c in
        let s = "R" ^ i32 0x7fffffff in
        Lwt.map ignore (Lwt_unix.write_string c s 0 (String.length s)))
      (fun port -> connect_and_close (fake_dsn port Dsn.Disable))
  in
  Alcotest.(check (result bool string))
    "length cap" (Error "protocol error: invalid message length") r

(* ------------------------------------------------------------ Postgres integration *)

let admin_dsn_s =
  match Sys.getenv_opt "HALTSQL_TEST_PG_DSN" with
  | Some s when s <> "" -> s
  | _ ->
      Printf.sprintf "postgres://postgres:%s@localhost:5417/postgres?sslmode=disable"
        (Option.value ~default:"haltlab" (Sys.getenv_opt "HALTSQL_PGPASSWORD"))

let admin_dsn = lazy (get_ok "admin dsn" (Dsn.parse admin_dsn_s))
let test_db = "haltsql_schema_test"
let db_dsn () = { (Lazy.force admin_dsn) with dbname = test_db }

let db_dsn_s () =
  let d = Lazy.force admin_dsn in
  Printf.sprintf "postgres://%s:%s@%s:%d/%s?sslmode=disable" d.user
    (Option.value d.password ~default:"")
    d.host d.port test_db

let pg_available =
  lazy
    (match
       Lwt_main.run
         (Lwt.catch
            (fun () ->
              Ct.Pg_wire.with_conn ~timeout:3. (Lazy.force admin_dsn) (fun _ ->
                  Lwt.return (Ok ())))
            (fun e -> Lwt.return (Error (Printexc.to_string e))))
     with
    | Ok () -> true
    | Error e ->
        Printf.eprintf
          "SKIP Postgres integration tests: %s not reachable (%s). Run `make -C lab up`.\n\
           %!"
          (Dsn.redacted (Lazy.force admin_dsn))
          e;
        false)

let require_pg () = if not (Lazy.force pg_available) then Alcotest.skip ()

let admin_exec sql =
  Lwt_main.run
    (Ct.Pg_wire.with_conn ~read_only:false (Lazy.force admin_dsn) (fun c ->
         Ct.Pg_wire.simple_query c sql))

let extra_sql =
  {|CREATE SCHEMA extra;
CREATE TABLE extra.events (id bigint, tenant_id text, at date) PARTITION BY RANGE (at);
CREATE TABLE extra.events_2026 PARTITION OF extra.events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE VIEW extra.v_events AS SELECT id, tenant_id FROM extra.events;
CREATE MATERIALIZED VIEW extra.mv AS SELECT count(*) AS n FROM extra.events;
CREATE TABLE extra."Mixed Case" ("Id" integer, amount numeric(10,2), dropped int, v varchar(20), tags text[]);
ALTER TABLE extra."Mixed Case" DROP COLUMN dropped;
CREATE SEQUENCE extra.seq;
CREATE TABLE extra.empty ();|}

let setup_db =
  lazy
    (ignore
       (admin_exec (Printf.sprintf "DROP DATABASE IF EXISTS %s WITH (FORCE)" test_db));
     ignore (admin_exec (Printf.sprintf "CREATE DATABASE %s" test_db));
     let sql = read "../../lab/schemas/saas_shared.sql" in
     Lwt_main.run
       (Ct.Pg_wire.with_conn ~read_only:false (db_dsn ()) (fun c ->
            let open Lwt.Syntax in
            let* _ = Ct.Pg_wire.simple_query c sql in
            let* _ = Ct.Pg_wire.simple_query c extra_sql in
            Lwt.return_unit)))

let cols_of (snap : Snap.t) s n =
  match Catalog.find snap.catalog ~schema:s ~name:n with
  | Some t ->
      List.map
        (fun (c : Catalog.column) -> (c.col_name, Option.value c.col_type ~default:"?"))
        t.columns
  | None -> Alcotest.failf "%s.%s missing from snapshot" s n

let test_pg_pull () =
  require_pg ();
  Lazy.force setup_db;
  let snap, warnings =
    get_ok "pull" (Pull.pull ~schemas:[ "app"; "extra" ] (db_dsn ()))
  in
  Alcotest.(check (list string))
    "warnings"
    [ "skipped table extra.empty: it has no columns" ]
    warnings;
  let strs = Alcotest.(list (pair string string)) in
  Alcotest.check strs "customers (PII columns present, typed)"
    [
      ("id", "bigint");
      ("tenant_id", "text");
      ("name", "text");
      ("email", "text");
      ("phone", "text");
      ("ssn", "text");
      ("country", "character(2)");
      ("created_at", "timestamp with time zone");
    ]
    (cols_of snap "app" "customers");
  Alcotest.check strs "users"
    [
      ("id", "bigint");
      ("tenant_id", "text");
      ("email", "text");
      ("full_name", "text");
      ("role", "text");
      ("password_hash", "text");
      ("created_at", "timestamp with time zone");
      ("last_login_at", "timestamp with time zone");
    ]
    (cols_of snap "app" "users");
  Alcotest.check strs "currencies"
    [
      ("code", "character(3)");
      ("name", "text");
      ("symbol", "text");
      ("decimals", "smallint");
    ]
    (cols_of snap "app" "currencies");
  Alcotest.check strs "payments.card_token present"
    [ ("card_token", "text") ]
    (List.filter (fun (c, _) -> c = "card_token") (cols_of snap "app" "payments"));
  Alcotest.check strs "quoted identifiers, dropped column gone"
    [
      ("Id", "integer");
      ("amount", "numeric(10,2)");
      ("v", "character varying(20)");
      ("tags", "text[]");
    ]
    (cols_of snap "extra" "Mixed Case");
  let kind n s =
    Option.map Snap.relkind_to_string (Snap.relkind snap ~schema:s ~name:n)
  in
  Alcotest.(check (option string))
    "partitioned" (Some "partitioned table") (kind "events" "extra");
  Alcotest.(check (option string))
    "partition" (Some "partition") (kind "events_2026" "extra");
  Alcotest.(check (option string)) "view" (Some "view") (kind "v_events" "extra");
  Alcotest.(check (option string))
    "matview" (Some "materialized view") (kind "mv" "extra");
  Alcotest.(check (option string)) "sequence" (Some "sequence") (kind "seq" "extra");
  Alcotest.(check (option string))
    "bigserial sequence" (Some "sequence") (kind "orders_id_seq" "app");
  let app =
    List.filter (fun (t : Catalog.table) -> t.schema = "app") snap.catalog.tables
  in
  Alcotest.(check int) "app relations (9 tables + 8 sequences)" 17 (List.length app);
  Alcotest.(check (option string)) "database" (Some test_db) snap.database;
  Alcotest.(check bool)
    "server version 17" true
    (match snap.server_version with
    | Some v -> String.starts_with ~prefix:"17" v
    | None -> false);
  (* Sorted, and stable across pulls. *)
  let keys =
    List.map (fun (t : Catalog.table) -> (t.schema, t.name)) snap.catalog.tables
  in
  Alcotest.(check bool) "sorted" true (keys = List.sort compare keys);
  let snap2, _ =
    get_ok "pull again" (Pull.pull ~schemas:[ "extra"; "app" ] (db_dsn ()))
  in
  Alcotest.(check string)
    "deterministic"
    (Yojson.Safe.to_string (Snap.to_json snap))
    (Yojson.Safe.to_string (Snap.to_json snap2));
  (* Only the requested schema. *)
  let snap3, _ = get_ok "pull app" (Pull.pull ~schemas:[ "app" ] (db_dsn ())) in
  Alcotest.(check bool)
    "app only" true
    (List.for_all (fun (t : Catalog.table) -> t.schema = "app") snap3.catalog.tables);
  (* End to end: pulled catalog + dbt PII -> draft -> load -> analyzer trusts the catalog. *)
  let dir = tmpdir () in
  let catalog = Filename.concat dir "catalog.json" in
  write catalog (Yojson.Safe.pretty_to_string (Snap.to_json snap3));
  let pii = (get_ok "dbt" (Imp.import_file Imp.Dbt (ex "dbt_manifest.json"))).manifest in
  let cfg = Draft.default_config ~tenant_column:"tenant_id" ~catalog_ref:"catalog.json" in
  let r = get_ok "draft" (Draft.draft ~base_dir:dir cfg snap3 pii) in
  let policy = Filename.concat dir "policy.yaml" in
  write policy r.yaml;
  check_contains "customers drafted" r.yaml
    "  app.customers:\n\
    \    columns: [id, tenant_id, name, country, created_at]\n\
    \    tenant_column: tenant_id\n";
  check_contains "users drafted" r.yaml
    "  app.users:\n    columns: [id, tenant_id, role, created_at, last_login_at]\n";
  check_contains "payments drafted" r.yaml
    "  app.payments:\n\
    \    columns: [id, tenant_id, invoice_id, method, amount_cents, paid_at]\n";
  check_contains "audit drafted" r.yaml
    "  app.audit_events:\n\
    \    columns: [id, tenant_id, actor_user_id, action, detail, created_at]\n";
  let p =
    match Policy_load.of_file policy with
    | Ok p -> p
    | Error es ->
        Alcotest.failf "load: %s" (String.concat "; " (List.map Load_error.to_string es))
  in
  let v = Haltsql.verify p ctx "SELECT * FROM app.users WHERE tenant_id = $1 LIMIT 5" in
  Alcotest.(check (list string))
    "star on users denied" [ "E_COLUMN_DENIED" ]
    (List.sort_uniq compare (codes v));
  let v = Haltsql.verify p ctx "SELECT * FROM app.currencies LIMIT 5" in
  Alcotest.(check bool) "currencies star allowed (catalog expansion)" true v.allowed;
  let code, _, _ = haltsql [ "lint-policy"; policy ] in
  Alcotest.(check int) "lint" 0 code

let test_pg_cli_pull () =
  require_pg ();
  Lazy.force setup_db;
  let dir = tmpdir () in
  let out = Filename.concat dir "catalog.json" in
  let code, stdout, err =
    cli [ "schema"; "pull"; "--dsn"; db_dsn_s (); "--schema"; "app"; "-o"; out; "--json" ]
  in
  Alcotest.(check int) ("exit; stderr: " ^ err) 0 code;
  let pw = Option.value (Lazy.force admin_dsn).password ~default:"\000" in
  check_not_contains "no password on stdout" stdout pw;
  check_not_contains "no password on stderr" err pw;
  check_not_contains "no password in file" (read out) pw;
  (match Yojson.Safe.from_string stdout with
  | `Assoc kvs ->
      Alcotest.(check (option int))
        "relations" (Some 17)
        (match List.assoc_opt "relations" kvs with Some (`Int n) -> Some n | _ -> None);
      Alcotest.(check (option int))
        "columns" (Some 87)
        (match List.assoc_opt "columns" kvs with Some (`Int n) -> Some n | _ -> None)
  | _ -> Alcotest.fail "summary");
  (match Catalog_load.of_file out with
  | Ok c -> Alcotest.(check int) "loads" 17 (List.length c.tables)
  | Error _ -> Alcotest.fail "catalog does not load");
  let code, _, _ = haltsql [ "validate"; out ] in
  Alcotest.(check int) "haltsql validate" 0 code;
  (* A schema with nothing in it: exit 1. *)
  let code, _, err =
    cli
      [
        "schema";
        "pull";
        "--dsn";
        db_dsn_s ();
        "--schema";
        "nope";
        "-o";
        Filename.concat dir "n.json";
      ]
  in
  Alcotest.(check int) "empty exit" 1 code;
  check_contains "empty msg" err "no relations found"

let test_pg_auth_failures () =
  require_pg ();
  let d = Lazy.force admin_dsn in
  let bad = { d with password = Some "definitely-wrong-pw" } in
  let e = get_error "wrong password" (Pull.pull ~timeout:5. bad) in
  check_contains "auth failed" e "28P01";
  check_not_contains "no password" e "definitely-wrong-pw";
  (* The lab server has ssl=off: sslmode=require must refuse to fall back. *)
  let e =
    get_error "require tls" (Pull.pull ~timeout:5. { d with sslmode = Dsn.Require })
  in
  check_contains "tls refused" e
    "server does not support TLS, but sslmode=require requires it";
  let e =
    get_error "no db"
      (Pull.pull ~timeout:5. { d with dbname = "haltsql_schema_does_not_exist" })
  in
  check_contains "no db" e "3D000"

let test_pg_readonly () =
  require_pg ();
  Lazy.force setup_db;
  (* Sessions opened by Pg_wire default to read-only transactions. *)
  let e =
    match
      Lwt_main.run
        (Lwt.catch
           (fun () ->
             Ct.Pg_wire.with_conn (db_dsn ()) (fun c ->
                 Lwt.map
                   (fun _ -> Ok ())
                   (Ct.Pg_wire.simple_query c "CREATE TABLE app.should_fail (x int)")))
           (function Ct.Pg_wire.Error m -> Lwt.return (Error m) | e -> Lwt.fail e))
    with
    | Ok () -> Alcotest.fail "write succeeded in a read-only session"
    | Error m -> m
  in
  check_contains "read-only" e "25006";
  (* Parameters are sent out of band. *)
  let rows =
    Lwt_main.run
      (Ct.Pg_wire.with_conn (db_dsn ()) (fun c ->
           Ct.Pg_wire.query c "SELECT $1::text || '!', $2::text IS NULL"
             ~params:[ Some "a'; DROP TABLE x; --"; None ]))
  in
  Alcotest.(check (list (array (option string))))
    "params"
    [ [| Some "a'; DROP TABLE x; --!"; Some "t" |] ]
    rows

let teardown () =
  if Lazy.is_val pg_available && Lazy.force pg_available && Lazy.is_val setup_db then
    try
      ignore
        (admin_exec (Printf.sprintf "DROP DATABASE IF EXISTS %s WITH (FORCE)" test_db))
    with e ->
      Printf.printf "warning: could not drop %s: %s\n" test_db (Printexc.to_string e)

(* regression: a DNS name starting with "127." is not loopback (sslmode default) *)
let test_dsn_loopback () =
  List.iter
    (fun (h, expected) -> Alcotest.(check bool) h expected (Dsn.is_loopback h))
    [
      ("127.0.0.1", true);
      ("127.10.0.1", true);
      ("localhost", true);
      ("::1", true);
      ("/var/run/postgresql", true);
      ("127.attacker.example", false);
      ("127.0.0.1.nip.io", false);
      ("127.0.0.256", false);
      ("db.example", false);
    ]

let () =
  let tc name f = Alcotest.test_case name `Quick f in
  (* Probe Postgres up front so the skip message is not swallowed by Alcotest's capture. *)
  ignore (Lazy.force pg_available);
  Fun.protect ~finally:teardown (fun () ->
      Alcotest.run ~and_exit:false "catalog_tools"
        [
          ( "dsn",
            [
              tc "url" test_dsn_url;
              tc "ipv6+defaults" test_dsn_ipv6_and_defaults;
              tc "keywords" test_dsn_keywords;
              tc "errors" test_dsn_errors;
              tc "loopback hosts" test_dsn_loopback;
            ] );
          ("scram", [ tc "pbkdf2" test_pbkdf2; tc "rfc7677" test_scram_rfc7677 ]);
          ("matcher", [ tc "tokens+match" test_matcher ]);
          ( "import",
            [
              tc "dbt manifest" test_dbt_manifest;
              tc "dbt custom tags" test_dbt_custom_tags;
              tc "dbt catalog" test_dbt_catalog;
              tc "datahub mce/mcp" test_datahub_mce;
              tc "datahub graphql" test_datahub_graphql;
              tc "unity" test_unity;
              tc "atlan" test_atlan;
              tc "collibra" test_collibra;
              tc "openmetadata" test_openmetadata;
              tc "wrong format" test_import_wrong_format;
              tc "manifest json" test_pii_json;
            ] );
          ("snapshot", [ tc "build" test_build_snapshot ]);
          ( "draft",
            [
              tc "relative path" test_relative_path;
              tc "draft" test_draft;
              tc "options" test_draft_options;
              tc "non-authoritative refused" test_non_authoritative_refused;
              tc "non-authoritative draft" test_draft_non_authoritative;
            ] );
          ( "cli",
            [
              tc "import" test_cli_import;
              tc "draft+lint" test_cli_draft_and_lint;
              tc "help" test_cli_help;
              tc "pull errors" test_cli_pull_errors;
              tc "fetch" test_cli_fetch;
            ] );
          ( "protocol",
            [
              tc "scram skip" test_fake_scram_skip;
              tc "tls refused" test_fake_tls_refused;
              tc "server error" test_fake_server_error;
            ] );
          ( "postgres",
            [
              tc "pull" test_pg_pull;
              tc "cli pull" test_pg_cli_pull;
              tc "auth failures" test_pg_auth_failures;
              tc "read-only" test_pg_readonly;
            ] );
        ])
