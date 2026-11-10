(* console/06-comply: data classification (catalog merge, allowed_by, exceptions, shadow
   denials, refresh rate limit, live fetch), control mappings, evidence packs (built end
   to end and extracted with tar), and live integration states. *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console
module Ct = Haltsql_catalog_tools
module Cf = Haltsql_catalog_fetch

let write_file path contents =
  Out_channel.with_open_bin path (fun oc -> output_string oc contents)

let read_file path = In_channel.with_open_bin path In_channel.input_all

let tmp_file ?(dir = temp_dir "comply") name contents =
  let p = Filename.concat dir name in
  write_file p contents;
  p

let str = function `String s -> s | j -> Yojson.Safe.to_string j
let strs j = match j with `List l -> List.map str l | _ -> []
let list j = match j with `List l -> l | _ -> []

(* ---- fixtures ---- *)

let dbt_manifest =
  {|{"nodes": {
      "model.x.customers": {"resource_type": "model", "schema": "app", "name": "customers",
        "columns": {
          "id": {"name": "id", "tags": []},
          "email": {"name": "email", "tags": ["pii"]},
          "phone": {"name": "phone", "meta": {"pii": true}},
          "ssn": {"name": "ssn", "tags": ["pii", "ssn"]},
          "tenant_id": {"name": "tenant_id"}}}}}|}

let file_manifest =
  {|{"tables": {
      "app.customers": {"columns": {"email": {"classifications": ["PII", "email"], "source": "manual"}}},
      "billing.invoices": {"columns": {"tax_id": {"classifications": ["government id"], "source": "manual"}}}}}|}

let policy_yaml name tables =
  Printf.sprintf
    {|apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: %s, owner: qa }
dialect: postgres-17
search_path: [app]
statements: { allow: [select] }
tables:
%s
mode: shadow
|}
    name tables

let load_policy name tables =
  let p = tmp_file (name ^ ".yaml") (policy_yaml name tables) in
  match Haltsql.Policy_load.of_file p with
  | Ok pol -> (name, pol)
  | Error errs ->
      Alcotest.failf "policy %s: %s" name
        (String.concat "; " (List.map Haltsql.Load_error.to_string errs))

let support () =
  load_policy "support" "  app.customers:\n    columns: [id, email, phone, tenant_id]"

let finance () = load_policy "finance" "  billing.invoices:\n    columns: \"*\""

let catalogs_extra () =
  let dir = temp_dir "catalogs" in
  let manifest = tmp_file ~dir "manifest.json" dbt_manifest in
  let file = tmp_file ~dir "pii.json" file_manifest in
  [
    ( "catalogs",
      `List
        [
          `Assoc [ ("kind", `String "dbt"); ("manifest", `String manifest) ];
          `Assoc
            [
              ("kind", `String "file"); ("file", `String file); ("label", `String "manual");
            ];
        ] );
    ( "data",
      `Assoc
        [
          ( "exceptions",
            `List
              [
                `Assoc
                  [
                    ("column", `String "app.customers.email");
                    ("policy", `String "support");
                    ("owner", `String "Lee Park");
                    ("ticket", `String "SEC-88");
                    ("expires", `String "2099-01-01");
                  ];
                `Assoc
                  [
                    ("column", `String "app.customers.phone");
                    ("policy", `String "support");
                    ("owner", `String "Lee Park");
                    ("ticket", `String "SEC-12");
                    ("expires", `String "2020-01-01");
                  ];
              ] );
        ] );
  ]

let find_column col doc =
  match
    List.find_opt (fun c -> member "column" c = `String col) (list (member "columns" doc))
  with
  | Some c -> c
  | None -> Alcotest.failf "column %s missing: %s" col (Yojson.Safe.to_string doc)

(* ---- data ---- *)

let data_tests =
  [
    ( "catalogs merged, allowed_by, exception statuses, shadow denials",
      `Quick,
      fun () ->
        with_console ~background:false
          (config ~extra:(catalogs_extra ()) ())
          (fun r ->
            r.ctx.policies <- [ support (); finance () ];
            load_records r
              [
                server_record ~request_id:"shadow-1" ~policy:"support" ~allowed:true
                  ~shadow:true ~codes:[ "E_COLUMN_DENIED" ]
                  ~sql:"SELECT ssn FROM app.customers LIMIT 1" ();
                server_record ~request_id:"ok-1" ~policy:"support"
                  ~sql:"SELECT ssn FROM app.customers LIMIT 1" ();
              ];
            let* res = post r "/api/v1/data/refresh" (`Assoc []) in
            check_status "refresh" 200 res;
            let* res = get r "/api/v1/data/columns?show=all" in
            check_status "columns" 200 res;
            let doc = snd res in
            let sources = list (member "sources" doc) in
            Alcotest.(check int) "two sources" 2 (List.length sources);
            List.iter
              (fun s ->
                Alcotest.(check bool)
                  "authoritative" true
                  (member "authoritative" s = `Bool true);
                Alcotest.(check bool) "no error" true (member "error" s = `Null))
              sources;
            Alcotest.(check bool) "tagged" true (member "totals.tagged" doc = `Int 4);
            Alcotest.(check bool) "tables" true (member "totals.tables" doc = `Int 2);
            let email = find_column "app.customers.email" doc in
            Alcotest.(check (list string))
              "email sources" [ "dbt"; "manual" ]
              (List.sort compare (strs (member "sources" email)));
            Alcotest.(check bool)
              "email tags union" true
              (List.mem "email"
                 (List.map String.lowercase_ascii (strs (member "tags" email)))
              && List.mem "pii"
                   (List.map String.lowercase_ascii (strs (member "tags" email))));
            Alcotest.(check (list string))
              "email allowed_by" [ "support" ]
              (strs (member "allowed_by" email));
            Alcotest.(check string)
              "email exception" "exception"
              (str (member "status" email));
            Alcotest.(check string)
              "owner" "Lee Park"
              (str (member "exception.owner" email));
            Alcotest.(check string)
              "ticket" "SEC-88"
              (str (member "exception.ticket" email));
            let phone = find_column "app.customers.phone" doc in
            Alcotest.(check string)
              "expired exception -> needs_review" "needs_review"
              (str (member "status" phone));
            Alcotest.(check bool)
              "marked expired" true
              (member "exception.expired" phone = `Bool true);
            let tax = find_column "billing.invoices.tax_id" doc in
            Alcotest.(check (list string))
              "tax allowed_by *" [ "finance" ]
              (strs (member "allowed_by" tax));
            Alcotest.(check string)
              "tax needs_review" "needs_review"
              (str (member "status" tax));
            let ssn = find_column "app.customers.ssn" doc in
            Alcotest.(check string) "ssn blocked" "blocked" (str (member "status" ssn));
            Alcotest.(check (list string))
              "ssn allowed_by" []
              (strs (member "allowed_by" ssn));
            Alcotest.(check bool)
              "ssn shadow denials" true
              (member "shadow_denials" ssn = `Int 1);
            Alcotest.(check bool)
              "totals" true
              (member "totals.blocked" doc = `Int 1
              && member "totals.exception" doc = `Int 1
              && member "totals.needs_review" doc = `Int 2);
            Alcotest.(check bool) "stored in ctx" true (r.ctx.catalog_columns <> None);
            (* filters *)
            let* res = get r "/api/v1/data/columns" in
            Alcotest.(check int)
              "default show=allowed hides blocked" 3
              (List.length (list (member "columns" (snd res))));
            let* res = get r "/api/v1/data/columns?show=all&q=government" in
            Alcotest.(check (list string))
              "q matches tags" [ "billing.invoices.tax_id" ]
              (List.map
                 (fun c -> str (member "column" c))
                 (list (member "columns" (snd res))));
            let* res = get r "/api/v1/data/columns?show=nope" in
            check_status "bad show" 400 res;
            Lwt.return_unit) );
    ( "no policies: every tagged column blocked",
      `Quick,
      fun () ->
        with_console ~background:false
          (config ~extra:(catalogs_extra ()) ())
          (fun r ->
            let* () = C.Data.reload r.ctx in
            let* res = get r "/api/v1/data/columns?show=all" in
            let doc = snd res in
            Alcotest.(check bool)
              "all blocked" true
              (member "totals.blocked" doc = `Int 4
              && member "totals.needs_review" doc = `Int 0);
            Lwt.return_unit) );
    ( "refresh is rate limited and logged",
      `Quick,
      fun () ->
        with_console ~background:false
          (config ~role:"dev" ~extra:(catalogs_extra ()) ())
          (fun r ->
            let* res = post r "/api/v1/data/refresh" (`Assoc []) in
            check_status "first (dev may refresh)" 200 res;
            Alcotest.(check bool)
              "totals returned" true
              (member "totals.tagged" (snd res) = `Int 4);
            let* res = post r "/api/v1/data/refresh" (`Assoc []) in
            check_status "second" 429 res;
            Alcotest.(check string)
              "code" "RATE_LIMITED"
              (str (member "error.code" (snd res)));
            let* res = get r "/api/v1/activity?action=data.refresh" in
            Alcotest.(check int)
              "logged once" 1
              (List.length (list (member "entries" (snd res))));
            Lwt.return_unit) );
    ( "catalog errors are reported, not fatal",
      `Quick,
      fun () ->
        let extra =
          [
            ( "catalogs",
              `List
                [
                  `Assoc
                    [
                      ("kind", `String "dbt"); ("manifest", `String "/nonexistent/m.json");
                    ];
                  `Assoc
                    [
                      ("kind", `String "openmetadata");
                      ("url", `String "https://om.example.test/api");
                    ];
                  `Assoc [ ("kind", `String "snowflake"); ("label", `String "weird") ];
                ] );
          ]
        in
        with_console ~background:false (config ~extra ()) (fun r ->
            let* () = C.Data.reload r.ctx in
            let* res = get r "/api/v1/data/columns?show=all" in
            let sources = list (member "sources" (snd res)) in
            Alcotest.(check int) "three sources" 3 (List.length sources);
            List.iter
              (fun s ->
                Alcotest.(check bool) "has error" true (member "error" s <> `Null))
              sources;
            let* res = get r "/api/v1/integrations" in
            let catalogs =
              List.find
                (fun g -> member "name" g = `String "Data catalogs")
                (list (member "groups" (snd res)))
            in
            List.iter
              (fun i ->
                Alcotest.(check string) "catalog state" "error" (str (member "state" i)))
              (list (member "items" catalogs));
            Lwt.return_unit) );
  ]

(* A fake live provider named "datahub" that reads a dbt manifest over HTTP. *)
let auth_seen = ref None

module Fake_datahub : Cf.Provider.S = struct
  let name = "datahub"
  let description = "test"
  let default_token_env = "DATAHUB_TOKEN"

  let fetch client (_ : Cf.Provider.filter) =
    let* r = Cf.Fetch_client.get_json client "/manifest" in
    Lwt.return
      (Result.map
         (fun document ->
           {
             Cf.Provider.source = Ct.Pii_import.Dbt;
             document;
             tables = [];
             warnings = [];
           })
         r)
end

let with_http_server handler f =
  let* addrs =
    Lwt_unix.getaddrinfo "127.0.0.1" "0" [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
  in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  let* () = Lwt_unix.bind fd (List.hd addrs).Unix.ai_addr in
  Lwt_unix.listen fd 16;
  let port =
    match Lwt_unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> assert false
  in
  let stop_p, stop = Lwt.wait () in
  let server = Cohttp_lwt_unix.Server.make ~callback:(fun _ req _ -> handler req) () in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~stop:stop_p ~mode:(`TCP (`Socket fd)) server);
  Lwt.finalize
    (fun () -> f port)
    (fun () ->
      Lwt.wakeup_later stop ();
      Lwt.return_unit)

let live_tests =
  [
    ( "live fetch is non-authoritative and flags columns",
      `Quick,
      fun () ->
        let saved = !C.Data.providers in
        C.Data.providers := [ (module Fake_datahub : Cf.Provider.S) ];
        Fun.protect
          ~finally:(fun () -> C.Data.providers := saved)
          (fun () ->
            Lwt_main.run
              (with_http_server
                 (fun req ->
                   auth_seen :=
                     Cohttp.Header.get (Cohttp.Request.headers req) "authorization";
                   Cohttp_lwt_unix.Server.respond_string ~status:`OK ~body:dbt_manifest ())
                 (fun port ->
                   let url = Printf.sprintf "http://127.0.0.1:%d" port in
                   let cfg =
                     config
                       ~extra:
                         [
                           ( "catalogs",
                             `List
                               [
                                 `Assoc
                                   [
                                     ("kind", `String "datahub");
                                     ("url", `String url);
                                     ("token", `String "dh-secret");
                                   ];
                               ] );
                         ]
                       ()
                   in
                   let store = C.Store.create cfg.state_dir in
                   let ctx = C.Ctx.create ~config:cfg ~store ~index:(C.Index.create ()) in
                   let* () = C.Data.reload ctx in
                   let doc = C.Data.compute ctx in
                   let s = List.hd (list (member "sources" doc)) in
                   Alcotest.(check bool)
                     "not authoritative" true
                     (member "authoritative" s = `Bool false);
                   Alcotest.(check bool) "no error" true (member "error" s = `Null);
                   Alcotest.(check bool)
                     "token not in detail" false
                     (let d = str (member "detail" s) in
                      let n = String.length "dh-secret" in
                      let rec has i =
                        i + n <= String.length d
                        && (String.sub d i n = "dh-secret" || has (i + 1))
                      in
                      has 0);
                   Alcotest.(check (option string))
                     "bearer sent" (Some "Bearer dh-secret") !auth_seen;
                   let email = find_column "app.customers.email" doc in
                   Alcotest.(check bool)
                     "column not authoritative" true
                     (member "authoritative" email = `Bool false);
                   Alcotest.(check (list string))
                     "source" [ "datahub" ]
                     (strs (member "sources" email));
                   Lwt.return_unit))) );
  ]

(* ---- controls ---- *)

let controls_tests =
  let expect fw ids =
    ( "controls " ^ fw,
      `Quick,
      fun () ->
        with_console ~background:false (config ~role:"dev" ()) (fun r ->
            let* res = get r ("/api/v1/evidence/controls?framework=" ^ fw) in
            check_status fw 200 res;
            let doc = snd res in
            Alcotest.(check (list string))
              "ids" ids
              (List.map (fun c -> str (member "id" c)) (list (member "controls" doc)));
            List.iter
              (fun c ->
                Alcotest.(check bool)
                  "has evidence" true
                  (strs (member "evidence" c) <> []);
                Alcotest.(check bool) "has what" true (str (member "what" c) <> ""))
              (list (member "controls" doc));
            let d = str (member "disclaimer" doc) in
            Alcotest.(check bool)
              "disclaimer" true
              (String.length d > 0
              &&
              let sub = "not certified" in
              let n = String.length sub in
              let rec has i =
                i + n <= String.length d && (String.sub d i n = sub || has (i + 1))
              in
              has 0);
            Lwt.return_unit) )
  in
  [
    expect "soc2" [ "CC6.1"; "CC6.3"; "CC7.2"; "CC8.1"; "A1.2" ];
    expect "iso27001" [ "A.5.15"; "A.8.2"; "A.8.15"; "A.8.16"; "A.8.32" ];
    expect "gdpr" [ "Art. 5(1)(f)"; "Art. 25"; "Art. 30"; "Art. 32" ];
    expect "hipaa"
      [ "164.308(a)(1)(ii)(D)"; "164.312(a)(1)"; "164.312(b)"; "164.312(c)(1)" ];
    ( "unknown framework",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            let* res = get r "/api/v1/evidence/controls?framework=pci" in
            check_status "pci" 400 res;
            Lwt.return_unit) );
  ]

(* ---- evidence packs ---- *)

let strip_chain = function
  | `Assoc l -> List.filter (fun (k, _) -> k <> "hash" && k <> "prev_hash") l
  | _ -> assert false

(* A sealed chain of [n] records; [tamper i] changes record i after sealing. *)
let chain ~prefix ?(tamper = -1) n =
  let rec go i prev acc =
    if i = n then List.rev acc
    else
      let fields =
        strip_chain (server_record ~request_id:(Printf.sprintf "%s-%d" prefix i) ())
      in
      let line, hash = Haltsql_cloud.Audit_chain.seal ~prev fields in
      let j = Yojson.Safe.from_string line in
      let j =
        if i = tamper then
          match j with
          | `Assoc l ->
              `Assoc
                (List.map
                   (fun (k, v) ->
                     if k = "caller" then (k, `String "token:mallory") else (k, v))
                   l)
          | j -> j
        else j
      in
      go (i + 1) hash (j :: acc)
  in
  go 0 Haltsql_cloud.Audit_chain.genesis []

let rec wait_ready r id tries =
  let* res = get r "/api/v1/evidence/packs" in
  let pack =
    List.find_opt (fun p -> member "id" p = `String id) (list (member "packs" (snd res)))
  in
  match pack with
  | Some p when member "state" p = `String "ready" -> Lwt.return p
  | Some p when member "state" p = `String "failed" ->
      Alcotest.failf "pack failed: %s" (Yojson.Safe.to_string p)
  | _ when tries = 0 -> Alcotest.fail "pack never became ready"
  | _ ->
      let* () = Lwt_unix.sleep 0.05 in
      wait_ready r id (tries - 1)

let get_raw r path =
  let* resp, body = Cohttp_lwt_unix.Client.get (uri r path) in
  let* s = Cohttp_lwt.Body.to_string body in
  Lwt.return (resp, s)

let pack_tests =
  [
    ( "pack built end to end",
      `Quick,
      fun () ->
        let extra =
          [
            ( "agents",
              `List
                [
                  `Assoc
                    [
                      ("name", `String "billing-reconciler"); ("via", `String "in_process");
                    ];
                  `Assoc
                    [ ("name", `String "analytics-agent"); ("via", `String "sidecar") ];
                ] );
            ( "data",
              `Assoc
                [
                  ( "exceptions",
                    `List
                      [
                        `Assoc
                          [
                            ("column", `String "app.customers.email");
                            ("owner", `String "Lee Park");
                            ("expires", `String "2099-01-01");
                          ];
                      ] );
                ] );
          ]
        in
        with_console ~background:false (config ~role:"audit" ~extra ()) (fun r ->
            r.ctx.policies <- [ support () ];
            r.ctx.ingest_status <-
              `List
                [
                  `Assoc
                    [
                      ("source", `String "s3://acme-audit/haltsql/");
                      ("error", `String "AccessDenied");
                    ];
                  `Assoc [ ("source", `String "/var/log/ok.jsonl"); ("error", `Null) ];
                ];
            load_records ~verifier:"haltsql-1" r (chain ~prefix:"a" 3);
            load_records ~verifier:"haltsql-2" r (chain ~prefix:"b" ~tamper:1 3);
            let now = Unix.gettimeofday () in
            let body =
              `Assoc
                [
                  ("framework", `String "soc2");
                  ("since", `String (C.Api.iso8601 (now -. 3600.)));
                  ("until", `String (C.Api.iso8601 (now +. 60.)));
                ]
            in
            let* res = post r "/api/v1/evidence/packs" body in
            check_status "create" 202 res;
            Alcotest.(check string) "id" "pack_1" (str (member "id" (snd res)));
            Alcotest.(check string) "building" "building" (str (member "state" (snd res)));
            let* pack = wait_ready r "pack_1" 100 in
            Alcotest.(check bool) "records" true (member "records" pack = `Int 6);
            Alcotest.(check bool)
              "chains" true
              (member "chains.verified" pack = `Int 1
              && member "chains.total" pack = `Int 2);
            let gaps = list (member "gaps" pack) in
            Alcotest.(check (list string))
              "gaps"
              [ "billing-reconciler"; "s3://acme-audit/haltsql/" ]
              (List.map (fun g -> str (member "name" g)) gaps);
            Alcotest.(check string)
              "built_by" "tester@acme.test"
              (str (member "built_by" pack));
            (* download and extract *)
            let* resp, tgz = get_raw r "/api/v1/evidence/packs/pack_1/download" in
            Alcotest.(check int)
              "download 200" 200
              (Cohttp.Code.code_of_status (Cohttp.Response.status resp));
            Alcotest.(check (option string))
              "content-type" (Some "application/gzip")
              (Cohttp.Header.get (Cohttp.Response.headers resp) "content-type");
            let dir = temp_dir "pack-extract" in
            let file = Filename.concat dir "pack.tar.gz" in
            write_file file tgz;
            let rc =
              Sys.command
                (Printf.sprintf "tar -xzf %s -C %s" (Filename.quote file)
                   (Filename.quote dir))
            in
            Alcotest.(check int) "tar -xzf" 0 rc;
            let root = Filename.concat dir "pack_1" in
            let manifest_s = read_file (Filename.concat root "manifest.json") in
            Alcotest.(check string)
              "manifest sha256 recorded"
              (Haltsql.sha256_hex manifest_s)
              (str (member "manifest_sha256" pack));
            let manifest = Yojson.Safe.from_string manifest_s in
            let files = list (member "files" manifest) in
            let paths = List.map (fun f -> str (member "path" f)) files in
            List.iter
              (fun p -> Alcotest.(check bool) ("has " ^ p) true (List.mem p paths))
              [
                "README.md";
                "records/haltsql-1.jsonl";
                "records/haltsql-2.jsonl";
                "chains.json";
                "policies.json";
                "activity.jsonl";
                "exceptions.json";
                "controls.json";
              ];
            List.iter
              (fun f ->
                let p = str (member "path" f) in
                let contents = read_file (Filename.concat root p) in
                Alcotest.(check string)
                  ("sha256 " ^ p)
                  (str (member "sha256" f))
                  (Haltsql.sha256_hex contents))
              files;
            Alcotest.(check bool)
              "manifest record count" true
              (member "records.total" manifest = `Int 6);
            Alcotest.(check string)
              "builder role" "audit"
              (str (member "builder.role" manifest));
            let lines =
              read_file (Filename.concat root "records/haltsql-1.jsonl")
              |> String.split_on_char '\n'
              |> List.filter (( <> ) "")
            in
            Alcotest.(check int) "raw lines" 3 (List.length lines);
            (* The extracted lines verify with the same chain code. *)
            Alcotest.(check bool)
              "extracted chain verifies" true
              (Haltsql_cloud.Audit_chain.verify_lines lines = Ok 3);
            let chains =
              Yojson.Safe.from_string (read_file (Filename.concat root "chains.json"))
            in
            let state v =
              List.find
                (fun c -> member "verifier" c = `String v)
                (list (member "chains" chains))
            in
            Alcotest.(check string)
              "intact" "intact"
              (str (member "state" (state "haltsql-1")));
            Alcotest.(check string)
              "broken" "broken"
              (str (member "state" (state "haltsql-2")));
            Alcotest.(check string)
              "break at tampered record" "b-1"
              (str (member "first_break.request_id" (state "haltsql-2")));
            let readme = read_file (Filename.concat root "README.md") in
            let contains sub =
              let n = String.length sub in
              let rec has i =
                i + n <= String.length readme
                && (String.sub readme i n = sub || has (i + 1))
              in
              has 0
            in
            Alcotest.(check bool) "readme disclaimer" true (contains "not certified");
            Alcotest.(check bool) "readme gap" true (contains "billing-reconciler");
            let policies =
              Yojson.Safe.from_string (read_file (Filename.concat root "policies.json"))
            in
            Alcotest.(check bool)
              "policy seen" true
              (List.exists
                 (fun p -> member "version" p = `String "sha256:abc")
                 (list (member "seen_in_records" policies)));
            Alcotest.(check bool)
              "policy loaded" true
              (List.exists
                 (fun p -> member "name" p = `String "support")
                 (list (member "loaded" policies)));
            let activity = read_file (Filename.concat root "activity.jsonl") in
            Alcotest.(check bool)
              "activity has evidence.build" true
              (let sub = "evidence.build" in
               let n = String.length sub in
               let rec has i =
                 i + n <= String.length activity
                 && (String.sub activity i n = sub || has (i + 1))
               in
               has 0);
            let exc =
              Yojson.Safe.from_string (read_file (Filename.concat root "exceptions.json"))
            in
            Alcotest.(check int)
              "exceptions" 1
              (List.length (list (member "exceptions" exc)));
            let ctl =
              Yojson.Safe.from_string (read_file (Filename.concat root "controls.json"))
            in
            Alcotest.(check string)
              "controls framework" "soc2"
              (str (member "framework" ctl));
            let* res = get r "/api/v1/activity?action=evidence.download" in
            Alcotest.(check int)
              "download logged" 1
              (List.length (list (member "entries" (snd res))));
            Lwt.return_unit) );
    ( "pack validation and missing packs",
      `Quick,
      fun () ->
        with_console ~background:false (config ~role:"analyst" ()) (fun r ->
            let* res =
              post r "/api/v1/evidence/packs"
                (`Assoc
                   [
                     ("framework", `String "pci");
                     ("since", `String "2026-01-01T00:00:00Z");
                   ])
            in
            check_status "bad framework" 400 res;
            let* res =
              post r "/api/v1/evidence/packs" (`Assoc [ ("framework", `String "gdpr") ])
            in
            check_status "since required" 400 res;
            let* res =
              post r "/api/v1/evidence/packs"
                (`Assoc
                   [
                     ("framework", `String "gdpr");
                     ("since", `String "2026-02-01T00:00:00Z");
                     ("until", `String "2026-01-01T00:00:00Z");
                   ])
            in
            check_status "since after until" 400 res;
            let* res = get r "/api/v1/evidence/packs/pack_9/download" in
            check_status "unknown pack" 404 res;
            (* an empty period still builds, with no records *)
            let* res =
              post r "/api/v1/evidence/packs"
                (`Assoc
                   [
                     ("framework", `String "hipaa");
                     ("since", `String "2020-01-01T00:00:00Z");
                     ("until", `String "2020-01-02T00:00:00Z");
                   ])
            in
            check_status "empty period" 202 res;
            let* pack = wait_ready r "pack_1" 100 in
            Alcotest.(check bool) "no records" true (member "records" pack = `Int 0);
            Lwt.return_unit) );
    ( "dev cannot build, list or download packs",
      `Quick,
      fun () ->
        with_console ~background:false (config ~role:"dev" ()) (fun r ->
            let* res =
              post r "/api/v1/evidence/packs"
                (`Assoc
                   [
                     ("framework", `String "soc2");
                     ("since", `String "2026-01-01T00:00:00Z");
                   ])
            in
            check_status "create" 403 res;
            Alcotest.(check string)
              "code" "FORBIDDEN"
              (str (member "error.code" (snd res)));
            let* res = get r "/api/v1/evidence/packs" in
            check_status "list" 403 res;
            let* res = get r "/api/v1/evidence/packs/pack_1/download" in
            check_status "download" 403 res;
            Lwt.return_unit) );
    ( "admin cannot build packs",
      `Quick,
      fun () ->
        with_console ~background:false (config ~role:"admin" ()) (fun r ->
            let* res =
              post r "/api/v1/evidence/packs"
                (`Assoc
                   [
                     ("framework", `String "soc2");
                     ("since", `String "2026-01-01T00:00:00Z");
                   ])
            in
            check_status "create" 403 res;
            Lwt.return_unit) );
  ]

(* ---- archive format ---- *)

let pack_format_tests =
  [
    ( "gzip of large data round-trips through gunzip",
      `Quick,
      fun () ->
        let data = String.init 200_000 (fun i -> Char.chr (i mod 251)) in
        let dir = temp_dir "gz" in
        let f = Filename.concat dir "x.gz" in
        write_file f (C.Pack.gzip data);
        Alcotest.(check int)
          "gunzip" 0
          (Sys.command (Printf.sprintf "gunzip -f %s" (Filename.quote f)));
        Alcotest.(check bool)
          "same bytes" true
          (read_file (Filename.concat dir "x") = data) );
  ]

(* ---- integrations ---- *)

let integration_tests =
  [
    ( "live integration states",
      `Quick,
      fun () ->
        let extra =
          [
            ( "auth",
              `Assoc
                [
                  ( "dev",
                    `Assoc
                      [ ("user", `String "tester@acme.test"); ("role", `String "admin") ]
                  );
                  ( "oidc",
                    `List
                      [
                        `Assoc
                          [
                            ("name", `String "okta");
                            ("issuer", `String "https://idp.example.test");
                            ("audience", `String "console");
                            ("jwks_uri", `String "https://idp.example.test/keys");
                          ];
                        `Assoc
                          [
                            ("name", `String "down");
                            ("issuer", `String "https://down.example.test");
                            ("audience", `String "console");
                            ("jwks_uri", `String "https://down.example.test/keys");
                          ];
                      ] );
                ] );
            ( "audit",
              `Assoc
                [
                  ( "sources",
                    `List
                      [
                        `Assoc
                          [
                            ("verifier", `String "haltsql-1");
                            ("s3", `String "s3://acme-audit/haltsql/");
                          ];
                        `Assoc
                          [
                            ("verifier", `String "haltsql-2");
                            ("file", `String "/var/log/ok.jsonl");
                          ];
                      ] );
                ] );
          ]
        in
        let saved = !C.Access.jwks_fetch in
        C.Access.jwks_fetch :=
          Some
            (fun u ->
              if Uri.host u = Some "idp.example.test" then
                Lwt.return (Ok {|{"keys": []}|})
              else Lwt.return (Error "connection refused"));
        Fun.protect
          ~finally:(fun () -> C.Access.jwks_fetch := saved)
          (fun () ->
            with_console ~background:false (config ~extra ()) (fun r ->
                r.ctx.fleet <-
                  Some
                    (`Assoc
                       [
                         ( "bundles",
                           `List
                             [
                               `Assoc
                                 [
                                   ("source", `String "s3://bundles/prod");
                                   ("version", `String "1.4.0");
                                   ("verifiers", `Int 2);
                                   ("in_sync", `Bool false);
                                 ];
                             ] );
                         ( "sinks",
                           `List
                             [
                               `Assoc
                                 [
                                   ("type", `String "kafka");
                                   ( "target",
                                     `String
                                       "https://user:pw@kafka.example.test/topic?key=1" );
                                   ("state", `String "buffering");
                                 ];
                               `Assoc
                                 [
                                   ("type", `String "file");
                                   ("target", `String "/var/log/a");
                                   ("state", `String "healthy");
                                 ];
                             ] );
                       ]);
                r.ctx.ingest_status <-
                  `List
                    [
                      `Assoc
                        [
                          ("source", `String "s3://acme-audit/haltsql/");
                          ("error", `String "AccessDenied");
                        ];
                    ];
                let* res = get r "/api/v1/integrations" in
                check_status "integrations" 200 res;
                let body = Yojson.Safe.to_string (snd res) in
                let items =
                  List.concat_map
                    (fun g -> list (member "items" g))
                    (list (member "groups" (snd res)))
                in
                let state id =
                  match List.find_opt (fun i -> member "id" i = `String id) items with
                  | Some i -> str (member "state" i)
                  | None -> Alcotest.failf "no item %s in %s" id body
                in
                Alcotest.(check string) "okta no keys" "degraded" (state "oidc:okta");
                Alcotest.(check string) "down" "error" (state "oidc:down");
                Alcotest.(check string)
                  "bundle drift" "degraded"
                  (state "bundle:s3://bundles/prod");
                Alcotest.(check string)
                  "s3 source error" "error"
                  (state "audit:s3://acme-audit/haltsql/");
                Alcotest.(check string)
                  "file source ok" "connected"
                  (state "audit:/var/log/ok.jsonl");
                Alcotest.(check string)
                  "kafka buffering" "degraded"
                  (state "sink:kafka:https://kafka.example.test/topic");
                Alcotest.(check string)
                  "file sink" "connected"
                  (state "sink:file:/var/log/a");
                let contains sub =
                  let n = String.length sub in
                  let rec has i =
                    i + n <= String.length body
                    && (String.sub body i n = sub || has (i + 1))
                  in
                  has 0
                in
                Alcotest.(check bool)
                  "no credentials" false
                  (contains "pw@" || contains "key=1");
                Lwt.return_unit)) );
  ]

let () =
  Random.self_init ();
  Alcotest.run "console-comply"
    [
      ("data", data_tests);
      ("live catalogs", live_tests);
      ("controls", controls_tests);
      ("packs", pack_tests);
      ("archive", pack_format_tests);
      ("integrations", integration_tests);
    ]
