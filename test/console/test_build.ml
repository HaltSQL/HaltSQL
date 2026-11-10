(* console/05-build: policy loading, shadow reports and suggestions, pull requests against a
   fake GitHub, the Playground (with a fake OPA) and the agents list. *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console

let write_file path s = Out_channel.with_open_bin path (fun oc -> output_string oc s)

let str j =
  match j with
  | `String s -> s
  | _ -> Alcotest.failf "not a string: %s" (Yojson.Safe.to_string j)

let int j =
  match j with
  | `Int n -> n
  | _ -> Alcotest.failf "not an int: %s" (Yojson.Safe.to_string j)

let list j =
  match j with
  | `List l -> l
  | _ -> Alcotest.failf "not a list: %s" (Yojson.Safe.to_string j)

let names j = List.map (fun p -> str (member "name" p)) (list j)

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

(* ---- policies ---- *)

let policy_yaml ?(mode = "enforce") ?(columns = "[id, tenant_id, status]")
    ?(tenancy = true) ?owner name =
  String.concat "\n"
    ([ "apiVersion: haltsql.dev/v1"; "kind: Policy"; "metadata:"; "  name: " ^ name ]
    @ (match owner with Some o -> [ "  owner: " ^ o ] | None -> [])
    @ [
        "dialect: postgres-17";
        "search_path: [app]";
        "statements: { allow: [select] }";
        "require_limit: { max: 100 }";
      ]
    @ (if tenancy then
         [ "tenancy: { mode: bound, keys: { tenant: \"${ctx.tenant_id}\" } }" ]
       else [])
    @ [ "tables:"; "  app.orders:"; "    columns: " ^ columns ]
    @ (if tenancy then [ "    tenant_column: tenant_id" ] else [])
    @ [ "mode: " ^ mode; "" ])

let analytics = policy_yaml ~owner:"data-team" "analytics"

let analytics_v2 =
  policy_yaml ~mode:"shadow" ~columns:"[id, tenant_id, status, region]" "analytics-v2"

let analytics_open = policy_yaml ~mode:"shadow" ~tenancy:false "open-analytics"

let policy_dir files =
  let d = temp_dir "console-policies" in
  List.iter (fun (n, s) -> write_file (Filename.concat d n) s) files;
  d

let with_policies ?(role = "admin") ?(extra = []) ?(files = []) f =
  let dir =
    policy_dir
      ([
         ("analytics.yaml", analytics);
         ("analytics-v2.yaml", analytics_v2);
         ("open-analytics.yaml", analytics_open);
       ]
      @ files)
  in
  let cfg =
    config ~role
      ~extra:(("policies", `Assoc [ ("files", `List [ `String dir ]) ]) :: extra)
      ()
  in
  with_console ~background:false cfg (fun r ->
      let* res = C.Policies.reload r.ctx in
      (match res with
      | Ok () -> ()
      | Error e -> Alcotest.failf "policies did not load: %s" (String.concat "; " e));
      f r dir)

let sql_region = "SELECT region FROM orders WHERE tenant_id = $1 LIMIT 10"
let sql_no_tenant = "SELECT id FROM orders LIMIT 10"
let sql_ok = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"
let sql_email = "SELECT email FROM orders WHERE tenant_id = $1 LIMIT 10"

let report_records () =
  List.init 3 (fun i ->
      server_record ~request_id:(Printf.sprintf "col-%d" i) ~allowed:false
        ~codes:[ "E_COLUMN_DENIED" ] ~fingerprint:"fp-region" ~sql:sql_region ())
  @ List.init 2 (fun i ->
      server_record ~request_id:(Printf.sprintf "ten-%d" i) ~allowed:false
        ~codes:[ "E_TENANT_MISSING" ] ~fingerprint:"fp-tenant" ~sql:sql_no_tenant ())
  @ [
      server_record ~request_id:"ok-1" ~sql:sql_ok ~fingerprint:"fp-ok" ();
      server_record ~request_id:"pii-1" ~allowed:false ~codes:[ "E_COLUMN_DENIED" ]
        ~fingerprint:"fp-email" ~sql:sql_email ();
    ]

let loading_tests =
  [
    ( "files and directories",
      `Quick,
      fun () ->
        with_policies
          ~files:
            [
              ( "suite.yaml",
                "apiVersion: haltsql.dev/v1\n\
                 kind: TestSuite\n\
                 metadata: { name: s }\n\
                 policy: analytics.yaml\n\
                 cases: []\n" );
              ("notes.txt", "not a policy");
            ]
          (fun r dir ->
            let* code, j = get r "/api/v1/policies" in
            check_status "list" 200 (code, j);
            let ps = member "policies" j in
            Alcotest.(check (list string))
              "names"
              [ "analytics-v2"; "analytics"; "open-analytics" ]
              (names ps);
            let a =
              List.find (fun p -> member "name" p = `String "analytics") (list ps)
            in
            let expected =
              match
                Haltsql.Policy_load.of_file (Filename.concat dir "analytics.yaml")
              with
              | Ok p -> p.version
              | Error _ -> Alcotest.fail "fixture"
            in
            Alcotest.(check string) "version" expected (str (member "version" a));
            Alcotest.(check string) "mode" "enforce" (str (member "mode" a));
            Alcotest.(check string) "origin" "file" (str (member "origin" a));
            Alcotest.(check string)
              "file basename" "analytics.yaml"
              (str (member "file" a));
            Alcotest.(check string) "owner" "data-team" (str (member "owner" a));
            Alcotest.(check (list string))
              "shadow" [ "analytics-v2" ]
              (List.map str (list (member "shadow" a)));
            Alcotest.(check bool)
              "no directory in listing" false
              (contains (Yojson.Safe.to_string j) dir);
            let* code, d = get r "/api/v1/policies/analytics" in
            check_status "detail" 200 (code, d);
            Alcotest.(check string) "yaml" analytics (str (member "yaml" d));
            Alcotest.(check int) "tables" 1 (List.length (list (member "tables" d)));
            let* code, _ = get r "/api/v1/policies/nope" in
            Alcotest.(check int) "unknown" 404 code;
            Lwt.return_unit) );
    ( "a failed reload keeps the last good set",
      `Quick,
      fun () ->
        with_policies (fun r dir ->
            write_file (Filename.concat dir "analytics.yaml") "kind: Policy\nnot: valid\n";
            let* res = C.Policies.reload r.ctx in
            Alcotest.(check bool) "reload failed" true (Result.is_error res);
            Alcotest.(check int) "still loaded" 3 (List.length r.ctx.policies);
            let* _, j = get r "/api/v1/policies" in
            Alcotest.(check bool) "errors" true (list (member "errors" j) <> []);
            Alcotest.(check bool)
              "errors carry no directories" false
              (contains (Yojson.Safe.to_string (member "errors" j)) dir);
            Lwt.return_unit) );
    ( "server config: path, inline and bundle policies",
      `Quick,
      fun () ->
        let d = policy_dir [ ("analytics.yaml", analytics) ] in
        let key = Haltsql_bundle.Key.generate () in
        let pub =
          Haltsql_bundle.Key.public_to_base64 (Haltsql_bundle.Key.public_of_secret key)
        in
        let bundled =
          match
            Haltsql.Policy_load.of_string Haltsql.Docload.Yaml (policy_yaml "reporting")
          with
          | Ok p -> p
          | Error _ -> Alcotest.fail "bundle policy"
        in
        let bytes =
          match
            Haltsql_bundle.build
              {
                name = "prod";
                version = "1.0.0";
                created_by = None;
                source = { url = None; commit = None };
              }
              ~policies:[ bundled ] ~catalogs:[]
          with
          | Ok b -> b
          | Error e -> Alcotest.failf "bundle: %s" (Haltsql_bundle.error_to_string e)
        in
        let bundle = Filename.concat d "prod.haltsqlbundle" in
        write_file bundle bytes;
        write_file (bundle ^ ".sig")
          (Haltsql_bundle.signatures_to_string [ Haltsql_bundle.sign key bytes ]);
        let server_cfg = Filename.concat d "server.yaml" in
        write_file server_cfg
          (String.concat "\n"
             [
               "apiVersion: haltsql.dev/v1";
               "kind: Config";
               "policies:";
               "  - path: ./analytics.yaml";
               "  - inline:";
               "      metadata: { name: inline-one }";
               "      search_path: [app]";
               "      statements: { allow: [select] }";
               "      tables: { app.orders: { columns: [id] } }";
               Printf.sprintf
                 "  - { bundle: ./prod.haltsqlbundle, public_keys: [%s], name_prefix: b- \
                  }"
                 pub;
               "";
             ]);
        let cfg =
          config
            ~extra:[ ("policies", `Assoc [ ("server_config", `String server_cfg) ]) ]
            ()
        in
        with_console ~background:false cfg (fun r ->
            let* res = C.Policies.reload r.ctx in
            (match res with
            | Ok () -> ()
            | Error e -> Alcotest.failf "load: %s" (String.concat "; " e));
            let* _, j = get r "/api/v1/policies" in
            let ps = list (member "policies" j) in
            let origin n =
              let p = List.find (fun p -> member "name" p = `String n) ps in
              (str (member "origin" p), member "file" p, member "bundle" p)
            in
            Alcotest.(check (list string))
              "names"
              [ "analytics"; "inline-one"; "b-reporting" ]
              (List.map (fun p -> str (member "name" p)) ps);
            let o, f, _ = origin "analytics" in
            Alcotest.(check string) "path origin" "config" o;
            Alcotest.(check string) "path file" "analytics.yaml" (str f);
            let o, f, _ = origin "inline-one" in
            Alcotest.(check string) "inline origin" "config" o;
            Alcotest.(check bool) "inline has no file" true (f = `Null);
            let o, _, b = origin "b-reporting" in
            Alcotest.(check string) "bundle origin" "bundle" o;
            Alcotest.(check string) "bundle name" "prod.haltsqlbundle" (str b);
            let* _, d = get r "/api/v1/policies/inline-one" in
            Alcotest.(check bool)
              "inline yaml rendered" true
              (contains (str (member "yaml" d)) "inline-one");
            Lwt.return_unit) );
    ( "fleet verifiers and fleet-only policies",
      `Quick,
      fun () ->
        with_policies (fun r _ ->
            r.ctx.fleet <-
              Some
                (Yojson.Safe.from_string
                   {|{"verifiers":[{"name":"haltsql-1","kind":"server","policies":[{"name":"analytics","version":"sha256:x","mode":"enforce","origin":"config"},{"name":"remote-only","version":"sha256:y","mode":"enforce","origin":"bundle_source"}]}]}|});
            let* _, j = get r "/api/v1/policies" in
            let ps = list (member "policies" j) in
            let a = List.find (fun p -> member "name" p = `String "analytics") ps in
            Alcotest.(check (list string))
              "verifiers" [ "haltsql-1" ]
              (List.map str (list (member "verifiers" a)));
            let ro = List.find (fun p -> member "name" p = `String "remote-only") ps in
            Alcotest.(check bool) "not loaded" true (member "loaded" ro = `Bool false);
            let* code, _ = get r "/api/v1/policies/remote-only" in
            Alcotest.(check int) "fleet-only detail" 200 code;
            Lwt.return_unit) );
  ]

(* ---- reports ---- *)

let report_tests =
  [
    ( "suggestions, never and comparison",
      `Quick,
      fun () ->
        with_policies (fun r _ ->
            load_records r (report_records ());
            let* code, j = get r "/api/v1/policies/analytics/report" in
            check_status "report" 200 (code, j);
            Alcotest.(check string) "compare" "analytics-v2" (str (member "compare" j));
            let sg = list (member "suggestions" j) in
            Alcotest.(check (list string))
              "suggestion ids"
              [ "analytics/column/app.orders.region" ]
              (List.map (fun s -> str (member "id" s)) sg);
            let s = List.hd sg in
            Alcotest.(check string) "kind" "column" (str (member "kind" s));
            Alcotest.(check int) "evidence" 3 (int (member "evidence.records" s));
            Alcotest.(check int)
              "distinct queries" 1
              (int (member "evidence.distinct_queries" s));
            let never = list (member "never" j) in
            let cat c = List.filter (fun n -> member "category" n = `String c) never in
            (match cat "tenancy" with
            | [ t ] ->
                Alcotest.(check (list string))
                  "codes" [ "E_TENANT_MISSING" ]
                  (List.map str (list (member "codes" t)));
                Alcotest.(check int) "records" 2 (int (member "records" t))
            | l -> Alcotest.failf "expected one tenancy row, got %d" (List.length l));
            (match cat "sensitive_column" with
            | [ p ] ->
                Alcotest.(check string)
                  "pii target" "app.orders.email"
                  (str (member "target" p))
            | l ->
                Alcotest.failf "expected one sensitive_column row, got %d" (List.length l));
            Alcotest.(check int)
              "denied_now_allowed" 3
              (int (member "comparison.denied_now_allowed" j));
            Alcotest.(check int)
              "allowed_now_denied" 0
              (int (member "comparison.allowed_now_denied" j));
            Alcotest.(check int)
              "tenancy_relaxed" 0
              (int (member "comparison.tenancy_relaxed" j));
            Alcotest.(check bool) "no PR" true (member "pull_request" j = `Null);
            Lwt.return_unit) );
    ( "tenancy is never suggested; relaxation is counted",
      `Quick,
      fun () ->
        with_policies (fun r _ ->
            load_records r
              (List.init 4 (fun i ->
                   server_record ~request_id:(Printf.sprintf "t-%d" i) ~allowed:false
                     ~codes:[ "E_TENANT_MISSING" ] ~sql:sql_no_tenant ()));
            let* code, j =
              get r "/api/v1/policies/analytics/report?compare=open-analytics"
            in
            check_status "report" 200 (code, j);
            Alcotest.(check int)
              "no suggestions" 0
              (List.length (list (member "suggestions" j)));
            Alcotest.(check int)
              "tenancy_relaxed" 4
              (int (member "comparison.tenancy_relaxed" j));
            Alcotest.(check int)
              "denied_now_allowed" 4
              (int (member "comparison.denied_now_allowed" j));
            let* code, _ = get r "/api/v1/policies/analytics/report?compare=missing" in
            Alcotest.(check int) "unknown compare" 404 code;
            let* code, _ = get r "/api/v1/policies/nope/report" in
            Alcotest.(check int) "unknown policy" 404 code;
            let* code, _ = get r "/api/v1/policies/analytics/report?since=garbage" in
            Alcotest.(check int) "bad since" 400 code;
            Lwt.return_unit) );
  ]

(* ---- in-process HTTP fakes ---- *)

let serve handler =
  let* addrs =
    Lwt_unix.getaddrinfo "127.0.0.1" "0" [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
  in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  let* () = Lwt_unix.bind fd (List.hd addrs).Unix.ai_addr in
  Lwt_unix.listen fd 16;
  let port = match Lwt_unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> 0 in
  let stop_p, stop = Lwt.wait () in
  let callback _ req body =
    let* b = Cohttp_lwt.Body.to_string body in
    let* status, out = handler req b in
    Cohttp_lwt_unix.Server.respond_string
      ~status:(Cohttp.Code.status_of_code status)
      ~body:out ()
  in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~stop:stop_p
        ~mode:(`TCP (`Socket fd))
        (Cohttp_lwt_unix.Server.make ~callback ()));
  Lwt.return (port, fun () -> Lwt.wakeup_later stop ())

(* A fake GitHub repository acme/policies: refs, commits with whole-file trees, raw
   contents, pull requests, check runs and reviews. *)
module Fake_github = struct
  type t = {
    mutable refs : (string * string) list;
    commit_tree : (string, string) Hashtbl.t;
    tree_files : (string, (string * string) list) Hashtbl.t;
    mutable n : int;
    mutable prs : (int * (string * string * string)) list;
        (** number -> head, title, body *)
    mutable reviews : Yojson.Safe.t list;
    mutable check_runs : Yojson.Safe.t list;
    mutable calls : string list;
    mutable bad_auth : int;
  }

  let fresh t prefix =
    t.n <- t.n + 1;
    Printf.sprintf "%s%04d" prefix t.n

  let create files =
    let t =
      {
        refs = [];
        commit_tree = Hashtbl.create 8;
        tree_files = Hashtbl.create 8;
        n = 0;
        prs = [];
        reviews = [];
        check_runs = [];
        calls = [];
        bad_auth = 0;
      }
    in
    let tree = fresh t "t" and commit = fresh t "c" in
    Hashtbl.replace t.tree_files tree files;
    Hashtbl.replace t.commit_tree commit tree;
    t.refs <- [ ("main", commit) ];
    t

  let files_at t r =
    let commit = Option.value (List.assoc_opt r t.refs) ~default:r in
    match Hashtbl.find_opt t.commit_tree commit with
    | Some tree -> Hashtbl.find_opt t.tree_files tree
    | None -> None

  let json s j = Lwt.return (s, Yojson.Safe.to_string j)
  let jstr k j = match member k j with `String s -> s | _ -> ""

  let pr_json t n =
    let head, title, _ = List.assoc n t.prs in
    `Assoc
      [
        ("number", `Int n);
        ("state", `String "open");
        ("merged", `Bool false);
        ("title", `String title);
        ( "html_url",
          `String (Printf.sprintf "https://github.test/acme/policies/pull/%d" n) );
        ( "head",
          `Assoc [ ("ref", `String head); ("sha", `String (List.assoc head t.refs)) ] );
      ]

  let handler t (req : Cohttp.Request.t) body =
    let uri = Cohttp.Request.uri req in
    let path = Uri.pct_decode (Uri.path uri) in
    let meth = Cohttp.Code.string_of_method (Cohttp.Request.meth req) in
    t.calls <- t.calls @ [ meth ^ " " ^ path ];
    if
      Cohttp.Header.get (Cohttp.Request.headers req) "authorization"
      <> Some "Bearer ghp_test"
    then t.bad_auth <- t.bad_auth + 1;
    let b = try Yojson.Safe.from_string body with _ -> `Null in
    let prefix = "/repos/acme/policies" in
    let rest =
      if String.starts_with ~prefix path then
        String.sub path (String.length prefix) (String.length path - String.length prefix)
      else path
    in
    let after p =
      String.sub rest (String.length p) (String.length rest - String.length p)
    in
    let starts p = String.starts_with ~prefix:p rest in
    match (meth, rest) with
    | "GET", _ when starts "/git/ref/heads/" -> (
        match List.assoc_opt (after "/git/ref/heads/") t.refs with
        | Some sha -> json 200 (`Assoc [ ("object", `Assoc [ ("sha", `String sha) ]) ])
        | None -> json 404 (`Assoc [ ("message", `String "Not Found") ]))
    | "POST", "/git/refs" ->
        let r = jstr "ref" b in
        let br = String.sub r 11 (String.length r - 11) in
        if List.mem_assoc br t.refs then
          json 422 (`Assoc [ ("message", `String "exists") ])
        else (
          t.refs <- t.refs @ [ (br, jstr "sha" b) ];
          json 201 (`Assoc [ ("ref", `String r) ]))
    | "PATCH", _ when starts "/git/refs/heads/" ->
        let br = after "/git/refs/heads/" in
        t.refs <- (br, jstr "sha" b) :: List.remove_assoc br t.refs;
        json 200 (`Assoc [])
    | "GET", _ when starts "/git/commits/" ->
        let sha = after "/git/commits/" in
        json 200
          (`Assoc
             [
               ("sha", `String sha);
               ("tree", `Assoc [ ("sha", `String (Hashtbl.find t.commit_tree sha)) ]);
             ])
    | "POST", "/git/trees" ->
        let base =
          Option.value (Hashtbl.find_opt t.tree_files (jstr "base_tree" b)) ~default:[]
        in
        let files =
          List.fold_left
            (fun acc e ->
              (jstr "path" e, jstr "content" e) :: List.remove_assoc (jstr "path" e) acc)
            base
            (match member "tree" b with `List l -> l | _ -> [])
        in
        let sha = fresh t "t" in
        Hashtbl.replace t.tree_files sha files;
        json 201 (`Assoc [ ("sha", `String sha) ])
    | "POST", "/git/commits" ->
        let sha = fresh t "c" in
        Hashtbl.replace t.commit_tree sha (jstr "tree" b);
        json 201 (`Assoc [ ("sha", `String sha) ])
    | "GET", _ when starts "/contents/" -> (
        let file = after "/contents/" in
        let r = Option.value (Uri.get_query_param uri "ref") ~default:"main" in
        match Option.bind (files_at t r) (List.assoc_opt file) with
        | Some text -> Lwt.return (200, text)
        | None -> json 404 (`Assoc [ ("message", `String "Not Found") ]))
    | "POST", "/pulls" ->
        let n = List.length t.prs + 1 in
        t.prs <- t.prs @ [ (n, (jstr "head" b, jstr "title" b, jstr "body" b)) ];
        json 201 (pr_json t n)
    | "PATCH", _ when starts "/pulls/" ->
        let n = int_of_string (after "/pulls/") in
        let head, _, _ = List.assoc n t.prs in
        t.prs <- (n, (head, jstr "title" b, jstr "body" b)) :: List.remove_assoc n t.prs;
        json 200 (pr_json t n)
    | "GET", _ when starts "/pulls/" && String.ends_with ~suffix:"/reviews" rest ->
        json 200 (`List t.reviews)
    | "GET", _ when starts "/pulls/" -> (
        match int_of_string_opt (after "/pulls/") with
        | Some n when List.mem_assoc n t.prs -> json 200 (pr_json t n)
        | _ -> json 404 (`Assoc [ ("message", `String "Not Found") ]))
    | "GET", _ when starts "/commits/" ->
        json 200 (`Assoc [ ("check_runs", `List t.check_runs) ])
    | _ -> json 404 (`Assoc [ ("message", `String ("no fake for " ^ meth ^ " " ^ rest)) ])
end

let github_cfg port =
  ( "integrations",
    `Assoc
      [
        ( "github",
          `Assoc
            [
              ("repo", `String "acme/policies");
              ("token", `String "ghp_test");
              ("api", `String (Printf.sprintf "http://127.0.0.1:%d" port));
              ("required_approvals", `Int 2);
            ] );
      ] )

let existing_suite =
  "# hand-written suite\n\
   apiVersion: haltsql.dev/v1\n\
   kind: TestSuite\n\
   metadata: { name: analytics }\n\
   policy: ../policies/analytics.yaml\n\
   cases:\n\
  \  - name: ok\n\
  \    sql: SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5\n\
  \    context: { tenant_id: acme }\n\
  \    expect: allow\n"

let new_test =
  "- name: region needs review\n\
  \  sql: SELECT region FROM orders WHERE tenant_id = $1 LIMIT 10\n\
  \  context: { tenant_id: acme }\n\
  \  expect: allow\n"

let pr_tests =
  [
    ( "open, update, reviews and checks",
      `Quick,
      fun () ->
        let gh =
          Fake_github.create
            [
              ("policies/analytics.yaml", analytics);
              ("tests/analytics.yaml", existing_suite);
            ]
        in
        Lwt_main.run
          (let* port, stop_gh = serve (Fake_github.handler gh) in
           Lwt.finalize
             (fun () ->
               let dir =
                 policy_dir
                   [ ("analytics.yaml", analytics); ("analytics-v2.yaml", analytics_v2) ]
               in
               let cfg =
                 config
                   ~extra:
                     [
                       ("policies", `Assoc [ ("files", `List [ `String dir ]) ]);
                       github_cfg port;
                     ]
                   ()
               in
               let* r = start ~background:false cfg in
               Lwt.finalize
                 (fun () ->
                   let* _ = C.Policies.reload r.ctx in
                   load_records r (report_records ());
                   let id = "analytics/column/app.orders.region" in
                   let* code, j =
                     post r "/api/v1/policies/analytics/pull-request"
                       (`Assoc
                          [
                            ("suggestions", `List [ `String id ]);
                            ("tests", `List [ `String new_test ]);
                          ])
                   in
                   check_status "create" 201 (code, j);
                   Alcotest.(check int) "number" 1 (int (member "number" j));
                   Alcotest.(check string)
                     "branch" "haltsql-console/analytics"
                     (str (member "branch" j));
                   Alcotest.(check bool)
                     "no token in response" false
                     (contains (Yojson.Safe.to_string j) "ghp_test");
                   let files =
                     Option.get (Fake_github.files_at gh "haltsql-console/analytics")
                   in
                   let policy = List.assoc "policies/analytics.yaml" files in
                   Alcotest.(check bool) "region added" true (contains policy "region");
                   (match Haltsql.Policy_load.of_string Haltsql.Docload.Yaml policy with
                   | Ok p -> Alcotest.(check string) "still analytics" "analytics" p.name
                   | Error _ -> Alcotest.fail "patched policy does not load");
                   let suite = List.assoc "tests/analytics.yaml" files in
                   Alcotest.(check bool)
                     "comment kept" true
                     (contains suite "# hand-written suite");
                   (match Haltsql.Docload.of_string Haltsql.Docload.Yaml suite with
                   | Ok d ->
                       Alcotest.(check int)
                         "cases" 2
                         (List.length (list (member "cases" d)))
                   | Error _ -> Alcotest.fail "suite does not parse");
                   Alcotest.(check int)
                     "main untouched" 2
                     (List.length (Option.get (Fake_github.files_at gh "main")));
                   (match C.Store.get r.ctx.store "pull_requests" "analytics" with
                   | Some d -> Alcotest.(check int) "stored" 1 (int (member "number" d))
                   | None -> Alcotest.fail "PR not stored");
                   (* second proposal updates the same PR *)
                   let head1 = List.assoc "haltsql-console/analytics" gh.refs in
                   let* code, j2 =
                     post r "/api/v1/policies/analytics/pull-request"
                       (`Assoc
                          [
                            ("tests", `List [ `String new_test ]);
                            ("title", `String "More tests");
                          ])
                   in
                   check_status "update" 200 (code, j2);
                   Alcotest.(check int) "same PR" 1 (int (member "number" j2));
                   Alcotest.(check int) "one PR" 1 (List.length gh.prs);
                   let head2 = List.assoc "haltsql-console/analytics" gh.refs in
                   Alcotest.(check bool) "branch advanced" true (head1 <> head2);
                   let _, title, _ = List.assoc 1 gh.prs in
                   Alcotest.(check string) "title updated" "More tests" title;
                   let suite =
                     List.assoc "tests/analytics.yaml"
                       (Option.get (Fake_github.files_at gh "haltsql-console/analytics"))
                   in
                   (match Haltsql.Docload.of_string Haltsql.Docload.Yaml suite with
                   | Ok d ->
                       Alcotest.(check int)
                         "cases" 3
                         (List.length (list (member "cases" d)))
                   | Error _ -> Alcotest.fail "suite does not parse");
                   (* reviews and checks *)
                   let review who st =
                     `Assoc
                       [
                         ("user", `Assoc [ ("login", `String who) ]);
                         ("state", `String st);
                         ("submitted_at", `String "2026-11-08T10:00:00Z");
                       ]
                   in
                   gh.reviews <-
                     [
                       review "alice" "APPROVED";
                       review "bob" "CHANGES_REQUESTED";
                       review "bob" "APPROVED";
                       review "carol" "APPROVED";
                       review "carol" "CHANGES_REQUESTED";
                       review "dave" "COMMENTED";
                     ];
                   gh.check_runs <-
                     [
                       `Assoc
                         [
                           ("name", `String "haltsql test");
                           ("status", `String "completed");
                           ("conclusion", `String "success");
                           ("output", `Assoc [ ("title", `String "3 cases passed") ]);
                         ];
                     ];
                   let* code, rep = get r "/api/v1/policies/analytics/report" in
                   check_status "report" 200 (code, rep);
                   let pr = member "pull_request" rep in
                   Alcotest.(check string) "state" "open" (str (member "state" pr));
                   Alcotest.(check (list string))
                     "approvals" [ "alice"; "bob" ]
                     (List.map
                        (fun a -> str (member "by" a))
                        (list (member "approvals" pr)));
                   Alcotest.(check int)
                     "required" 2
                     (int (member "required_approvals" pr));
                   Alcotest.(check string)
                     "check" "success"
                     (str (member "state" (List.hd (list (member "checks" pr)))));
                   let s = List.hd (list (member "suggestions" rep)) in
                   Alcotest.(check int)
                     "suggestion under review" 1
                     (int (member "review.pull_request" s));
                   Alcotest.(check int) "token always sent" 0 gh.bad_auth;
                   let* _, act = get r "/api/v1/activity?action=policy.pull_request" in
                   Alcotest.(check int)
                     "logged" 2
                     (List.length (list (member "entries" act)));
                   let* code, _ =
                     post r "/api/v1/policies/analytics/pull-request"
                       (`Assoc
                          [
                            ( "suggestions",
                              `List [ `String "analytics/column/app.orders.nope" ] );
                          ])
                   in
                   Alcotest.(check int) "unknown suggestion" 400 code;
                   let* code, _ =
                     post r "/api/v1/policies/analytics/pull-request" (`Assoc [])
                   in
                   Alcotest.(check int) "nothing to propose" 400 code;
                   let* code, _ =
                     post r "/api/v1/policies/analytics/pull-request"
                       (`Assoc
                          [ ("tests", `List [ `String "- name: x\n  expect: maybe\n" ]) ])
                   in
                   Alcotest.(check int) "invalid test" 400 code;
                   Lwt.return_unit)
                 (fun () ->
                   stop r;
                   Lwt.return_unit))
             (fun () ->
               stop_gh ();
               Lwt.return_unit)) );
    ( "new suite file when none exists",
      `Quick,
      fun () ->
        let gh = Fake_github.create [ ("policies/analytics.yaml", analytics) ] in
        Lwt_main.run
          (let* port, stop_gh = serve (Fake_github.handler gh) in
           let dir = policy_dir [ ("analytics.yaml", analytics) ] in
           let cfg =
             config
               ~extra:
                 [
                   ("policies", `Assoc [ ("files", `List [ `String dir ]) ]);
                   github_cfg port;
                 ]
               ()
           in
           let* r = start ~background:false cfg in
           let* _ = C.Policies.reload r.ctx in
           let* code, j =
             post r "/api/v1/policies/analytics/pull-request"
               (`Assoc [ ("tests", `List [ `String new_test ]) ])
           in
           stop r;
           stop_gh ();
           check_status "create" 201 (code, j);
           let suite =
             List.assoc "tests/analytics.yaml"
               (Option.get (Fake_github.files_at gh "haltsql-console/analytics"))
           in
           (match Haltsql.Docload.of_string Haltsql.Docload.Yaml suite with
           | Ok d ->
               Alcotest.(check string)
                 "policy path" "../policies/analytics.yaml"
                 (str (member "policy" d));
               Alcotest.(check int) "cases" 1 (List.length (list (member "cases" d)))
           | Error _ -> Alcotest.fail "suite does not parse");
           Lwt.return_unit) );
    ( "not configured and permissions",
      `Quick,
      fun () ->
        with_policies (fun r _ ->
            let* code, j =
              post r "/api/v1/policies/analytics/pull-request"
                (`Assoc [ ("tests", `List [ `String new_test ]) ])
            in
            Alcotest.(check int) "503" 503 code;
            Alcotest.(check string) "code" "NOT_CONFIGURED" (str (member "error.code" j));
            Lwt.return_unit);
        with_policies ~role:"audit" (fun r _ ->
            let* code, _ =
              post r "/api/v1/policies/analytics/pull-request"
                (`Assoc [ ("tests", `List [ `String new_test ]) ])
            in
            Alcotest.(check int) "audit 403" 403 code;
            Lwt.return_unit) );
  ]

(* ---- playground ---- *)

let draft_with_region = policy_yaml ~columns:"[id, tenant_id, status, region]" "analytics"

let check_body ?(extra = []) targets =
  `Assoc
    ([
       ("sql", `String sql_region);
       ("context", `Assoc [ ("tenant_id", `String "acme") ]);
       ("targets", `List targets);
     ]
    @ extra)

let stage_state result name =
  let s =
    List.find (fun s -> member "stage" s = `String name) (list (member "stages" result))
  in
  str (member "state" s)

let playground_tests =
  [
    ( "live denies, draft allows",
      `Quick,
      fun () ->
        with_policies (fun r _ ->
            r.ctx.catalog_columns <-
              Some
                (Yojson.Safe.from_string
                   {|{"columns":[{"column":"app.orders.region","tags":["location"],"sources":["dbt"]}]}|});
            let* code, j =
              post r "/api/v1/playground/check"
                (check_body
                   [
                     `Assoc [ ("policy", `String "analytics") ];
                     `Assoc
                       [
                         ("policy", `String "analytics");
                         ("draft", `String draft_with_region);
                       ];
                   ])
            in
            check_status "check" 200 (code, j);
            let res = list (member "results" j) in
            let live = List.nth res 0 and draft = List.nth res 1 in
            Alcotest.(check string)
              "live label" "analytics (live)"
              (str (member "label" live));
            Alcotest.(check bool) "live denies" false (member "allowed" live = `Bool true);
            Alcotest.(check string) "tables stage" "denied" (stage_state live "tables");
            Alcotest.(check string) "parse stage" "passed" (stage_state live "parse");
            Alcotest.(check string) "where draft" "draft" (str (member "where" draft));
            Alcotest.(check bool) "draft allows" true (member "allowed" draft = `Bool true);
            (* verdict JSON exactly as Verdict.to_json *)
            let p =
              match
                Haltsql.Policy_load.of_string Haltsql.Docload.Yaml draft_with_region
              with
              | Ok p -> p
              | Error _ -> Alcotest.fail "draft"
            in
            let v =
              Haltsql.verify p
                (Haltsql.Context.make [ ("tenant_id", One "acme") ])
                sql_region
            in
            let strip = function
              | `Assoc l -> `Assoc (List.remove_assoc "elapsed_us" l)
              | j -> j
            in
            Alcotest.(check string)
              "verdict"
              (Yojson.Safe.to_string (strip (Haltsql.Verdict.to_json v)))
              (Yojson.Safe.to_string (strip (member "verdict" draft)));
            Alcotest.(check bool)
              "opa not asked" true
              (member "opa.asked" live = `Bool false);
            let col =
              List.find
                (fun c -> member "column" c = `String "app.orders.region")
                (list (member "columns" j))
            in
            Alcotest.(check (list string))
              "tags" [ "location" ]
              (List.map str (list (member "tags" col)));
            Alcotest.(check (list string))
              "allowed_by" [ "analytics-v2" ]
              (List.map str (list (member "allowed_by" col)));
            let tc = str (member "test_case" j) in
            Alcotest.(check bool)
              "test case expects deny" true (contains tc "expect: deny");
            let suite =
              "apiVersion: haltsql.dev/v1\n\
               kind: TestSuite\n\
               metadata: { name: t }\n\
               policy: p.yaml\n\
               cases:\n" ^ tc
            in
            (match Haltsql.Docload.of_string Haltsql.Docload.Yaml suite with
            | Ok d -> (
                match Haltsql.Test_suite.of_json ~base_dir:"/" d with
                | Ok s -> Alcotest.(check int) "one case" 1 (List.length s.cases)
                | Error _ -> Alcotest.fail "test_case is not a valid suite case")
            | Error _ -> Alcotest.fail "test_case is not YAML");
            let* _, act = get r "/api/v1/activity?action=playground.check" in
            let entries = list (member "entries" act) in
            Alcotest.(check int) "logged" 1 (List.length entries);
            let e = Yojson.Safe.to_string (List.hd entries) in
            Alcotest.(check bool)
              "sha logged" true
              (contains e (Haltsql.sha256_hex sql_region));
            Alcotest.(check bool) "sql not logged" false (contains e "SELECT region");
            Lwt.return_unit) );
    ( "invalid draft, unknown policy, audit role",
      `Quick,
      fun () ->
        with_policies (fun r _ ->
            let* code, j =
              post r "/api/v1/playground/check"
                (check_body
                   [ `Assoc [ ("draft", `String "kind: Policy\nmetadata: {}\n") ] ])
            in
            Alcotest.(check int) "invalid draft" 400 code;
            Alcotest.(check bool)
              "errors listed" true
              (list (member "error.errors" j) <> []);
            let* code, _ =
              post r "/api/v1/playground/check"
                (check_body [ `Assoc [ ("policy", `String "nope") ] ])
            in
            Alcotest.(check int) "unknown policy" 404 code;
            let* code, _ =
              post r "/api/v1/playground/check" (`Assoc [ ("sql", `String "SELECT 1") ])
            in
            Alcotest.(check int) "no targets" 400 code;
            Lwt.return_unit);
        with_policies ~role:"audit" (fun r _ ->
            let* code, j =
              post r "/api/v1/playground/check"
                (check_body [ `Assoc [ ("policy", `String "analytics") ] ])
            in
            Alcotest.(check int) "audit 403" 403 code;
            Alcotest.(check string) "code" "FORBIDDEN" (str (member "error.code" j));
            Lwt.return_unit) );
    ( "caller picks enforced and shadow policies",
      `Quick,
      fun () ->
        with_policies
          ~extra:
            [
              ( "agents",
                `List
                  [
                    `Assoc
                      [
                        ("name", `String "bot");
                        ("callers", `List [ `String "token:bot" ]);
                        ("policy", `String "analytics");
                      ];
                  ] );
            ]
          (fun r _ ->
            let* code, j =
              post r "/api/v1/playground/check"
                (`Assoc
                   [
                     ("sql", `String sql_region);
                     ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                     ("caller", `String "bot");
                   ])
            in
            check_status "check" 200 (code, j);
            Alcotest.(check (list string))
              "labels"
              [ "analytics (live)"; "analytics-v2 (shadow)" ]
              (List.map (fun x -> str (member "label" x)) (list (member "results" j)));
            Lwt.return_unit) );
  ]

(* ---- OPA ---- *)

let fake_opa () =
  serve (fun req _body ->
      let path = Uri.path (Cohttp.Request.uri req) in
      if contains path "slow" then
        let* () = Lwt_unix.sleep 1.0 in
        Lwt.return (200, {|{"result": true}|})
      else if contains path "deny" then
        Lwt.return
          (200, {|{"result": {"allow": false, "reasons": ["outside business hours"]}}|})
      else Lwt.return (200, {|{"result": true}|}))

let with_opa decision f =
  Lwt_main.run
    (let* port, stop_opa = fake_opa () in
     let dir = policy_dir [ ("analytics.yaml", analytics) ] in
     let cfg =
       config
         ~extra:
           [
             ("policies", `Assoc [ ("files", `List [ `String dir ]) ]);
             ( "opa",
               `Assoc
                 [
                   ("url", `String (Printf.sprintf "http://127.0.0.1:%d" port));
                   ("decision_path", `String ("haltsql/" ^ decision));
                   ("timeout_ms", `Int 200);
                 ] );
           ]
         ()
     in
     let* r = start ~background:false cfg in
     Lwt.finalize
       (fun () ->
         let* _ = C.Policies.reload r.ctx in
         f r)
       (fun () ->
         stop r;
         stop_opa ();
         Lwt.return_unit))

let opa_check r sql =
  post r "/api/v1/playground/check"
    (`Assoc
       [
         ("sql", `String sql);
         ("context", `Assoc [ ("tenant_id", `String "acme") ]);
         ("targets", `List [ `Assoc [ ("policy", `String "analytics") ] ]);
       ])

let opa_tests =
  [
    ( "allow",
      `Quick,
      fun () ->
        with_opa "allow" (fun r ->
            let* code, j = opa_check r sql_ok in
            check_status "check" 200 (code, j);
            let res = List.hd (list (member "results" j)) in
            Alcotest.(check bool) "asked" true (member "opa.asked" res = `Bool true);
            Alcotest.(check bool) "allowed" true (member "allowed" res = `Bool true);
            Alcotest.(check string) "opa stage" "passed" (stage_state res "opa");
            (* HaltSQL denies: OPA is not asked *)
            let* _, j = opa_check r sql_no_tenant in
            let res = List.hd (list (member "results" j)) in
            Alcotest.(check bool) "not asked" true (member "opa.asked" res = `Bool false);
            Alcotest.(check string) "opa not_run" "not_run" (stage_state res "opa");
            Lwt.return_unit) );
    ( "deny",
      `Quick,
      fun () ->
        with_opa "deny" (fun r ->
            let* _, j = opa_check r sql_ok in
            let res = List.hd (list (member "results" j)) in
            Alcotest.(check bool) "denied" true (member "allowed" res = `Bool false);
            Alcotest.(check bool)
              "opa denied" true
              (member "opa.allowed" res = `Bool false);
            let codes =
              List.map
                (fun x -> str (member "code" x))
                (list (member "verdict.reasons" res))
            in
            Alcotest.(check (list string)) "external policy" [ "E_EXTERNAL_POLICY" ] codes;
            Lwt.return_unit) );
    ( "timeout denies (on_error deny)",
      `Quick,
      fun () ->
        with_opa "slow" (fun r ->
            let* _, j = opa_check r sql_ok in
            let res = List.hd (list (member "results" j)) in
            Alcotest.(check bool) "denied" true (member "allowed" res = `Bool false);
            Alcotest.(check bool) "error set" true (member "opa.error" res <> `Null);
            Lwt.return_unit) );
  ]

(* ---- agents ---- *)

let proxy_record ~user =
  `Assoc
    [
      ("ts", `String (C.Api.iso8601 (Unix.gettimeofday ())));
      ("event", `String "statement");
      ("session", `String "s1");
      ("user", `String user);
      ("policy", `String "analytics");
      ("policy_version", `String "sha256:abc");
      ("protocol", `String "simple");
      ("allowed", `Bool true);
      ("reasons", `List []);
      ("shadow_reasons", `List []);
      ("sql_sha256", `String "x");
      ("fingerprint", `String "f");
      ("tables", `List [ `String "app.orders" ]);
    ]

let agents_extra =
  [
    ( "agents",
      `List
        [
          `Assoc
            [
              ("name", `String "analytics-agent");
              ("team", `String "Data platform");
              ("stack", `String "LangGraph, Python");
              ("callers", `List [ `String "token:a1"; `String "token:a2" ]);
              ("policy", `String "analytics");
            ];
          `Assoc [ ("name", `String "inproc"); ("via", `String "in_process") ];
        ] );
    ( "verifiers",
      `List
        [
          `Assoc
            [
              ("name", `String "mcp-1");
              ("url", `String "http://127.0.0.1:1");
              ("kind", `String "mcp");
            ];
        ] );
  ]

let agent_tests =
  [
    ( "merge, guessing, counts and detail",
      `Quick,
      fun () ->
        with_policies ~extra:agents_extra (fun r _ ->
            load_records r
              [
                server_record ~request_id:"a1-1" ~caller:"token:a1" ();
                server_record ~request_id:"a1-2" ~caller:"token:a1" ();
                server_record ~request_id:"a1-3" ~caller:"token:a1" ~allowed:false
                  ~codes:[ "E_COLUMN_DENIED" ] ~sql:sql_region ();
                server_record ~request_id:"a2-1" ~caller:"token:a2" ();
                server_record ~request_id:"u-1" ~caller:"token:unknown" ();
                server_record ~request_id:"u-2" ~caller:"token:unknown" ~allowed:false
                  ~codes:[ "E_TENANT_MISSING" ] ();
                server_record ~request_id:"old" ~caller:"token:old"
                  ~ts:(Unix.gettimeofday () -. (8. *. 86400.))
                  ();
                proxy_record ~user:"pguser";
              ];
            load_records ~verifier:"mcp-1" r
              [ server_record ~request_id:"m-1" ~caller:"token:mcpbot" () ];
            let* code, j = get r "/api/v1/agents" in
            check_status "agents" 200 (code, j);
            let counts k = int (member ("counts." ^ k) j) in
            Alcotest.(check int) "all" 5 (counts "all");
            Alcotest.(check int) "sidecar" 2 (counts "sidecar");
            Alcotest.(check int) "proxy" 1 (counts "proxy");
            Alcotest.(check int) "mcp" 1 (counts "mcp");
            Alcotest.(check int) "in_process" 1 (counts "in_process");
            let agents = list (member "agents" j) in
            let find n = List.find (fun a -> member "name" a = `String n) agents in
            let a = find "analytics-agent" in
            Alcotest.(check int) "queries" 4 (int (member "queries" a));
            Alcotest.(check int) "denied" 1 (int (member "denied" a));
            Alcotest.(check string) "team" "Data platform" (str (member "team" a));
            Alcotest.(check (list string))
              "shadow" [ "analytics-v2" ]
              (List.map str (list (member "shadow" a)));
            Alcotest.(check string) "audit" "central" (str (member "audit" a));
            let ip = find "inproc" in
            Alcotest.(check bool)
              "in-process queries null" true
              (member "queries" ip = `Null);
            Alcotest.(check string) "in-process audit" "in_app" (str (member "audit" ip));
            Alcotest.(check string)
              "proxy guessed" "proxy"
              (str (member "via" (find "pguser")));
            Alcotest.(check string)
              "mcp guessed" "mcp"
              (str (member "via" (find "token:mcpbot")));
            Alcotest.(check bool)
              "old caller outside range" false
              (List.exists (fun a -> member "name" a = `String "token:old") agents);
            let* _, j = get r "/api/v1/agents?range=30d" in
            Alcotest.(check int) "30d" 6 (int (member "counts.all" j));
            let* _, j = get r "/api/v1/agents?via=proxy" in
            Alcotest.(check (list string))
              "via filter" [ "pguser" ]
              (names (member "agents" j));
            let* _, j = get r "/api/v1/agents?sort=queries" in
            Alcotest.(check string)
              "sort queries" "analytics-agent"
              (str (member "name" (List.hd (list (member "agents" j)))));
            let* code, _ = get r "/api/v1/agents?sort=bogus" in
            Alcotest.(check int) "bad sort" 400 code;
            let* code, d = get r "/api/v1/agents/analytics-agent" in
            check_status "detail" 200 (code, d);
            (match list (member "top_codes" d) with
            | [ t ] ->
                Alcotest.(check string) "code" "E_COLUMN_DENIED" (str (member "code" t));
                Alcotest.(check int) "count" 1 (int (member "count" t));
                Alcotest.(check string)
                  "object" "app.orders.region"
                  (str (member "top_object" t))
            | l -> Alcotest.failf "expected one top code, got %d" (List.length l));
            Alcotest.(check string)
              "enforced" "analytics"
              (str (member "policies.enforced.name" d));
            Alcotest.(check (list string))
              "shadow policies" [ "analytics-v2" ]
              (names (member "policies.shadow" d));
            let* code, _ = get r "/api/v1/agents/nobody" in
            Alcotest.(check int) "unknown" 404 code;
            Lwt.return_unit) );
  ]

let () =
  Alcotest.run "console-build"
    [
      ("policies", loading_tests);
      ("report", report_tests);
      ("pull requests", pr_tests);
      ("playground", playground_tests);
      ("opa", opa_tests);
      ("agents", agent_tests);
    ]
