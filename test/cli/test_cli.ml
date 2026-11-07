(* End-to-end tests for the haltsql CLI. Each test runs the built binary.

   Tests marked [needs analyzer] depend on the parser + analyzer producing
   real verdicts; everything else only depends on the CLI and the loaders. *)

let bin =
  let b =
    Option.value (Sys.getenv_opt "HALTSQL_BIN") ~default:"../../bin/haltsql/main.exe"
  in
  if Filename.is_relative b then Filename.concat (Sys.getcwd ()) b else b

let fx name = Filename.concat "fixtures" name

type result = { code : int; out : string; err : string }

let tmpdir =
  lazy
    (let d =
       Filename.concat
         (Filename.get_temp_dir_name ())
         (Printf.sprintf "haltsql-cli-%d" (Unix.getpid ()))
     in
     (try Unix.mkdir d 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
     d)

let tmp name = Filename.concat (Lazy.force tmpdir) name

(* Runs [bin args] with [stdin] contents; stdout/stderr captured via files to
   avoid pipe deadlocks on large outputs. *)
let run ?(stdin = "") args =
  let inp = tmp "stdin" and o = tmp "stdout" and e = tmp "stderr" in
  Out_channel.with_open_bin inp (fun oc -> output_string oc stdin);
  let fd_in = Unix.openfile inp [ Unix.O_RDONLY ] 0 in
  let fd_out = Unix.openfile o [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o644 in
  let fd_err = Unix.openfile e [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o644 in
  let pid = Unix.create_process bin (Array.of_list (bin :: args)) fd_in fd_out fd_err in
  List.iter Unix.close [ fd_in; fd_out; fd_err ];
  let _, st = Unix.waitpid [] pid in
  let code =
    match st with
    | Unix.WEXITED c -> c
    | Unix.WSIGNALED s -> 128 + s
    | Unix.WSTOPPED _ -> -1
  in
  let read f = In_channel.with_open_bin f In_channel.input_all in
  { code; out = read o; err = read e }

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  n = 0 || go 0

let check_code msg expected r =
  if r.code <> expected then
    Alcotest.failf "%s: expected exit %d, got %d\nstdout:\n%s\nstderr:\n%s" msg expected
      r.code r.out r.err

let check_contains msg s sub =
  if not (contains s sub) then
    Alcotest.failf "%s: expected output to contain %S, got:\n%s" msg sub s

let json_of s =
  try Yojson.Safe.from_string s
  with e -> Alcotest.failf "invalid JSON (%s): %s" (Printexc.to_string e) s

let member k = function
  | `Assoc kv -> Option.value (List.assoc_opt k kv) ~default:`Null
  | _ -> `Null

let policy = fx "shop.yaml"
let ctx = {|{"tenant_id":"acme"}|}
let good_sql = "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10"
let bad_sql = "SELECT id FROM orders LIMIT 10"

(* ------------------------------------------------------------- verify *)

let verify_allowed () =
  let r = run [ "verify"; "--policy"; policy; "--context"; ctx; "--sql"; good_sql ] in
  check_code "allowed" 0 r;
  check_contains "stdout" r.out "ALLOWED";
  check_contains "bind params" r.out "$1 = \"acme\""

let verify_denied () =
  let r = run [ "verify"; "--policy"; policy; "--context"; ctx; "--sql"; bad_sql ] in
  check_code "denied" 1 r;
  check_contains "stdout" r.out "DENIED";
  check_contains "code" r.out "E_TENANT_MISSING"

let verify_denied_any () =
  (* Holds even with a stub analyzer: DROP is never allowed. *)
  let r = run [ "verify"; "-p"; policy; "-c"; ctx; "--sql"; "DROP TABLE app.orders" ] in
  check_code "denied" 1 r;
  check_contains "stdout" r.out "DENIED"

let verify_json () =
  let r =
    run
      [
        "verify";
        "--policy";
        fx "shop.json";
        "--context";
        ctx;
        "--sql";
        "DROP TABLE x";
        "--json";
      ]
  in
  check_code "denied" 1 r;
  let j = json_of r.out in
  Alcotest.(check bool) "allowed=false" true (member "allowed" j = `Bool false);
  Alcotest.(check bool)
    "policy name" true
    (member "name" (member "policy" j) = `String "shop");
  Alcotest.(check bool)
    "has sql_sha256" true
    (match member "sql_sha256" j with `String _ -> true | _ -> false)

let verify_stdin_and_file () =
  let r = run ~stdin:"DROP TABLE x" [ "verify"; "-p"; policy; "-c"; ctx; "--json" ] in
  check_code "stdin" 1 r;
  let f = tmp "q.sql" in
  Out_channel.with_open_bin f (fun oc -> output_string oc "DROP TABLE x");
  let r2 = run [ "verify"; "-p"; policy; "-c"; ctx; "--file"; f; "--json" ] in
  check_code "file" 1 r2;
  Alcotest.(check bool)
    "same sha" true
    (member "sql_sha256" (json_of r.out) = member "sql_sha256" (json_of r2.out))

let verify_context_file () =
  let r =
    run
      [ "verify"; "-p"; policy; "--context-file"; fx "ctx.yaml"; "--sql"; "DROP TABLE x" ]
  in
  check_code "yaml ctx" 1 r;
  let r =
    run
      [ "verify"; "-p"; policy; "--context-file"; fx "ctx.json"; "--sql"; "DROP TABLE x" ]
  in
  check_code "json ctx" 1 r

let verify_usage_errors () =
  check_code "missing policy file" 2
    (run [ "verify"; "-p"; fx "nope.yaml"; "--sql"; "SELECT 1" ]);
  check_code "bad policy" 2
    (run [ "verify"; "-p"; fx "bad_policy.yaml"; "--sql"; "SELECT 1" ]);
  check_code "bad context json" 2
    (run [ "verify"; "-p"; policy; "-c"; "{nope"; "--sql"; "SELECT 1" ]);
  check_code "context not object" 2
    (run [ "verify"; "-p"; policy; "-c"; "[1]"; "--sql"; "SELECT 1" ]);
  check_code "sql and file" 2
    (run [ "verify"; "-p"; policy; "--sql"; "x"; "--file"; "y" ]);
  check_code "no --policy" 2 (run [ "verify"; "--sql"; "SELECT 1" ]);
  check_code "unknown flag" 2 (run [ "verify"; "--bogus" ]);
  check_code "unknown command" 2 (run [ "frobnicate" ]);
  let r = run [ "verify"; "-p"; fx "bad_policy.yaml"; "--sql"; "SELECT 1" ] in
  check_contains "located error" r.err "bad_policy.yaml"

let verify_shadow () =
  (* [needs analyzer for shadow_reasons]: shadow mode always exits 0. *)
  let r = run [ "verify"; "-p"; fx "shadow.yaml"; "-c"; ctx; "--sql"; "DROP TABLE x" ] in
  check_code "shadow allowed" 0 r;
  check_contains "shadow notice" r.out "shadow mode"

(* -------------------------------------------------------------- batch *)

let batch_lines n =
  let b = Buffer.create (n * 80) in
  for i = 0 to n - 1 do
    (match i mod 5 with
    | 0 ->
        Printf.bprintf b
          {|{"id":%d,"sql":"SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10","context":{"tenant_id":"acme"}}|}
          i
    | 1 -> Printf.bprintf b {|{"id":"s%d","sql":"DROP TABLE x"}|} i
    | 2 -> Printf.bprintf b {|{"id":%d,"sql":42}|} i
    | 3 -> Printf.bprintf b {|{"id":%d, not json|} i
    | _ -> Printf.bprintf b {|{"id":%d,"sql":"SELECT 1","context":"bad"}|} i);
    Buffer.add_char b '\n';
    if i mod 97 = 0 then Buffer.add_string b "\n" (* blank lines are skipped *)
  done;
  Buffer.contents b

let check_batch_output n out =
  let lines = String.split_on_char '\n' out |> List.filter (fun l -> l <> "") in
  Alcotest.(check int) "one output line per input line" n (List.length lines);
  List.iteri
    (fun i l ->
      let j = json_of l in
      (* "id" is the first field *)
      (match j with
      | `Assoc (("id", _) :: _) -> ()
      | _ -> Alcotest.failf "line %d: id is not the first field: %s" i l);
      let id = member "id" j in
      match i mod 5 with
      | 0 ->
          Alcotest.(check bool) (Printf.sprintf "id %d" i) true (id = `Int i);
          Alcotest.(check bool) "verdict" true (member "allowed" j <> `Null)
      | 1 ->
          Alcotest.(check bool) "string id" true (id = `String (Printf.sprintf "s%d" i));
          Alcotest.(check bool) "denied" true (member "allowed" j = `Bool false)
      | 2 | 4 ->
          Alcotest.(check bool) (Printf.sprintf "id %d" i) true (id = `Int i);
          Alcotest.(check bool)
            "error" true
            (match member "error" j with `String _ -> true | _ -> false)
      | _ ->
          Alcotest.(check bool) "null id for invalid JSON" true (id = `Null);
          Alcotest.(check bool)
            "error" true
            (match member "error" j with `String _ -> true | _ -> false))
    lines

let batch_basic () =
  let n = 200 in
  let r = run ~stdin:(batch_lines n) [ "verify"; "-p"; policy; "--batch" ] in
  check_code "batch exit" 0 r;
  check_batch_output n r.out

let batch_jobs_order () =
  let n = 5003 in
  let input = batch_lines n in
  let r1 = run ~stdin:input [ "verify"; "-p"; policy; "--batch" ] in
  let r4 = run ~stdin:input [ "verify"; "-p"; policy; "--batch"; "--jobs"; "4" ] in
  check_code "jobs=4 exit" 0 r4;
  check_batch_output n r4.out;
  (* Identical except for elapsed_us. *)
  let strip s = Str.global_replace (Str.regexp {|"elapsed_us":[0-9]+|}) "" s in
  Alcotest.(check bool) "same output as sequential" true (strip r1.out = strip r4.out)

let batch_default_context () =
  let r =
    run ~stdin:{|{"id":1,"sql":"DROP TABLE x"}|}
      [ "verify"; "-p"; policy; "--batch"; "-c"; ctx ]
  in
  check_code "exit" 0 r;
  let j = json_of (String.trim r.out) in
  Alcotest.(check bool) "id" true (member "id" j = `Int 1);
  Alcotest.(check bool) "denied" true (member "allowed" j = `Bool false)

let batch_policy_error () =
  check_code "bad policy" 2
    (run ~stdin:"{}\n" [ "verify"; "-p"; fx "bad_policy.yaml"; "--batch" ])

let batch_large () =
  let n = 100_000 in
  let b = Buffer.create (n * 60) in
  for i = 0 to n - 1 do
    Printf.bprintf b
      {|{"id":%d,"sql":"SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5","context":{"tenant_id":"t%d"}}|}
      i (i mod 7);
    Buffer.add_char b '\n'
  done;
  let t0 = Unix.gettimeofday () in
  let r =
    run ~stdin:(Buffer.contents b) [ "verify"; "-p"; policy; "--batch"; "--jobs"; "4" ]
  in
  let dt = Unix.gettimeofday () -. t0 in
  check_code "exit" 0 r;
  let count = List.length (List.filter (( <> ) "") (String.split_on_char '\n' r.out)) in
  Alcotest.(check int) "100k lines" n count;
  Printf.printf "  100k-line batch with --jobs 4: %.2fs\n%!" dt

(* ------------------------------------------------------------ explain *)

let explain_report () =
  let sql = "SELECT id\nFROM orders\nLIMIT 10" in
  let r = run [ "explain"; "-p"; policy; "-c"; ctx; "--sql"; sql ] in
  check_code "denied" 1 r;
  List.iter
    (check_contains "report" r.out)
    [
      "Verdict:";
      "DENIED";
      "Policy:";
      "shop";
      "Statement:";
      "Tables:";
      "Columns:";
      "Reasons";
    ]

let explain_caret () =
  (* [needs analyzer]: reason.loc points at the relation missing a tenant predicate. *)
  let sql = "SELECT id\nFROM orders\nLIMIT 10" in
  let r = run [ "explain"; "-p"; policy; "-c"; ctx; "--sql"; sql ] in
  check_code "denied" 1 r;
  check_contains "code" r.out "E_TENANT_MISSING";
  check_contains "caret" r.out "^"

(* ----------------------------------------------------------- validate *)

let validate_ok () =
  let r =
    run
      [
        "validate";
        fx "shop.yaml";
        fx "shop.json";
        fx "suites/shop.suite.yaml";
        fx "catalog.json";
        fx "scenario.yaml";
      ]
  in
  check_code "all ok" 0 r;
  check_contains "ok" r.out "shop.yaml: ok (Policy"

let validate_config () =
  (* [needs config loader] *)
  let r = run [ "validate"; fx "config.yaml" ] in
  check_code "config ok" 0 r

let validate_errors () =
  let r = run [ "validate"; fx "shop.yaml"; fx "bad_policy.yaml" ] in
  check_code "has error" 1 r;
  check_contains "ok line" r.out "shop.yaml: ok";
  check_contains "error located" r.out "bad_policy.yaml";
  check_contains "key" r.out "tabels";
  check_code "unknown kind" 1 (run [ "validate"; fx "unknown_kind.yaml" ]);
  check_code "missing file" 1 (run [ "validate"; fx "missing.yaml" ]);
  check_code "no files" 2 (run [ "validate" ])

let validate_json () =
  let r = run [ "validate"; "--json"; fx "shop.yaml"; fx "bad_policy.yaml" ] in
  check_code "exit" 1 r;
  let j = json_of r.out in
  Alcotest.(check bool) "ok=false" true (member "ok" j = `Bool false);
  match member "files" j with
  | `List [ a; b ] ->
      Alcotest.(check bool) "first ok" true (member "ok" a = `Bool true);
      Alcotest.(check bool) "first kind" true (member "kind" a = `String "Policy");
      Alcotest.(check bool) "second has errors" true (member "errors" b <> `List [])
  | _ -> Alcotest.fail "expected two file entries"

(* ------------------------------------------------------------ convert *)

let convert_roundtrip () =
  let out_json = tmp "shop.converted.json" and out_yaml = tmp "shop.converted.yaml" in
  check_code "to json" 0
    (run [ "convert"; fx "shop.yaml"; "--to"; "json"; "-o"; out_json ]);
  check_code "to yaml" 0 (run [ "convert"; out_json; "--to"; "yaml"; "-o"; out_yaml ]);
  let version f =
    let r = run [ "validate"; "--json"; f ] in
    check_code ("validate " ^ f) 0 r;
    r.out
  in
  ignore (version out_json);
  ignore (version out_yaml);
  (* Same normalized policy => same policy version. *)
  let v f =
    let r = run [ "verify"; "-p"; f; "--sql"; "DROP TABLE x"; "--json" ] in
    member "version" (member "policy" (json_of r.out))
  in
  Alcotest.(check bool)
    "same version" true
    (v (fx "shop.yaml") = v out_yaml && v out_json = v out_yaml);
  let r = run [ "convert"; fx "shop.json"; "--to"; "yaml" ] in
  check_code "stdout" 0 r;
  check_contains "yaml content" r.out "app.orders"

let convert_errors () =
  check_code "invalid doc" 2 (run [ "convert"; fx "bad_policy.yaml"; "--to"; "json" ]);
  check_code "bad format" 2 (run [ "convert"; fx "shop.yaml"; "--to"; "toml" ]);
  check_code "missing" 2 (run [ "convert"; fx "nope.yaml"; "--to"; "json" ])

(* ------------------------------------------------------------- schema *)

let schema_export () =
  let dir = tmp "schemas/nested" in
  let r = run [ "schema"; "export"; "--out"; dir ] in
  check_code "exit" 0 r;
  List.iter
    (fun f ->
      let p = Filename.concat dir f in
      if not (Sys.file_exists p) then Alcotest.failf "missing %s" p;
      ignore (json_of (In_channel.with_open_bin p In_channel.input_all)))
    [
      "policy.schema.json";
      "config.schema.json";
      "catalog.schema.json";
      "scenario.schema.json";
    ]

(* --------------------------------------------------------------- test *)

let test_suites_dir () =
  (* [needs analyzer] all fixture cases pass with a working analyzer. *)
  let r = run [ "test"; fx "suites" ] in
  check_code "all pass" 0 r;
  check_contains "pass" r.out "PASS";
  check_contains "summary" r.out "2 suite(s), 5 case(s): 5 passed, 0 failed"

let test_failing () =
  let r = run [ "test"; fx "failing.suite.yaml" ] in
  check_code "failure" 1 r;
  check_contains "fail" r.out "FAIL  wrong expectation";
  check_contains "summary" r.out "0 passed, 1 failed"

let test_filter_json () =
  let r = run [ "test"; "--json"; "--filter"; "tables"; fx "suites" ] in
  let j = json_of r.out in
  let total =
    (match member "passed" j with `Int n -> n | _ -> -1)
    + match member "failed" j with `Int n -> n | _ -> -1
  in
  Alcotest.(check int) "only one case tagged 'tables'" 1 total;
  match member "suites" j with
  | `List l -> Alcotest.(check int) "two suites" 2 (List.length l)
  | _ -> Alcotest.fail "suites"

let test_errors () =
  check_code "missing path" 2 (run [ "test"; fx "nope" ]);
  check_code "bad suite" 1 (run [ "test"; fx "shop.yaml" ]);
  check_code "no args" 2 (run [ "test" ])

(* ------------------------------------------------------ config/version *)

let config_show () =
  (* [needs config loader] *)
  let r = run [ "config"; "show"; "--config"; fx "config.yaml" ] in
  check_code "exit" 0 r;
  let _ = json_of r.out in
  if contains r.out "49a959c110885c75afc29130f42e53da36757e1381bba1b83fcebfb56074e967"
  then Alcotest.fail "token hash must be redacted"

let config_show_errors () =
  check_code "missing" 2 (run [ "config"; "show"; "--config"; fx "nope.yaml" ]);
  check_code "required flag" 2 (run [ "config"; "show" ])

let version () =
  let r = run [ "version" ] in
  check_code "exit" 0 r;
  check_contains "haltsql" r.out "haltsql 0.1.0";
  check_contains "pg" r.out "postgres grammar";
  check_contains "ocaml" r.out ("ocaml " ^ Sys.ocaml_version);
  let j = json_of (run [ "version"; "--json" ]).out in
  Alcotest.(check bool) "json" true (member "haltsql" j = `String "0.1.0")

let help () =
  List.iter
    (fun cmd ->
      let r = run (cmd @ [ "--help=plain" ]) in
      check_code (String.concat " " cmd) 0 r;
      check_contains "examples" r.out "EXAMPLES")
    [
      [ "verify" ];
      [ "explain" ];
      [ "validate" ];
      [ "convert" ];
      [ "schema"; "export" ];
      [ "test" ];
      [ "config"; "show" ];
      [ "lint-policy" ];
    ]

(* -------------------------------------------------------------- lint *)

let lint () =
  let r = run [ "lint-policy"; fx "shadow.yaml" ] in
  check_code "exit" 0 r;
  List.iter
    (check_contains "finding" r.out)
    [
      "W_BROAD_COLUMNS";
      "app.currencies";
      "W_SHADOW_MODE";
      "W_NO_REQUIRE_LIMIT";
      "W_TENANCY_KEY_UNUSED";
      "region";
      "1 of 2 table(s) are tenant-scoped";
      "functions allowlist has";
    ];
  let r = run [ "lint-policy"; "--json"; fx "shop.yaml" ] in
  check_code "exit" 0 r;
  let j = json_of r.out in
  (match member "findings" j with
  | `List l ->
      let codes = List.map (fun f -> member "code" f) l in
      Alcotest.(check bool)
        "no shadow warning" false
        (List.mem (`String "W_SHADOW_MODE") codes);
      Alcotest.(check bool)
        "no require_limit warning" false
        (List.mem (`String "W_NO_REQUIRE_LIMIT") codes)
  | _ -> Alcotest.fail "findings");
  check_code "bad policy" 2 (run [ "lint-policy"; fx "bad_policy.yaml" ])

(* ---- enterprise subcommands registered in main.ml ---- *)

(* Every leaf command must build its command line: a duplicated option name
   (e.g. a subcommand flag clashing with the inherited --version) only fails
   at run time. *)
let all_commands_have_help () =
  List.iter
    (fun c ->
      let r = run (c @ [ "--help=plain" ]) in
      check_code (String.concat " " c ^ " --help") 0 r)
    [
      [ "schema"; "export" ];
      [ "schema"; "pull" ];
      [ "schema"; "import" ];
      [ "policy"; "draft" ];
      [ "rls"; "generate" ];
      [ "rls"; "check" ];
      [ "bundle"; "keygen" ];
      [ "bundle"; "build" ];
      [ "bundle"; "sign" ];
      [ "bundle"; "verify" ];
      [ "bundle"; "inspect" ];
    ]

let bundle_roundtrip () =
  let k = tmp "bundle.key" and b = tmp "shop.haltsqlbundle" in
  List.iter
    (fun f -> try Sys.remove f with Sys_error _ -> ())
    [ k; k ^ ".pub"; b; b ^ ".sig" ];
  check_code "keygen" 0 (run [ "bundle"; "keygen"; "-o"; k ]);
  check_code "build" 0
    (run [ "bundle"; "build"; policy; "--name"; "cli"; "--bundle-version"; "1"; "-o"; b ]);
  check_code "sign" 0 (run [ "bundle"; "sign"; b; "--key"; k ]);
  let r = run [ "bundle"; "verify"; b; "--public-key"; k ^ ".pub"; "--json" ] in
  check_code "verify" 0 r;
  check_contains "verified policy" r.out "\"shop\"";
  Out_channel.with_open_gen [ Open_append; Open_binary ] 0o644 b (fun oc ->
      output_string oc " ");
  check_code "tampered" 1 (run [ "bundle"; "verify"; b; "--public-key"; k ^ ".pub" ])

let rls_generate () =
  let r = run [ "rls"; "generate"; "-p"; policy ] in
  check_code "rls generate" 0 r;
  check_contains "rls" r.out "CREATE POLICY";
  check_contains "rls" r.out "ENABLE ROW LEVEL SECURITY"

(* Provider placeholders go through the secrets resolver; without a
   secrets.vault section they fail closed, before any network access. *)
let config_secret_provider () =
  let f = tmp "vault-config.yaml" in
  Out_channel.with_open_bin f (fun oc ->
      output_string oc
        "apiVersion: haltsql.dev/v1\n\
         kind: Config\n\
         telemetry:\n\
        \  otlp:\n\
        \    endpoint: http://127.0.0.1:4318\n\
        \    headers:\n\
        \      authorization: \"Bearer ${vault:secret/data/x#token}\"\n");
  let r = run [ "config"; "show"; "--config"; f ] in
  check_code "config show" 2 r;
  check_contains "config show" r.err "secrets.vault is not configured";
  let r = run [ "validate"; f ] in
  check_code "validate" 1 r;
  check_contains "validate" r.out "secrets.vault is not configured"

let () =
  let tc name f = Alcotest.test_case name `Quick f in
  let slow name f = Alcotest.test_case name `Slow f in
  Alcotest.run "haltsql-cli"
    [
      ( "verify",
        [
          tc "denies DDL" verify_denied_any;
          tc "json output" verify_json;
          tc "stdin and --file" verify_stdin_and_file;
          tc "context files" verify_context_file;
          tc "usage errors exit 2" verify_usage_errors;
          tc "[needs analyzer] allowed + bind params" verify_allowed;
          tc "[needs analyzer] denied with reason" verify_denied;
          tc "shadow mode exits 0" verify_shadow;
        ] );
      ( "batch",
        [
          tc "malformed lines do not stop the batch" batch_basic;
          tc "--jobs preserves order" batch_jobs_order;
          tc "default context" batch_default_context;
          tc "policy load error" batch_policy_error;
          slow "100k lines" batch_large;
        ] );
      ( "explain",
        [ tc "report" explain_report; tc "[needs analyzer] caret" explain_caret ] );
      ( "validate",
        [
          tc "ok" validate_ok;
          tc "errors" validate_errors;
          tc "json" validate_json;
          tc "[needs config loader] config" validate_config;
        ] );
      ("convert", [ tc "roundtrip" convert_roundtrip; tc "errors" convert_errors ]);
      ("schema", [ tc "export" schema_export ]);
      ( "test",
        [
          tc "[needs analyzer] directory" test_suites_dir;
          tc "failing suite" test_failing;
          tc "filter + json" test_filter_json;
          tc "errors" test_errors;
        ] );
      ( "config",
        [ tc "[needs config loader] show" config_show; tc "errors" config_show_errors ] );
      ("misc", [ tc "version" version; tc "help" help; tc "lint-policy" lint ]);
      ( "enterprise",
        [
          tc "every subcommand builds" all_commands_have_help;
          tc "bundle keygen/build/sign/verify" bundle_roundtrip;
          tc "rls generate" rls_generate;
          tc "secret provider placeholders" config_secret_provider;
        ] );
    ]
