open Haltsql_pgquery

let is_ok = function Ok _ -> true | Error _ -> false

let test_parse_ok () =
  match
    Pgquery_raw.parse_json "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 10"
  with
  | Error (m, _) -> Alcotest.fail m
  | Ok json ->
      let j = Yojson.Safe.from_string json in
      let stmts = Yojson.Safe.Util.(member "stmts" j |> to_list) in
      Alcotest.(check int) "one statement" 1 (List.length stmts)

let test_parse_error () =
  match Pgquery_raw.parse_json "SELEC 1" with
  | Ok _ -> Alcotest.fail "expected a parse error"
  | Error (_, pos) -> Alcotest.(check int) "cursor position" 1 pos

let test_nul_rejected () =
  Alcotest.(check bool)
    "NUL byte rejected" false
    (is_ok (Pgquery_raw.parse_json "SELECT 1\000; DROP TABLE x"))

let test_fingerprint () =
  match
    ( Pgquery_raw.fingerprint "SELECT * FROM t WHERE a = 1",
      Pgquery_raw.fingerprint "SELECT * FROM t WHERE a = 2" )
  with
  | Ok a, Ok b -> Alcotest.(check string) "literals normalized" a b
  | _ -> Alcotest.fail "fingerprint failed"

let test_version () =
  Alcotest.(check bool)
    "postgres 17 grammar" true
    (Pgquery_raw.pg_version_num >= 170000 && Pgquery_raw.pg_version_num < 180000)

let test_parallel_domains () =
  let work () =
    for i = 1 to 2000 do
      match
        Pgquery_raw.parse_json (Printf.sprintf "SELECT %d FROM t WHERE x = 'v%d'" i i)
      with
      | Ok _ -> ()
      | Error (m, _) -> failwith m
    done
  in
  let ds = List.init 4 (fun _ -> Domain.spawn work) in
  List.iter Domain.join ds

(* Deep trees must not crash the process, even from a secondary domain whose
   thread has a small stack (regression: SIGBUS on macOS). *)
let deep_inputs =
  [
    "SELECT 1" ^ String.concat "" (List.init 100_000 (fun _ -> "+1"));
    String.concat " UNION ALL " (List.init 20_000 (fun _ -> "SELECT 1"));
    "SELECT 1" ^ String.concat "" (List.init 50_000 (fun _ -> "::int"));
  ]

let test_deep_in_domain () =
  let d =
    Domain.spawn (fun () ->
        List.map
          (fun sql -> (Pgquery_raw.parse_json sql, Pgquery_raw.fingerprint sql))
          deep_inputs)
  in
  (* Either a result or a clean error is fine; a crash fails the whole run. *)
  ignore (Domain.join d)

let () =
  Alcotest.run "pgquery"
    [
      ( "raw",
        [
          Alcotest.test_case "parse ok" `Quick test_parse_ok;
          Alcotest.test_case "parse error" `Quick test_parse_error;
          Alcotest.test_case "NUL rejected" `Quick test_nul_rejected;
          Alcotest.test_case "fingerprint" `Quick test_fingerprint;
          Alcotest.test_case "version" `Quick test_version;
          Alcotest.test_case "parallel domains" `Quick test_parallel_domains;
          Alcotest.test_case "deep trees in a domain" `Quick test_deep_in_domain;
        ] );
    ]
