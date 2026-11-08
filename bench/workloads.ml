(* Query corpora for the library, CLI and HTTP suites.

   - complexity tiers (bench/corpus/complexity.jsonl): lab-like analytics queries
     an LLM agent writes, from a point lookup (t1) to a multi-CTE report with window
     functions and six joins (t5). Every one MUST be allowed by the saas fixture
     policy; the harness checks this before timing anything.
   - benign: every case of test/corpus/benign_analytics.suite.yaml (allowed).
   - attack: every other test/corpus suite against its own policy (mostly denials,
     exercising the early exits).
   - pathological: huge IN lists, deep nesting, 50-way joins, long identifiers, a
     query just under max_bytes. *)

open Haltsql

let ( // ) = Filename.concat

type item = { policy : Policy.t; context : Context.t; sql : string }
type workload = { wname : string; items : item array; expect_allowed : bool option }

let fail fmt = Printf.ksprintf failwith fmt

let load_policy f =
  match Policy_load.of_file f with
  | Ok p -> p
  | Error es -> fail "%s" (String.concat "\n" (f :: List.map Load_error.to_string es))

let suite f =
  match Test_suite.of_file f with
  | Ok s -> s
  | Error es -> fail "%s" (String.concat "\n" (f :: List.map Load_error.to_string es))

let acme = Context.make [ ("tenant_id", Context.One "acme") ]
let saas_policy_path root = root // "test/fixtures/policies/saas.yaml"
let complexity_path root = root // "bench/corpus/complexity.jsonl"

(* (id, tier, sql) from the JSONL corpus. *)
let complexity_rows root =
  let ic = open_in (complexity_path root) in
  let rows = ref [] in
  (try
     while true do
       let line = String.trim (input_line ic) in
       if line <> "" then
         let j = Yojson.Safe.from_string line in
         let s k = Yojson.Safe.Util.(member k j |> to_string) in
         rows := (s "id", s "tier", s "sql") :: !rows
     done
   with End_of_file -> close_in ic);
  List.rev !rows

let tiers root =
  let saas = load_policy (saas_policy_path root) in
  let rows = complexity_rows root in
  let names = List.sort_uniq compare (List.map (fun (_, t, _) -> t) rows) in
  List.map
    (fun t ->
      {
        wname = t;
        items =
          rows
          |> List.filter (fun (_, t', _) -> t' = t)
          |> List.map (fun (_, _, sql) -> { policy = saas; context = acme; sql })
          |> Array.of_list;
        expect_allowed = Some true;
      })
    names

let benign root =
  let saas = load_policy (saas_policy_path root) in
  let s = suite (root // "test/corpus/benign_analytics.suite.yaml") in
  {
    wname = "corpus_benign";
    items =
      Array.of_list
        (List.map
           (fun (c : Test_suite.case) ->
             { policy = saas; context = c.context; sql = c.sql })
           s.cases);
    expect_allowed = Some true;
  }

let attack root =
  let corpus = root // "test/corpus" in
  let items =
    Sys.readdir corpus |> Array.to_list |> List.sort compare
    |> List.filter (fun f ->
        Filename.check_suffix f ".suite.yaml" && f <> "benign_analytics.suite.yaml")
    |> List.concat_map (fun f ->
        match Test_suite.of_file (corpus // f) with
        | Error _ -> []
        | Ok s -> (
            match Policy_load.of_file s.policy_path with
            | Error _ -> []
            | Ok p ->
                List.map
                  (fun (c : Test_suite.case) ->
                    { policy = p; context = c.context; sql = c.sql })
                  s.cases))
    |> Array.of_list
  in
  { wname = "corpus_attack"; items; expect_allowed = None }

let pathological root =
  let saas = load_policy (saas_policy_path root) in
  let in_list n = String.concat ", " (List.init n string_of_int) in
  let nest n =
    String.concat "" (List.init n (fun _ -> "(1 + ")) ^ "1" ^ String.make n ')'
  in
  let joins n =
    "SELECT t0.id FROM orders t0"
    ^ String.concat ""
        (List.init n (fun i ->
             Printf.sprintf " JOIN orders t%d ON t%d.tenant_id = $1 AND t%d.id = t0.id"
               (i + 1) (i + 1) (i + 1)))
    ^ " WHERE t0.tenant_id = $1 LIMIT 10"
  in
  let near_limit =
    let b = Buffer.create 16000 in
    Buffer.add_string b "SELECT o.id, o.status FROM orders o WHERE o.tenant_id = $1";
    let i = ref 0 in
    while Buffer.length b < 15_500 do
      Buffer.add_string b (Printf.sprintf " AND o.total_cents <> %d" !i);
      incr i
    done;
    Buffer.add_string b " LIMIT 10";
    Buffer.contents b
  in
  let sqls =
    [
      "SELECT id FROM orders WHERE tenant_id = $1 AND id IN (" ^ in_list 10_000
      ^ ") LIMIT 10";
      "SELECT id FROM orders WHERE tenant_id = $1 AND id IN (" ^ in_list 2_500
      ^ ") LIMIT 10";
      "SELECT " ^ nest 30 ^ " AS x FROM orders WHERE tenant_id = $1 LIMIT 1";
      "SELECT " ^ nest 500 ^ " AS x FROM orders WHERE tenant_id = $1 LIMIT 1";
      joins 50;
      joins 6;
      "SELECT o.id AS " ^ String.make 63 'x'
      ^ " FROM orders o WHERE o.tenant_id = $1 LIMIT 1";
      "SELECT o.id FROM orders " ^ String.make 4000 'a' ^ " WHERE tenant_id = $1 LIMIT 1";
      near_limit;
      String.concat " UNION ALL "
        (List.init 100 (fun _ -> "SELECT id FROM orders WHERE tenant_id = $1"))
      ^ " LIMIT 10";
    ]
  in
  {
    wname = "pathological";
    items =
      Array.of_list (List.map (fun sql -> { policy = saas; context = acme; sql }) sqls);
    expect_allowed = None;
  }

(* Fails loudly if a workload that must be allowed is not: a benchmark over denied
   queries would silently measure the wrong code path. *)
let check w =
  match w.expect_allowed with
  | None -> ()
  | Some want ->
      Array.iter
        (fun it ->
          let v = Haltsql.verify it.policy it.context it.sql in
          if v.allowed <> want then
            fail "bench corpus: %s expected %s but got %s for: %s" w.wname
              (if want then "allowed" else "denied")
              (if v.allowed then "allowed" else "denied")
              it.sql)
        w.items

(* JSONL lines for `haltsql verify --batch` and request bodies for the HTTP suite: the
   complexity tiers in a fixed round-robin order. *)
let mix_sqls root = List.map (fun (_, _, sql) -> sql) (complexity_rows root)
