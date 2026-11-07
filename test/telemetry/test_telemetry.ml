open Lwt.Infix
module T = Haltsql_telemetry
module E = T.Exporter
module J = T.Otlp_json
module Config = Haltsql_load.Config
module Core = Haltsql_core

let run = Lwt_main.run

(* ---- JSON helpers ---- *)

let member k = function
  | `Assoc kv -> (
      match List.assoc_opt k kv with
      | Some v -> v
      | None -> Alcotest.failf "missing key %s" k)
  | _ -> Alcotest.failf "not an object looking for %s" k

let nth i = function `List l -> List.nth l i | _ -> Alcotest.fail "not a list"
let list = function `List l -> l | _ -> Alcotest.fail "not a list"

let str = function
  | `String s -> s
  | j -> Alcotest.failf "not a string: %s" (Yojson.Safe.to_string j)

let attr k attrs =
  match List.find_opt (fun a -> member "key" a = `String k) (list attrs) with
  | Some a -> member "value" a
  | None -> Alcotest.failf "attribute %s missing" k

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

(* ---- gzip ---- *)

let rows =
  String.concat ""
    (List.init 300 (fun i ->
         Printf.sprintf "row %d: alpha beta gamma\n" (i * 7919 mod 1000)))

(* Produced by Python's gzip module (dynamic Huffman block). *)
let python_gzip_hex =
  "1f8b08000000000002ff75d84b6e54311404d039abc8129eefc7d766378d846040048a90d83e2c80338da50caa5dd5a7fdf1f3cfdbf3f9edf5e3d7f7d7db97afbf5f6fdf5eefefaf4f1ffffe7ed7c5c9c98393e9c1c99e8d93bead935538a94c9c64074e62164ed65506eb5106a1086e2982b315c11c45308f22d8a108ba14416d45904711c465044b19ac5406ad08ee28827315c1598a605211ec56043d8aa08e22a847116428822865b0363350040ae046f05f2980d90fcb7b59dec3f20ecbbb59de66798be555066b29835404b71f96f7b2bc5cc3876b185cc36a969797e0700d1fae61700debe187cdf21e96976bb8b886d92c6fb1bc8aa02ed770710d936b5897e56506bc052caf77a0585e05b00fb7f0e11606b7302fcb7b58de6179b9854b1964b1bcc94f4011cce51a2eae61700debb0bcc3f2720d1fae61700d8bd74011dcc3357cb886b4e1d0869b366cdab068c3a20d93360cda708d33d001cbcb1da00c8732dc94e1a60c9b322cca3029c3a00c1765b82843c2f0528687321cca7028c34d193665589461528649190665b82843c2f05286f7e11ad286431b6edab069c3a20d8b364cda3068c3451b9a861c43d2f09086431a6ed27093864d1a166998a4619086411a2ed29032bca4e1210d87341cd27093864d1a166998d73f103887a4e12a5f03b69773f8700e89c3210e3771d8c4611387451c267118c4e1220e6d43ae216d7868c3a10d376db869c3a60d8b364cda3068c3a00d57f8d18c41f3b180363cb4e1d0869b366cdab068c3a40d93360cda70d186a6a16dc867c3431d0e75b8a9c3a60e9b3a2cea30a9c3a00e1775681c720d89c3431c0e71b889c34d1c367158c4611287411c0671b88843daf0fad590383cc4e110879b386ce2b088c3240e93388cf43782bf14793f3987d4e1a10e873adcd46153874d1d167598d46150878b3a5c7e38e41c5287873a1cea7053879b3a6ceab0a8c3a40ee33a02ce2175481c5ebf1b5287873a1cea7053874d1d167558d4615287411d2eead038a40e2f7978c8c3210f3779d8e4619387451e267918e4e1220f979f0eb987e4e1210fe7bf3cfc0bd4700e6a551e0000"

let of_hex h =
  String.init
    (String.length h / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

let test_crc32 () =
  Alcotest.(check int32) "crc32(123456789)" 0xCBF43926l (T.Gzip.crc32 "123456789");
  Alcotest.(check int32) "crc32(empty)" 0l (T.Gzip.crc32 "")

let test_gzip_roundtrip () =
  let rnd = Random.State.make [| 42 |] in
  let random = String.init 100_000 (fun _ -> Char.chr (Random.State.int rnd 256)) in
  let cases =
    [
      "";
      "a";
      "abcabcabcabcabcabc";
      rows;
      random;
      String.make 70_000 'x';
      String.concat "" (List.init 2000 string_of_int);
    ]
  in
  List.iter
    (fun s ->
      match T.Gzip.decompress (T.Gzip.compress s) with
      | Ok d ->
          Alcotest.(check bool)
            (Printf.sprintf "roundtrip %d bytes" (String.length s))
            true (String.equal d s)
      | Error e -> Alcotest.failf "decompress failed: %s" e)
    cases;
  let c = T.Gzip.compress rows in
  Alcotest.(check bool)
    "compresses repetitive text" true
    (String.length c < String.length rows / 4);
  Alcotest.(check string) "gzip magic" "\x1f\x8b\x08" (String.sub c 0 3)

let test_gzip_python () =
  match T.Gzip.decompress (of_hex python_gzip_hex) with
  | Ok d -> Alcotest.(check string) "dynamic-Huffman stream from Python" rows d
  | Error e -> Alcotest.failf "decompress failed: %s" e

let test_gzip_corrupt () =
  let flip off =
    let c = Bytes.of_string (T.Gzip.compress rows) in
    let i = Bytes.length c - off in
    Bytes.set c i (Char.chr (Char.code (Bytes.get c i) lxor 1));
    T.Gzip.decompress (Bytes.to_string c)
  in
  Alcotest.(check (result string string)) "size check" (Error "size mismatch") (flip 1);
  Alcotest.(check (result string string)) "crc check" (Error "CRC-32 mismatch") (flip 6);
  Alcotest.(check bool)
    "not gzip" true
    (Result.is_error (T.Gzip.decompress "hello world, not gzip"));
  match T.Gzip.decompress ~max_size:100 (T.Gzip.compress rows) with
  | Error e -> Alcotest.(check string) "bomb guard" "decompressed size limit exceeded" e
  | Ok _ -> Alcotest.fail "size limit ignored"

(* ---- traceparent ---- *)

let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

let test_traceparent () =
  (match T.Traceparent.parse tp with
  | Some t ->
      Alcotest.(check string) "trace id" "4bf92f3577b34da6a3ce929d0e0e4736" t.trace_id;
      Alcotest.(check string) "parent id" "00f067aa0ba902b7" t.parent_id;
      Alcotest.(check int) "flags" 1 t.flags;
      Alcotest.(check bool) "sampled" true (T.Traceparent.sampled t);
      Alcotest.(check string) "roundtrip" tp (T.Traceparent.to_string t)
  | None -> Alcotest.fail "valid traceparent rejected");
  Alcotest.(check bool) "OWS trimmed" true (T.Traceparent.parse ("  " ^ tp ^ "\t") <> None);
  (match
     T.Traceparent.parse
       "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00-what-the-future-holds"
   with
  | Some t ->
      Alcotest.(check bool) "future version: not sampled" false (T.Traceparent.sampled t)
  | None -> Alcotest.fail "future version with extra fields rejected");
  List.iter
    (fun (why, s) -> Alcotest.(check bool) why true (T.Traceparent.parse s = None))
    [
      ("uppercase hex", "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01");
      ("zero trace id", "00-00000000000000000000000000000000-00f067aa0ba902b7-01");
      ("zero parent id", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01");
      ("version ff", "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
      ("v00 extra data", tp ^ "-extra");
      ( "future version w/o dash",
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x" );
      ("short", "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01");
      ("bad separator", "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
      ("non-hex flags", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g");
      ("empty", "");
    ]

(* ---- OTLP JSON ---- *)

let test_otlp_json () =
  let span =
    {
      J.trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
      span_id = "00f067aa0ba902b7";
      parent_span_id = Some "1111111111111111";
      name = "haltsql.verify";
      kind = J.Server;
      start_ns = 1_700_000_000_000_000_000L;
      end_ns = 1_700_000_000_000_500_000L;
      attributes =
        [
          ("a", J.Int 5);
          ("b", J.Bool true);
          ("c", J.Strings [ "x"; "y" ]);
          ("d", J.Float 1.5);
        ];
      status = J.Error "boom";
      flags = 1;
    }
  in
  let j =
    J.traces_request
      ~resource:[ ("service.name", J.String "svc") ]
      ~scope:{ J.scope_name = "haltsql"; scope_version = "1" }
      [ span ]
  in
  Alcotest.(check string)
    "exact encoding"
    {|{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"svc"}}]},"scopeSpans":[{"scope":{"name":"haltsql","version":"1"},"spans":[{"traceId":"4bf92f3577b34da6a3ce929d0e0e4736","spanId":"00f067aa0ba902b7","parentSpanId":"1111111111111111","flags":1,"name":"haltsql.verify","kind":2,"startTimeUnixNano":"1700000000000000000","endTimeUnixNano":"1700000000000500000","attributes":[{"key":"a","value":{"intValue":"5"}},{"key":"b","value":{"boolValue":true}},{"key":"c","value":{"arrayValue":{"values":[{"stringValue":"x"},{"stringValue":"y"}]}}},{"key":"d","value":{"doubleValue":1.5}}],"status":{"code":2,"message":"boom"}}]}]}]}|}
    (Yojson.Safe.to_string j);
  let m =
    J.metrics_request ~resource:[]
      ~scope:{ J.scope_name = "s"; scope_version = "1" }
      ~start_ns:1L ~time_ns:2L
      [
        J.Sum
          {
            name = "c";
            description = "d";
            unit_ = "1";
            points = [ ([ ("k", J.String "v") ], 3) ];
          };
        J.Histogram
          {
            name = "h";
            description = "";
            unit_ = "s";
            bounds = [| 0.5 |];
            points =
              [
                {
                  J.h_attrs = [];
                  bucket_counts = [| 1; 2 |];
                  h_sum = 2.5;
                  h_count = 3;
                  h_min = Some 0.1;
                  h_max = Some 1.2;
                };
              ];
          };
      ]
  in
  Alcotest.(check string)
    "metrics encoding"
    {|{"resourceMetrics":[{"resource":{"attributes":[]},"scopeMetrics":[{"scope":{"name":"s","version":"1"},"metrics":[{"name":"c","description":"d","unit":"1","sum":{"dataPoints":[{"attributes":[{"key":"k","value":{"stringValue":"v"}}],"startTimeUnixNano":"1","timeUnixNano":"2","asInt":"3"}],"aggregationTemporality":2,"isMonotonic":true}},{"name":"h","description":"","unit":"s","histogram":{"dataPoints":[{"attributes":[],"startTimeUnixNano":"1","timeUnixNano":"2","count":"3","sum":2.5,"bucketCounts":["1","2"],"explicitBounds":[0.5],"min":0.1,"max":1.2}],"aggregationTemporality":2}}]}]}]}|}
    (Yojson.Safe.to_string m)

let test_retry_after () =
  Alcotest.(check (option (float 0.001)))
    "delta" (Some 120.)
    (E.parse_retry_after ~now:0. "120");
  (* Sun, 06 Nov 1994 08:49:37 GMT = 784111777 *)
  Alcotest.(check (option (float 0.001)))
    "http-date" (Some 7.)
    (E.parse_retry_after ~now:784111770. "Sun, 06 Nov 1994 08:49:37 GMT");
  Alcotest.(check (option (float 0.001)))
    "past date" (Some 0.)
    (E.parse_retry_after ~now:784111800. "Sun, 06 Nov 1994 08:49:37 GMT");
  Alcotest.(check (option (float 0.001)))
    "garbage" None
    (E.parse_retry_after ~now:0. "soon");
  Alcotest.(check int) "random hex length" 32 (String.length (E.random_hex 16))

(* ---- exporter against a fake collector ---- *)

let otlp ?(headers = []) ?(timeout = 2) ?(interval = 60) ?(traces = true)
    ?(metrics = true) (f : Fake_http.t) =
  {
    Config.otlp_endpoint = Printf.sprintf "http://127.0.0.1:%d/" f.port;
    otlp_headers = headers;
    service_name = "haltsql-test";
    otlp_traces = traces;
    otlp_metrics = metrics;
    export_interval_seconds = interval;
    timeout_seconds = timeout;
  }

let ok_handler _ _ = Fake_http.respond "{}"

let create ?max_queue ?max_batch ?gzip ?max_retries ?(base_backoff = 0.01) c =
  match
    E.create ?max_queue ?max_batch ?gzip ?max_retries ~base_backoff
      ~service_version:"9.9.9" c
  with
  | Ok e -> e
  | Error m -> Alcotest.fail m

let reason code = { Core.Reason.code; message = "m"; loc = None; rule = "r"; hint = None }

let verdict =
  {
    Core.Verdict.allowed = false;
    reasons = [ reason Core.Reason.E_TABLE_DENIED ];
    shadow_reasons = [ reason Core.Reason.E_LIMIT_REQUIRED ];
    policy_name = "shop";
    policy_version = "v7";
    statement_kind = Some "select";
    tables = [];
    columns = [];
    bind_params = [];
    fingerprint = None;
    sql_sha256 = "ab12" ^ String.make 60 'c';
    elapsed_us = 42;
  }

let spans_of body =
  member "resourceSpans" body |> nth 0 |> member "scopeSpans" |> nth 0 |> member "spans"
  |> list

let traces_posts (f : Fake_http.t) =
  List.filter (fun (r, _) -> Fake_http.path r = "/v1/traces") f.requests

let metrics_posts (f : Fake_http.t) =
  List.filter (fun (r, _) -> Fake_http.path r = "/v1/metrics") f.requests

let test_verify_span () =
  run
    (let f = Fake_http.start ok_handler in
     let e =
       create
         (otlp ~metrics:false
            ~headers:[ ("authorization", "Bearer s3cr3t"); ("x-tenant", "acme") ]
            f)
     in
     let sp = E.start_verify e ~traceparent:tp () in
     Alcotest.(check string)
       "joins incoming trace" "4bf92f3577b34da6a3ce929d0e0e4736" (E.span_trace_id sp);
     let out = T.Traceparent.to_string (E.traceparent sp) in
     Alcotest.(check bool)
       "propagates new span id" true
       (String.sub out 0 36 = "00-4bf92f3577b34da6a3ce929d0e0e4736-"
       && String.sub out 36 16 <> "00f067aa0ba902b7");
     E.end_verify e sp verdict;
     E.flush e >|= fun () ->
     f.stop ();
     match traces_posts f with
     | [ (req, body) ] ->
         Alcotest.(check (option string))
           "content-type" (Some "application/json")
           (Fake_http.header req "content-type");
         Alcotest.(check (option string))
           "custom header" (Some "Bearer s3cr3t")
           (Fake_http.header req "authorization");
         Alcotest.(check (option string))
           "second header" (Some "acme")
           (Fake_http.header req "x-tenant");
         Alcotest.(check (option string))
           "no gzip" None
           (Fake_http.header req "content-encoding");
         let j = Yojson.Safe.from_string body in
         let res =
           member "resourceSpans" j |> nth 0 |> member "resource" |> member "attributes"
         in
         Alcotest.(check string)
           "service.name" "haltsql-test"
           (attr "service.name" res |> member "stringValue" |> str);
         Alcotest.(check string)
           "service.version" "9.9.9"
           (attr "service.version" res |> member "stringValue" |> str);
         let s =
           match spans_of j with
           | [ s ] -> s
           | l -> Alcotest.failf "%d spans" (List.length l)
         in
         Alcotest.(check string)
           "traceId" "4bf92f3577b34da6a3ce929d0e0e4736"
           (member "traceId" s |> str);
         Alcotest.(check string)
           "parentSpanId" "00f067aa0ba902b7"
           (member "parentSpanId" s |> str);
         Alcotest.(check string) "spanId" (E.span_id sp) (member "spanId" s |> str);
         Alcotest.(check int)
           "16 hex span id" 16
           (String.length (member "spanId" s |> str));
         Alcotest.(check string) "name" "haltsql.verify" (member "name" s |> str);
         Alcotest.(check bool) "kind SERVER" true (member "kind" s = `Int 2);
         Alcotest.(check bool)
           "status OK" true
           (member "status" s = `Assoc [ ("code", `Int 1) ]);
         let a = member "attributes" s in
         Alcotest.(check string)
           "policy" "shop"
           (attr "haltsql.policy" a |> member "stringValue" |> str);
         Alcotest.(check string)
           "policy version" "v7"
           (attr "haltsql.policy_version" a |> member "stringValue" |> str);
         Alcotest.(check bool)
           "allowed" true
           (attr "haltsql.allowed" a = `Assoc [ ("boolValue", `Bool false) ]);
         Alcotest.(check bool)
           "shadow" true
           (attr "haltsql.shadow" a = `Assoc [ ("boolValue", `Bool true) ]);
         Alcotest.(check (list string))
           "reason codes"
           [ "E_TABLE_DENIED"; "E_LIMIT_REQUIRED" ]
           (attr "haltsql.reason_codes" a |> member "arrayValue" |> member "values"
          |> list
           |> List.map (fun v -> member "stringValue" v |> str));
         Alcotest.(check string)
           "statement hash" verdict.sql_sha256
           (attr "db.statement.sha256" a |> member "stringValue" |> str);
         Alcotest.(check bool)
           "no db.statement" false
           (List.exists (fun x -> member "key" x = `String "db.statement") (list a));
         let st = E.stats e in
         Alcotest.(check int) "exported" 1 st.spans_exported;
         Alcotest.(check int) "batches" 1 st.batches_sent
     | l -> Alcotest.failf "expected 1 traces POST, got %d" (List.length l))

let test_batching () =
  run
    (let f = Fake_http.start ok_handler in
     let e = create ~max_batch:3 (otlp ~metrics:false f) in
     for i = 1 to 7 do
       E.end_span e (E.start_span e (Printf.sprintf "s%d" i))
     done;
     E.flush e >|= fun () ->
     f.stop ();
     let sizes =
       List.map
         (fun (_, b) -> List.length (spans_of (Yojson.Safe.from_string b)))
         (traces_posts f)
     in
     Alcotest.(check (list int)) "batch sizes" [ 3; 3; 1 ] sizes;
     let names =
       List.concat_map
         (fun (_, b) ->
           List.map
             (fun s -> member "name" s |> str)
             (spans_of (Yojson.Safe.from_string b)))
         (traces_posts f)
     in
     Alcotest.(check (list string))
       "order kept"
       [ "s1"; "s2"; "s3"; "s4"; "s5"; "s6"; "s7" ]
       names;
     Alcotest.(check int) "exported" 7 (E.stats e).spans_exported)

let test_background_export () =
  run
    (let f = Fake_http.start ok_handler in
     let e = create ~max_batch:2 (otlp ~metrics:false ~interval:3600 f) in
     E.start e;
     E.end_span e (E.start_span e "a");
     E.end_span e (E.start_span e "b");
     (* A full batch wakes the loop even though the interval is an hour. *)
     let rec wait n =
       if traces_posts f <> [] || n = 0 then Lwt.return_unit
       else Lwt_unix.sleep 0.05 >>= fun () -> wait (n - 1)
     in
     wait 60 >>= fun () ->
     Alcotest.(check int) "posted without flush" 1 (List.length (traces_posts f));
     E.shutdown e >|= fun () -> f.stop ())

let test_queue_bound () =
  run
    (let f = Fake_http.start ok_handler in
     let e = create ~max_queue:5 ~max_batch:100 (otlp ~metrics:false f) in
     let t0 = Unix.gettimeofday () in
     for _ = 1 to 8 do
       E.end_span e (E.start_span e "x")
     done;
     Alcotest.(check bool) "end_span never blocks" true (Unix.gettimeofday () -. t0 < 0.5);
     let st = E.stats e in
     Alcotest.(check int) "queued" 5 st.spans_queued;
     Alcotest.(check int) "dropped" 3 st.spans_dropped;
     E.flush e >|= fun () ->
     f.stop ();
     Alcotest.(check int) "exported" 5 (E.stats e).spans_exported)

let test_unsampled () =
  run
    (let f = Fake_http.start ok_handler in
     let e = create (otlp ~metrics:false f) in
     let sp =
       E.start_verify e
         ~traceparent:"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00" ()
     in
     E.end_verify e sp verdict;
     let sp2 = E.start_verify e ~traceparent:"garbage" () in
     Alcotest.(check bool)
       "invalid header starts a new trace" true
       (E.span_trace_id sp2 <> "4bf92f3577b34da6a3ce929d0e0e4736");
     E.end_verify e sp2 verdict;
     E.flush e >|= fun () ->
     f.stop ();
     match traces_posts f with
     | [ (_, b) ] ->
         Alcotest.(check int)
           "only the sampled span" 1
           (List.length (spans_of (Yojson.Safe.from_string b)))
     | l -> Alcotest.failf "%d posts" (List.length l))

let test_retry_503 () =
  run
    (let n = ref 0 in
     let f =
       Fake_http.start (fun _ _ ->
           incr n;
           if !n <= 2 then
             Fake_http.respond ~status:503 ~headers:[ ("retry-after", "0") ] "busy"
           else Fake_http.respond "{}")
     in
     let e = create ~max_retries:5 (otlp ~metrics:false f) in
     E.end_span e (E.start_span e "x");
     E.flush e >|= fun () ->
     f.stop ();
     Alcotest.(check int) "3 attempts" 3 (List.length (traces_posts f));
     let st = E.stats e in
     Alcotest.(check int) "retries" 2 st.retries;
     Alcotest.(check int) "exported" 1 st.spans_exported;
     Alcotest.(check int) "no failure" 0 st.export_failures)

let test_retry_after_429 () =
  run
    (let n = ref 0 in
     let f =
       Fake_http.start (fun _ _ ->
           incr n;
           if !n = 1 then
             Fake_http.respond ~status:429 ~headers:[ ("retry-after", "1") ] "slow down"
           else Fake_http.respond "{}")
     in
     let e = create ~max_retries:2 (otlp ~metrics:false f) in
     E.end_span e (E.start_span e "x");
     let t0 = Unix.gettimeofday () in
     E.flush e >|= fun () ->
     let dt = Unix.gettimeofday () -. t0 in
     f.stop ();
     Alcotest.(check bool)
       (Printf.sprintf "waited Retry-After (%.2fs)" dt)
       true
       (dt >= 0.95 && dt < 3.);
     Alcotest.(check int) "2 attempts" 2 (List.length (traces_posts f));
     Alcotest.(check int) "exported" 1 (E.stats e).spans_exported)

let test_permanent_400 () =
  run
    (let f = Fake_http.start (fun _ _ -> Fake_http.respond ~status:400 "bad") in
     let errors = ref [] in
     let e =
       match
         E.create ~base_backoff:0.01
           ~on_error:(fun m -> errors := m :: !errors)
           (otlp ~metrics:false ~headers:[ ("authorization", "Bearer TOPSECRET") ] f)
       with
       | Ok e -> e
       | Error m -> Alcotest.fail m
     in
     E.end_span e (E.start_span e "x");
     E.end_span e (E.start_span e "y");
     E.flush e >|= fun () ->
     f.stop ();
     Alcotest.(check int) "no retry" 1 (List.length (traces_posts f));
     let st = E.stats e in
     Alcotest.(check int) "failures" 1 st.export_failures;
     Alcotest.(check int) "dropped" 2 st.spans_dropped;
     Alcotest.(check (list string))
       "error message"
       [ "otlp traces export to /v1/traces failed: HTTP 400" ]
       !errors;
     Alcotest.(check bool)
       "header value never logged" false
       (List.exists (fun m -> contains m "TOPSECRET") !errors))

let test_timeout () =
  run
    (let f =
       Fake_http.start (fun _ _ -> Lwt_unix.sleep 3. >>= fun () -> Fake_http.respond "{}")
     in
     let e = create ~max_retries:0 (otlp ~metrics:false ~timeout:1 f) in
     E.end_span e (E.start_span e "x");
     let t0 = Unix.gettimeofday () in
     E.flush e >|= fun () ->
     let dt = Unix.gettimeofday () -. t0 in
     f.stop ();
     Alcotest.(check bool)
       (Printf.sprintf "gave up after the timeout (%.2fs)" dt)
       true
       (dt >= 0.9 && dt < 2.5);
     Alcotest.(check int) "failure" 1 (E.stats e).export_failures)

let test_connection_refused () =
  run
    (let f = Fake_http.start ok_handler in
     f.stop ();
     Lwt_unix.sleep 0.1 >>= fun () ->
     let e = create ~max_retries:1 (otlp ~metrics:false f) in
     E.end_span e (E.start_span e "x");
     E.flush e >|= fun () ->
     let st = E.stats e in
     Alcotest.(check int) "retried once" 1 st.retries;
     Alcotest.(check int) "failed" 1 st.export_failures;
     Alcotest.(check int) "dropped" 1 st.spans_dropped)

let test_gzip_export () =
  run
    (let f = Fake_http.start ok_handler in
     let e = create ~gzip:true (otlp ~metrics:false f) in
     E.end_span e (E.start_span e "zipped");
     E.flush e >|= fun () ->
     f.stop ();
     match traces_posts f with
     | [ (req, body) ] -> (
         Alcotest.(check (option string))
           "content-encoding" (Some "gzip")
           (Fake_http.header req "content-encoding");
         match T.Gzip.decompress body with
         | Ok json ->
             let s = List.hd (spans_of (Yojson.Safe.from_string json)) in
             Alcotest.(check string) "span name" "zipped" (member "name" s |> str)
         | Error m -> Alcotest.failf "bad gzip body: %s" m)
     | l -> Alcotest.failf "%d posts" (List.length l))

let find_metric name body =
  member "resourceMetrics" body |> nth 0 |> member "scopeMetrics" |> nth 0
  |> member "metrics" |> list
  |> List.find (fun m -> member "name" m = `String name)

let test_metrics_export () =
  run
    (let f = Fake_http.start ok_handler in
     let e = create (otlp ~traces:false f) in
     E.observe_verify e ~policy:"shop" ~result:"allowed" ~codes:[] ~seconds:0.0003;
     E.observe_verify e ~policy:"shop" ~result:"denied" ~codes:[ "E_TABLE_DENIED" ]
       ~seconds:2.0;
     E.observe_verify e ~policy:"shop" ~result:"denied"
       ~codes:[ "E_TABLE_DENIED"; "E_LIMIT_REQUIRED" ]
       ~seconds:0.0001;
     E.observe_http e ~route:"/v1/verify" ~status:200;
     E.observe_reload e ~ok:false;
     E.observe_audit_error e;
     E.set_policies_loaded e 3;
     E.flush e >|= fun () ->
     f.stop ();
     Alcotest.(check int) "no traces when disabled" 0 (List.length (traces_posts f));
     match metrics_posts f with
     | [ (_, body) ] ->
         let j = Yojson.Safe.from_string body in
         let vt = find_metric "haltsql_verify_total" j in
         let sum = member "sum" vt in
         Alcotest.(check bool) "monotonic" true (member "isMonotonic" sum = `Bool true);
         Alcotest.(check bool)
           "cumulative" true
           (member "aggregationTemporality" sum = `Int 2);
         let pts =
           member "dataPoints" sum |> list
           |> List.map (fun p ->
               ( attr "result" (member "attributes" p) |> member "stringValue" |> str,
                 member "asInt" p |> str ))
         in
         Alcotest.(check (list (pair string string)))
           "verify_total points"
           [ ("allowed", "1"); ("denied", "2") ]
           pts;
         let reasons =
           member "sum" (find_metric "haltsql_reasons_total" j)
           |> member "dataPoints" |> list
           |> List.map (fun p ->
               ( attr "code" (member "attributes" p) |> member "stringValue" |> str,
                 member "asInt" p |> str ))
         in
         Alcotest.(check (list (pair string string)))
           "reasons"
           [ ("E_LIMIT_REQUIRED", "1"); ("E_TABLE_DENIED", "2") ]
           reasons;
         let h =
           member "histogram" (find_metric "haltsql_verify_duration_seconds" j)
           |> member "dataPoints" |> nth 0
         in
         Alcotest.(check string) "hist count" "3" (member "count" h |> str);
         let counts =
           member "bucketCounts" h |> list |> List.map (fun c -> int_of_string (str c))
         in
         Alcotest.(check int) "bucket count length" 14 (List.length counts);
         Alcotest.(check (list int))
           "per-bucket counts"
           [ 1; 0; 1; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 1 ]
           counts;
         Alcotest.(check int)
           "bounds" 13
           (List.length (member "explicitBounds" h |> list));
         Alcotest.(check bool) "max" true (member "max" h = `Float 2.0);
         let g =
           member "gauge" (find_metric "haltsql_policies_loaded" j)
           |> member "dataPoints" |> nth 0
         in
         Alcotest.(check bool) "gauge" true (member "asDouble" g = `Float 3.0);
         let http =
           member "sum" (find_metric "haltsql_http_requests_total" j)
           |> member "dataPoints" |> nth 0
         in
         Alcotest.(check string)
           "http status label" "200"
           (attr "status" (member "attributes" http) |> member "stringValue" |> str);
         ignore (find_metric "haltsql_policy_reload_total" j);
         ignore (find_metric "haltsql_audit_errors_total" j);
         ignore (find_metric "haltsql_otlp_spans_dropped_total" j);
         Alcotest.(check int) "metric exports" 1 (E.stats e).metric_exports
     | l -> Alcotest.failf "%d metrics posts" (List.length l))

let test_noop () =
  run
    (let e = E.noop in
     Alcotest.(check bool) "disabled" false (E.enabled e);
     let sp = E.start_verify e ~traceparent:tp () in
     E.end_verify e sp verdict;
     E.observe_verify e ~policy:"p" ~result:"allowed" ~codes:[] ~seconds:0.1;
     Alcotest.(check int) "no metrics" 0 (List.length (E.metrics_snapshot e));
     E.start e;
     E.flush e >>= fun () ->
     E.shutdown e >|= fun () ->
     Alcotest.(check int) "nothing queued" 0 (E.stats e).spans_queued);
  match E.of_config None with
  | Ok e -> Alcotest.(check bool) "of_config None" false (E.enabled e)
  | Error m -> Alcotest.fail m

let test_bad_endpoint () =
  let c =
    {
      Config.otlp_endpoint = "ftp://collector";
      otlp_headers = [];
      service_name = "x";
      otlp_traces = true;
      otlp_metrics = true;
      export_interval_seconds = 1;
      timeout_seconds = 1;
    }
  in
  match E.create c with
  | Error m ->
      Alcotest.(check string)
        "message" "telemetry: otlp endpoint must be an http(s) URL" m
  | Ok _ -> Alcotest.fail "ftp endpoint accepted"

let () =
  Alcotest.run "telemetry"
    [
      ( "gzip",
        [
          Alcotest.test_case "crc32" `Quick test_crc32;
          Alcotest.test_case "roundtrip" `Quick test_gzip_roundtrip;
          Alcotest.test_case "python dynamic block" `Quick test_gzip_python;
          Alcotest.test_case "corrupt input" `Quick test_gzip_corrupt;
        ] );
      ("traceparent", [ Alcotest.test_case "parse" `Quick test_traceparent ]);
      ( "encoding",
        [
          Alcotest.test_case "otlp json" `Quick test_otlp_json;
          Alcotest.test_case "retry-after" `Quick test_retry_after;
        ] );
      ( "exporter",
        [
          Alcotest.test_case "verify span" `Quick test_verify_span;
          Alcotest.test_case "batching" `Quick test_batching;
          Alcotest.test_case "background export" `Quick test_background_export;
          Alcotest.test_case "queue bound" `Quick test_queue_bound;
          Alcotest.test_case "unsampled parent" `Quick test_unsampled;
          Alcotest.test_case "retry 503" `Quick test_retry_503;
          Alcotest.test_case "retry-after 429" `Quick test_retry_after_429;
          Alcotest.test_case "permanent 400" `Quick test_permanent_400;
          Alcotest.test_case "timeout" `Quick test_timeout;
          Alcotest.test_case "connection refused" `Quick test_connection_refused;
          Alcotest.test_case "gzip" `Quick test_gzip_export;
          Alcotest.test_case "metrics" `Quick test_metrics_export;
          Alcotest.test_case "noop" `Quick test_noop;
          Alcotest.test_case "bad endpoint" `Quick test_bad_endpoint;
        ] );
    ]
