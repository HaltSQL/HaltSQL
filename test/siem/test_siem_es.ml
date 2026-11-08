(* Elasticsearch / OpenSearch audit sink against the real products in Docker:
     19200  Elasticsearch 8 with security on: TLS from a test CA, an API key and
            basic auth (elastic user)
     19201  OpenSearch 2 (security plugin disabled, plain http on loopback)
   Documents are queried back and their hash chain verified; mapping conflicts,
   per-item retries (an ingest pipeline that fails some documents), duplicates,
   bad credentials and the cluster being down are exercised. *)

open Lwt.Infix
open Siem_testlib
module Config = Haltsql_load.Config
module S = Haltsql_siem.Stream_sink
module Http = Haltsql_cloud.Http

let es_image = "docker.elastic.co/elasticsearch/elasticsearch:8.15.3"
let os_image = "opensearchproject/opensearch:2.17.1"
let es_container = "haltsql-siem-es"
let os_container = "haltsql-siem-opensearch"
let es_url = "https://localhost:19200"
let os_url = "http://127.0.0.1:19201"
let elastic_pw = "es-test-" ^ string_of_int (Unix.getpid ()) ^ "-pw"
let run = Lwt_main.run

type es_env = { pki : pki; ctx : Http.ctx; api_key : string }

let basic =
  [ ("Authorization", "Basic " ^ Base64.encode_string ("elastic:" ^ elastic_pw)) ]

let call ?(ctx = Http.default_ctx) ?(headers = []) ?body meth url =
  let headers =
    (if body <> None then [ ("Content-Type", "application/json") ] else []) @ headers
  in
  Http.request ~ctx ~timeout:30. ?body ~headers meth (Uri.of_string url)

let call_ok ?ctx ?headers ?body meth url =
  match run (call ?ctx ?headers ?body meth url) with
  | Ok r when r.status >= 200 && r.status < 300 -> Yojson.Safe.from_string r.body
  | Ok r -> Alcotest.failf "%s -> HTTP %d: %s" url r.status r.body
  | Error e -> Alcotest.failf "%s: %s" url e

let rec member path j =
  match (path, j) with
  | [], j -> j
  | k :: rest, `Assoc kv ->
      member rest (Option.value ~default:`Null (List.assoc_opt k kv))
  | _ -> `Null

let healthy_cluster ?ctx ?headers url () =
  call ?ctx ?headers `GET (url ^ "/_cluster/health") >|= function
  | Ok r when r.status = 200 -> (
      match member [ "status" ] (Yojson.Safe.from_string r.body) with
      | `String ("green" | "yellow") -> true
      | _ -> false)
  | _ -> false

let wait_cluster ?ctx ?headers ~container url =
  Lwt.catch
    (fun () ->
      wait_until ~interval:2.
        ~deadline:(Unix.gettimeofday () +. 240.)
        (container ^ " to start")
        (healthy_cluster ?ctx ?headers url))
    (fun e ->
      Printf.printf "%s logs:\n%s\n%!" container (logs container);
      Lwt.fail e)

let es_env =
  lazy
    (let pki = make_pki () in
     if not (image_present es_image) then failwith ("cannot pull " ^ es_image);
     let e k v = [ "-e"; k ^ "=" ^ v ] in
     run_container ~name:es_container
       ([
          "-p";
          "127.0.0.1:19200:9200";
          "-v";
          pki.dir ^ ":/usr/share/elasticsearch/config/certs:ro";
        ]
       @ e "discovery.type" "single-node"
       @ e "ES_JAVA_OPTS" "-Xms512m -Xmx512m"
       @ e "ELASTIC_PASSWORD" elastic_pw
       @ e "xpack.security.enabled" "true"
       @ e "xpack.security.http.ssl.enabled" "true"
       @ e "xpack.security.http.ssl.key" "certs/server.key"
       @ e "xpack.security.http.ssl.certificate" "certs/server.crt"
       @ e "xpack.security.http.ssl.certificate_authorities" "certs/ca.pem"
       @ e "xpack.security.transport.ssl.enabled" "false"
       @ e "xpack.ml.enabled" "false"
       @ e "cluster.routing.allocation.disk.threshold_enabled" "false")
       es_image [];
     let ctx =
       match run (Http.ctx_of_ca_file pki.ca_file) with
       | Ok c -> c
       | Error m -> failwith m
     in
     run (wait_cluster ~ctx ~headers:basic ~container:es_container es_url);
     let key =
       call_ok ~ctx ~headers:basic `POST
         (es_url ^ "/_security/api_key")
         ~body:{|{"name":"haltsql-siem-test"}|}
     in
     let api_key =
       match member [ "encoded" ] key with `String k -> k | _ -> failwith "no api key"
     in
     { pki; ctx; api_key })

let os_env =
  lazy
    (if not (image_present os_image) then failwith ("cannot pull " ^ os_image);
     let e k v = [ "-e"; k ^ "=" ^ v ] in
     run_container ~name:os_container
       ([ "-p"; "127.0.0.1:19201:9200" ]
       @ e "discovery.type" "single-node"
       @ e "DISABLE_SECURITY_PLUGIN" "true"
       @ e "DISABLE_INSTALL_DEMO_CONFIG" "true"
       @ e "OPENSEARCH_JAVA_OPTS" "-Xms512m -Xmx512m"
       @ e "cluster.routing.allocation.disk.threshold_enabled" "false")
       os_image [];
     run (wait_cluster ~container:os_container os_url))

let es () =
  skip_unless_docker ();
  Lazy.force es_env

let os () =
  skip_unless_docker ();
  Lazy.force os_env

let es_cfg ?(urls = [ es_url ]) ?auth ?ca ?pipeline ?(timeout_ms = 10_000)
    ?(max_records = 10) target =
  {
    Config.es_urls = urls;
    es_target = target;
    es_auth = auth;
    es_pipeline = pipeline;
    es_ca = ca;
    es_timeout_ms = timeout_ms;
    es_batch = batch ~max_records ();
  }

let make_sink ?(on_error = Config.Stream_fail_closed) ?(max_attempts = 3)
    ?(max_buffer = 10_000) cfg =
  match
    run
      (Haltsql_siem.Siem.of_config ~host:"siem-test" ~run_id:"es" ~max_attempts
         ~base_backoff:0.1 ~max_backoff:0.5 ~on_event
         {
           Config.stream = Config.Stream_elasticsearch cfg;
           stream_on_error = on_error;
           max_buffer_records = max_buffer;
           sink_index = 0;
         })
  with
  | Ok s -> s
  | Error e -> Alcotest.failf "of_config: %s" e

let flush_ok s =
  match run (S.flush s) with Ok () -> () | Error e -> Alcotest.failf "flush: %s" e

(* All documents of an index / data stream: (_id, event.original), checking that
   the searchable fields equal the hashed record. *)
let search ?ctx ?(headers = []) url target =
  ignore (call_ok ?ctx ~headers `POST (url ^ "/" ^ target ^ "/_refresh"));
  let r =
    call_ok ?ctx ~headers `POST
      (url ^ "/" ^ target ^ "/_search")
      ~body:{|{"size":1000,"query":{"match_all":{}}}|}
  in
  let hits = match member [ "hits"; "hits" ] r with `List l -> l | _ -> [] in
  ( r,
    List.map
      (fun h ->
        let src = member [ "_source" ] h in
        let original =
          match member [ "event"; "original" ] src with
          | `String l -> l
          | _ -> Alcotest.fail "document without event.original"
        in
        (* the searchable fields are exactly the hashed record's *)
        let sort = function
          | `Assoc kv -> List.sort compare kv
          | _ -> Alcotest.fail "_source is not an object"
        in
        let fields =
          match src with
          | `Assoc kv -> `Assoc (List.filter (fun (k, _) -> k <> "event") kv)
          | j -> j
        in
        Alcotest.(check string)
          "fields match event.original"
          (Yojson.Safe.to_string (`Assoc (sort (Yojson.Safe.from_string original))))
          (Yojson.Safe.to_string (`Assoc (sort fields)));
        ((match member [ "_id" ] h with `String s -> s | _ -> ""), original))
      hits )

let check_docs ~expect docs =
  Alcotest.(check int) "documents stored" expect (List.length docs);
  List.iter
    (fun (id, src) -> Alcotest.(check string) "_id is the record hash" (hash_of src) id)
    docs;
  let chain = link_chain (List.map snd docs) in
  Alcotest.(check int) "linked from genesis" expect (List.length chain);
  Alcotest.(check int) "chain verifies" expect (verify_chain chain)

let python_verify search_response =
  if Lazy.force python3 then begin
    let tmp = Filename.temp_file "haltsql-siem-es" ".json" in
    write_file tmp (Yojson.Safe.to_string search_response);
    let code, out = run_python "verify_chain.py" [ "es"; tmp ] in
    Sys.remove tmp;
    if code <> 0 || not (python_ok out) then Alcotest.failf "verify_chain.py es: %s" out
  end

(* ---- Elasticsearch ---- *)

let test_es_index_api_key () =
  let env = es () in
  events := [];
  let s =
    make_sink
      (es_cfg ~auth:(Config.Es_api_key env.api_key) ~ca:(Config.Pem_inline env.pki.ca_pem)
         (Config.Es_index "haltsql-audit-test"))
  in
  write_n s ~from:0 30;
  flush_ok s;
  Alcotest.(check int) "delivered" 30 (S.stats s).records_delivered;
  let resp, docs = search ~ctx:env.ctx ~headers:basic es_url "haltsql-audit-test" in
  check_docs ~expect:30 docs;
  python_verify resp;
  (match Yojson.Safe.from_string (snd (List.hd docs)) with
  | `Assoc (("@timestamp", `String _) :: _) -> ()
  | _ -> Alcotest.fail "@timestamp is the first field");
  check_no_secret ~secret:env.api_key;
  ignore (run (S.close s))

let test_es_data_stream_basic () =
  let env = es () in
  let s =
    make_sink
      (es_cfg
         ~auth:(Config.Es_basic { username = "elastic"; password = elastic_pw })
         ~ca:(Config.Pem_path env.pki.ca_file) (Config.Es_data_stream "logs-haltsql-test"))
  in
  write_n s ~from:0 8;
  flush_ok s;
  let ds =
    call_ok ~ctx:env.ctx ~headers:basic `GET (es_url ^ "/_data_stream/logs-haltsql-test")
  in
  (match member [ "data_streams" ] ds with
  | `List [ _ ] -> ()
  | _ -> Alcotest.fail "data stream was not created");
  let _, docs = search ~ctx:env.ctx ~headers:basic es_url "logs-haltsql-test" in
  check_docs ~expect:8 docs;
  check_no_secret ~secret:elastic_pw;
  ignore (run (S.close s))

let test_es_duplicates () =
  let env = es () in
  let cfg =
    es_cfg ~auth:(Config.Es_api_key env.api_key) ~ca:(Config.Pem_path env.pki.ca_file)
      (Config.Es_index "haltsql-dup-test")
  in
  let t =
    match run (Haltsql_siem.Es_sink.create cfg) with
    | Ok t -> t
    | Error e -> Alcotest.fail e
  in
  let entries =
    Array.init 5 (fun i ->
        let line, hash =
          Haltsql_cloud.Audit_chain.seal
            ~prev:
              (if i = 0 then Haltsql_cloud.Audit_chain.genesis else String.make 64 'a')
            (record i [])
        in
        { S.line; hash })
  in
  let all_delivered = function
    | Ok r -> Array.for_all (function S.Delivered -> true | _ -> false) r
    | Error _ -> false
  in
  Alcotest.(check bool)
    "first delivery" true
    (all_delivered (run (Haltsql_siem.Es_sink.deliver t entries)));
  (* a retry after a lost response: every item answers 409, counted as delivered *)
  Alcotest.(check bool)
    "redelivery is idempotent" true
    (all_delivered (run (Haltsql_siem.Es_sink.deliver t entries)));
  let _, docs = search ~ctx:env.ctx ~headers:basic es_url "haltsql-dup-test" in
  Alcotest.(check int) "stored once" 5 (List.length docs)

let verify_chain_from_any src =
  match Haltsql_cloud.Audit_chain.verify_lines ~initial_prev:None [ src ] with
  | Ok n -> n
  | Error (_, m) -> Alcotest.failf "stored record is not intact: %s" m

let test_es_mapping_conflict () =
  let env = es () in
  ignore
    (call_ok ~ctx:env.ctx ~headers:basic `PUT
       (es_url ^ "/haltsql-mapping-test")
       ~body:{|{"mappings":{"properties":{"x":{"type":"long"}}}}|});
  events := [];
  let s =
    make_sink
      (es_cfg ~auth:(Config.Es_api_key env.api_key) ~ca:(Config.Pem_path env.pki.ca_file)
         (Config.Es_index "haltsql-mapping-test"))
  in
  let bad i = i = 2 || i = 5 || i = 8 in
  write_n s ~from:0 10 ~extra:(fun i ->
      [ ("x", if bad i then `String "not-a-number" else `Int i) ]);
  flush_ok s;
  let st = S.stats s in
  Alcotest.(check int) "delivered" 7 st.records_delivered;
  Alcotest.(check (list (pair string int)))
    "dropped with a metric"
    [ ("mapping", 3) ]
    st.records_dropped;
  Alcotest.(check int)
    "logged, never silent" 3
    (List.length
       (List.filter
          (fun e ->
            let sub =
              "rejected by the destination (mapping: document_parsing_exception)"
            in
            let n = String.length sub in
            let rec go i =
              i + n <= String.length e && (String.sub e i n = sub || go (i + 1))
            in
            go 0)
          !events));
  Alcotest.(check bool)
    "metric line" true
    (List.mem
       {|haltsql_audit_stream_sink_records_dropped_total{sink="elasticsearch://localhost:19200/haltsql-mapping-test",type="elasticsearch",reason="mapping"} 3|}
       (String.split_on_char '\n' (Haltsql_siem.Siem.metrics_text [ s ])));
  let _, docs = search ~ctx:env.ctx ~headers:basic es_url "haltsql-mapping-test" in
  Alcotest.(check int) "stored" 7 (List.length docs);
  (* every stored record is intact; the dropped ones show as gaps in the links *)
  List.iter (fun (_, src) -> ignore (verify_chain_from_any src)) docs;
  Alcotest.(check int)
    "links stop at the first dropped record" 2
    (List.length (link_chain (List.map snd docs)));
  ignore (run (S.close s))

let put_pipeline env body =
  ignore
    (call_ok ~ctx:env.ctx ~headers:basic `PUT
       (es_url ^ "/_ingest/pipeline/haltsql-flaky")
       ~body)

let test_es_partial_retry () =
  let env = es () in
  (* documents with x = "retry" fail in the ingest pipeline until it is fixed *)
  put_pipeline env
    {|{"processors":[{"fail":{"if":"ctx.x == 'retry'","message":"not now"}}]}|};
  let s =
    make_sink ~max_attempts:2
      (es_cfg ~auth:(Config.Es_api_key env.api_key) ~ca:(Config.Pem_path env.pki.ca_file)
         ~pipeline:"haltsql-flaky" (Config.Es_index "haltsql-retry-test"))
  in
  write_n s ~from:0 6 ~extra:(fun i ->
      [ ("x", `String (if i = 1 || i = 4 then "retry" else "ok")) ]);
  Alcotest.(check bool)
    "flush reports the failure" true
    (Result.is_error (run (S.flush s)));
  let st = S.stats s in
  Alcotest.(check int) "the others were delivered" 4 st.records_delivered;
  Alcotest.(check int) "failed items kept" 2 st.buffered_records;
  Alcotest.(check int) "retried" 1 st.retries;
  Alcotest.(check (list (pair string int))) "nothing dropped" [] st.records_dropped;
  put_pipeline env {|{"processors":[]}|};
  flush_ok s;
  let _, docs = search ~ctx:env.ctx ~headers:basic es_url "haltsql-retry-test" in
  check_docs ~expect:6 docs;
  ignore (run (S.close s))

let test_es_bad_api_key () =
  let env = es () in
  events := [];
  let bogus = Base64.encode_string "id:not-the-key" in
  let s =
    make_sink ~max_attempts:1
      (es_cfg ~auth:(Config.Es_api_key bogus) ~ca:(Config.Pem_path env.pki.ca_file)
         (Config.Es_index "haltsql-audit-test"))
  in
  write_n s ~from:0 1;
  (match run (S.flush s) with
  | Ok () -> Alcotest.fail "accepted a bogus API key"
  | Error e ->
      Alcotest.(check bool)
        "401" true
        (let sub = "HTTP 401" in
         let n = String.length sub in
         let rec go i =
           i + n <= String.length e && (String.sub e i n = sub || go (i + 1))
         in
         go 0));
  Alcotest.(check bool) "unhealthy" false (S.healthy s);
  check_no_secret ~secret:bogus;
  ignore (run (S.close s))

let test_es_untrusted_ca () =
  let env = es () in
  let s =
    make_sink ~max_attempts:1
      (es_cfg ~auth:(Config.Es_api_key env.api_key)
         ~ca:(Config.Pem_inline env.pki.rogue_ca_pem)
         (Config.Es_index "haltsql-audit-test"))
  in
  write_n s ~from:0 1;
  Alcotest.(check bool)
    "TLS verification fails closed" true
    (Result.is_error (run (S.flush s)));
  ignore (run (S.close s))

let pause c = ignore (docker_ok [ "pause"; c ])
let unpause c = ignore (docker_ok [ "unpause"; c ])

let test_es_down on_error () =
  let env = es () in
  let index = "haltsql-down-test" in
  let s =
    make_sink ~on_error ~max_attempts:2
      (es_cfg ~auth:(Config.Es_api_key env.api_key) ~ca:(Config.Pem_path env.pki.ca_file)
         ~timeout_ms:2000 (Config.Es_index index))
  in
  let before =
    match
      run (call ~ctx:env.ctx ~headers:basic `GET (es_url ^ "/" ^ index ^ "/_count"))
    with
    | Ok r when r.status = 200 -> (
        match member [ "count" ] (Yojson.Safe.from_string r.body) with
        | `Int n -> n
        | _ -> 0)
    | _ -> 0
  in
  write_n s ~from:0 3;
  flush_ok s;
  pause es_container;
  Fun.protect
    ~finally:(fun () -> unpause es_container)
    (fun () ->
      write_n s ~from:3 1;
      Alcotest.(check bool)
        "flush fails while the cluster is down" true
        (Result.is_error (run (S.flush s)));
      match on_error with
      | Config.Stream_fail_closed ->
          Alcotest.(check bool) "unhealthy" false (S.healthy s);
          Alcotest.(check bool)
            "writes refused" true
            (Result.is_error (S.write s (record 50 [])))
      | Config.Stream_buffer ->
          Alcotest.(check bool) "healthy" true (S.healthy s);
          write_n s ~from:4 5
      | Config.Stream_drop ->
          Alcotest.(check bool) "healthy" true (S.healthy s);
          write_n s ~from:4 5;
          Alcotest.(check (list (pair string int)))
            "dropped and counted"
            [ ("on_error_drop", 5) ]
            (S.stats s).records_dropped);
  run (wait_cluster ~ctx:env.ctx ~headers:basic ~container:es_container es_url);
  (* a just-unpaused node can be slow to answer its first requests: the sink
     recovers on a later attempt *)
  run
    (wait_until ~interval:0.5
       ~deadline:(Unix.gettimeofday () +. 60.)
       "the sink to recover"
       (fun () -> S.flush s >|= Result.is_ok));
  Alcotest.(check bool) "healthy again" true (S.healthy s);
  let expect = match on_error with Config.Stream_buffer -> 9 | _ -> 4 in
  Alcotest.(check int) "buffer empty" 0 (S.stats s).buffered_records;
  ignore (run (S.close s));
  let _, docs = search ~ctx:env.ctx ~headers:basic es_url index in
  Alcotest.(check int) "documents stored" (before + expect) (List.length docs);
  ignore (call_ok ~ctx:env.ctx ~headers:basic `DELETE (es_url ^ "/" ^ index))

(* ---- OpenSearch ---- *)

let test_os_index () =
  os ();
  let s = make_sink (es_cfg ~urls:[ os_url ] (Config.Es_index "haltsql-audit-os")) in
  write_n s ~from:0 20;
  flush_ok s;
  let resp, docs = search os_url "haltsql-audit-os" in
  check_docs ~expect:20 docs;
  python_verify resp;
  ignore (run (S.close s))

let test_os_data_stream () =
  os ();
  ignore
    (call_ok `PUT
       (os_url ^ "/_index_template/haltsql-ds")
       ~body:{|{"index_patterns":["haltsql-ds-*"],"data_stream":{},"priority":100}|});
  let s =
    make_sink (es_cfg ~urls:[ os_url ] (Config.Es_data_stream "haltsql-ds-audit"))
  in
  write_n s ~from:0 6;
  flush_ok s;
  let _, docs = search os_url "haltsql-ds-audit" in
  check_docs ~expect:6 docs;
  ignore (run (S.close s))

let test_os_mapping_conflict () =
  os ();
  ignore
    (call_ok `PUT
       (os_url ^ "/haltsql-mapping-os")
       ~body:{|{"mappings":{"properties":{"x":{"type":"long"}}}}|});
  let s = make_sink (es_cfg ~urls:[ os_url ] (Config.Es_index "haltsql-mapping-os")) in
  write_n s ~from:0 5 ~extra:(fun i ->
      [ ("x", if i = 3 then `String "nope" else `Int i) ]);
  flush_ok s;
  Alcotest.(check (list (pair string int)))
    "dropped"
    [ ("mapping", 1) ]
    (S.stats s).records_dropped;
  let _, docs = search os_url "haltsql-mapping-os" in
  Alcotest.(check int) "stored" 4 (List.length docs);
  ignore (run (S.close s))

let test_os_restart_buffer () =
  os ();
  let s =
    make_sink ~on_error:Config.Stream_buffer
      (es_cfg ~urls:[ os_url ] ~timeout_ms:2000 (Config.Es_index "haltsql-restart-os"))
  in
  S.start s;
  write_n s ~from:0 5;
  run
    (wait_until ~interval:0.2
       ~deadline:(Unix.gettimeofday () +. 30.)
       "first delivery"
       (fun () -> Lwt.return ((S.stats s).records_delivered = 5)));
  ignore (docker_ok [ "stop"; "-t"; "10"; os_container ]);
  write_n s ~from:5 10;
  run
    (wait_until ~interval:0.2
       ~deadline:(Unix.gettimeofday () +. 30.)
       "the outage to be noticed"
       (fun () -> Lwt.return (not (S.stats s).delivering)));
  Alcotest.(check bool) "healthy while buffering" true (S.healthy s);
  ignore (docker_ok [ "start"; os_container ]);
  run (wait_cluster ~container:os_container os_url);
  run
    (wait_until ~interval:0.5
       ~deadline:(Unix.gettimeofday () +. 60.)
       "buffer drained"
       (fun () -> Lwt.return ((S.stats s).buffered_records = 0)));
  Alcotest.(check (result unit string)) "close" (Ok ()) (run (S.close s));
  let _, docs = search os_url "haltsql-restart-os" in
  check_docs ~expect:15 docs

let () =
  Alcotest.run "siem-es"
    [
      ( "elasticsearch",
        [
          Alcotest.test_case "index, API key, TLS: query back and verify" `Slow
            test_es_index_api_key;
          Alcotest.test_case "data stream, basic auth" `Slow test_es_data_stream_basic;
          Alcotest.test_case "redelivery is idempotent (409)" `Slow test_es_duplicates;
          Alcotest.test_case "mapping conflict: partial failure" `Slow
            test_es_mapping_conflict;
          Alcotest.test_case "failed items retried individually" `Slow
            test_es_partial_retry;
          Alcotest.test_case "bad API key fails closed" `Slow test_es_bad_api_key;
          Alcotest.test_case "untrusted CA fails closed" `Slow test_es_untrusted_ca;
          Alcotest.test_case "cluster down, on_error=fail_closed" `Slow
            (test_es_down Config.Stream_fail_closed);
          Alcotest.test_case "cluster down, on_error=buffer" `Slow
            (test_es_down Config.Stream_buffer);
          Alcotest.test_case "cluster down, on_error=drop" `Slow
            (test_es_down Config.Stream_drop);
        ] );
      ( "opensearch",
        [
          Alcotest.test_case "index: query back and verify" `Slow test_os_index;
          Alcotest.test_case "data stream" `Slow test_os_data_stream;
          Alcotest.test_case "mapping conflict" `Slow test_os_mapping_conflict;
          Alcotest.test_case "node restart, on_error=buffer" `Slow test_os_restart_buffer;
        ] );
    ]
