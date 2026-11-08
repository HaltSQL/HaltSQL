(* Kafka audit sink against the real apache/kafka broker (KRaft, single node) in
   Docker. Listeners on host ports:
     19092 PLAINTEXT
     19093 SASL_SSL      (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512; certificate from a test CA)
     19094 SASL_PLAINTEXT (PLAIN, SCRAM)
   Records are read back with the broker's own kafka-console-consumer and their
   hash chain is verified; the broker is stopped and started during shipping. *)

open Siem_testlib
module Config = Haltsql_load.Config
module S = Haltsql_siem.Stream_sink

let image = "apache/kafka:3.9.1"
let container = "haltsql-siem-kafka"
let password = "kafka-test-" ^ string_of_int (Unix.getpid ()) ^ "-pw"
let run = Lwt_main.run

let properties =
  String.concat "\n"
    [
      "process.roles=broker,controller";
      "node.id=1";
      "controller.quorum.voters=1@localhost:9093";
      "listeners=PLAINTEXT://:19092,SASL_SSL://:19093,SASL_PLAINTEXT://:19094,CONTROLLER://:9093";
      "advertised.listeners=PLAINTEXT://localhost:19092,SASL_SSL://localhost:19093,SASL_PLAINTEXT://localhost:19094";
      "controller.listener.names=CONTROLLER";
      "listener.security.protocol.map=PLAINTEXT:PLAINTEXT,SASL_SSL:SASL_SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,CONTROLLER:PLAINTEXT";
      "inter.broker.listener.name=PLAINTEXT";
      "sasl.enabled.mechanisms=PLAIN,SCRAM-SHA-256,SCRAM-SHA-512";
      Printf.sprintf
        "listener.name.sasl_ssl.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule \
         required user_haltsql=\"%s\";"
        password;
      "listener.name.sasl_ssl.scram-sha-256.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule \
       required;";
      "listener.name.sasl_ssl.scram-sha-512.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule \
       required;";
      Printf.sprintf
        "listener.name.sasl_plaintext.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule \
         required user_haltsql=\"%s\";"
        password;
      "listener.name.sasl_plaintext.scram-sha-256.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule \
       required;";
      "listener.name.sasl_plaintext.scram-sha-512.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule \
       required;";
      "ssl.keystore.type=PEM";
      "ssl.keystore.location=/cfg/server-bundle.pem";
      "log.dirs=/tmp/kraft-logs";
      "offsets.topic.replication.factor=1";
      "transaction.state.log.replication.factor=1";
      "transaction.state.log.min.isr=1";
      "num.partitions=1";
      "auto.create.topics.enable=false";
      "group.initial.rebalance.delay.ms=0";
      "";
    ]

let kafka_sh tool args = [ "exec"; container; "/opt/kafka/bin/" ^ tool ] @ args

let ready () =
  Lwt.return
    (match
       docker
         (kafka_sh "kafka-topics.sh"
            [ "--bootstrap-server"; "localhost:19092"; "--list" ])
     with
    | 0, _ -> true
    | _ -> false)

let wait_ready () =
  Lwt.catch
    (fun () -> wait_until ~deadline:(Unix.gettimeofday () +. 120.) "kafka to start" ready)
    (fun e ->
      Printf.printf "kafka logs:\n%s\n%!" (logs container);
      Lwt.fail e)

let env =
  lazy
    (let pki = make_pki () in
     write_file (Filename.concat pki.dir "server.properties") properties;
     if not (image_present image) then failwith ("cannot pull " ^ image);
     let scram m = Printf.sprintf "'%s=[name=haltsql,password=%s]'" m password in
     run_container ~name:container
       [
         "-p";
         "127.0.0.1:19092:19092";
         "-p";
         "127.0.0.1:19093:19093";
         "-p";
         "127.0.0.1:19094:19094";
         "-v";
         pki.dir ^ ":/cfg:ro";
         "--entrypoint";
         "sh";
       ]
       image
       [
         "-c";
         String.concat " "
           [
             "/opt/kafka/bin/kafka-storage.sh format --ignore-formatted -t \
              MkU3OEVBNTcwNTJENDM2Qk";
             "-c /cfg/server.properties";
             "--add-scram";
             scram "SCRAM-SHA-256";
             "--add-scram";
             scram "SCRAM-SHA-512";
             "&& exec /opt/kafka/bin/kafka-server-start.sh /cfg/server.properties";
           ];
       ];
     run (wait_ready ());
     pki)

let setup () =
  skip_unless_docker ();
  Lazy.force env

let create_topic ?(partitions = 3) topic =
  ignore
    (docker_ok
       (kafka_sh "kafka-topics.sh"
          [
            "--bootstrap-server";
            "localhost:19092";
            "--create";
            "--if-not-exists";
            "--topic";
            topic;
            "--partitions";
            string_of_int partitions;
            "--replication-factor";
            "1";
          ]))

type msg = { partition : int; offset : int; key : string; value : string }

(* Reads [n] messages with the real console consumer (all partitions, from the
   beginning), ordered by (partition, offset). *)
let consume topic n =
  let out =
    docker_ok
      (kafka_sh "kafka-console-consumer.sh"
         [
           "--bootstrap-server";
           "localhost:19092";
           "--topic";
           topic;
           "--from-beginning";
           "--max-messages";
           string_of_int n;
           "--timeout-ms";
           "30000";
           "--property";
           "print.key=true";
           "--property";
           "print.partition=true";
           "--property";
           "print.offset=true";
           "--property";
           "key.separator=\t";
         ])
  in
  let field prefix s =
    let l = String.length prefix in
    if String.length s > l && String.sub s 0 l = prefix then
      int_of_string (String.sub s l (String.length s - l))
    else failwith ("unexpected consumer output: " ^ s)
  in
  String.split_on_char '\n' out
  |> List.filter_map (fun line ->
      match String.split_on_char '\t' line with
      | [ p; o; key; value ] ->
          Some
            { partition = field "Partition:" p; offset = field "Offset:" o; key; value }
      | _ -> None)
  |> List.sort (fun a b -> compare (a.partition, a.offset) (b.partition, b.offset))

let kafka_cfg ?(brokers = [ "localhost:19092" ]) ?tls ?sasl ?(acks = Config.Acks_all)
    topic =
  {
    Config.kafka_brokers = brokers;
    kafka_topic = topic;
    kafka_client_id = "haltsql-siem-test";
    kafka_acks = acks;
    kafka_tls = tls;
    kafka_sasl = sasl;
    kafka_batch = batch ();
  }

let make_sink ?(on_error = Config.Stream_fail_closed) ?(run_id = "run1") k =
  match
    run
      (Haltsql_siem.Siem.of_config ~host:"siem-test" ~run_id ~max_attempts:3
         ~base_backoff:0.1 ~max_backoff:1.0 ~on_event
         {
           Config.stream = Config.Stream_kafka k;
           stream_on_error = on_error;
           max_buffer_records = 10_000;
           sink_index = 0;
         })
  with
  | Ok s -> s
  | Error e -> Alcotest.failf "of_config: %s" e

let check_shipped ~topic ~run_id ~partitions n =
  let msgs = consume topic n in
  Alcotest.(check int) "messages consumed" n (List.length msgs);
  let key = Haltsql_siem.Siem.chain_id ~host:"siem-test" ~run_id in
  List.iter (fun m -> Alcotest.(check string) "key is the chain id" key m.key) msgs;
  let parts = List.sort_uniq compare (List.map (fun m -> m.partition) msgs) in
  Alcotest.(check (list int))
    "one partition, chosen like the Java client"
    [ Haltsql_siem.Kafka_wire.partition_for_key key ~partitions ]
    parts;
  let lines = dedupe (List.map (fun m -> m.value) msgs) in
  lines

let flush_ok s =
  match run (S.flush s) with Ok () -> () | Error e -> Alcotest.failf "flush: %s" e

(* ---- tests ---- *)

let test_plaintext () =
  ignore (setup ());
  let topic = "haltsql.audit.plain" in
  create_topic topic;
  let s = make_sink (kafka_cfg topic) in
  write_n s ~from:0 25;
  flush_ok s;
  Alcotest.(check int) "delivered" 25 (S.stats s).records_delivered;
  let lines = check_shipped ~topic ~run_id:"run1" ~partitions:3 25 in
  Alcotest.(check int) "chain verifies" 25 (verify_chain lines);
  Alcotest.(check string)
    "chain head" (S.stats s).chain_head
    (hash_of (List.nth lines 24));
  ignore (run (S.close s))

(* The real Java producer is the oracle for our murmur2 partitioner. *)
let test_java_partitioner () =
  ignore (setup ());
  let topic = "haltsql.partitioner" in
  create_topic ~partitions:7 topic;
  let keys =
    [
      "haltsql/a/1";
      "haltsql/host-1/20261107T120000.000000Z.42";
      "k";
      "21";
      "foobar";
      "xyzzy-0123";
    ]
  in
  let input = String.concat "" (List.map (fun k -> k ^ "\t{}\n") keys) in
  let tmp = Filename.temp_file "haltsql-siem-keys" ".txt" in
  write_file tmp input;
  let code, out =
    run_cmd
      [|
        "sh";
        "-c";
        Printf.sprintf
          "docker exec -i %s /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server \
           localhost:19092 --topic %s --property parse.key=true --property \
           key.separator='\t' < %s"
          container topic (Filename.quote tmp);
      |]
  in
  Sys.remove tmp;
  if code <> 0 then Alcotest.failf "console producer failed: %s" out;
  let msgs = consume topic (List.length keys) in
  Alcotest.(check int) "all consumed" (List.length keys) (List.length msgs);
  List.iter
    (fun m ->
      Alcotest.(check int)
        ("partition of " ^ m.key) m.partition
        (Haltsql_siem.Kafka_wire.partition_for_key m.key ~partitions:7))
    msgs

let sasl mech =
  Some
    { Config.sasl_mechanism = mech; sasl_username = "haltsql"; sasl_password = password }

let tls ca = Some { Config.kafka_ca = Some ca; kafka_cert = None; kafka_key = None }

let shipped_over ~name ~brokers ?tls ?sasl () =
  let topic = "haltsql.audit." ^ name in
  create_topic topic;
  events := [];
  let s = make_sink ~run_id:name (kafka_cfg ~brokers ?tls ?sasl topic) in
  write_n s ~from:0 12;
  flush_ok s;
  let lines = check_shipped ~topic ~run_id:name ~partitions:3 12 in
  Alcotest.(check int) "chain verifies" 12 (verify_chain lines);
  check_no_secret ~secret:password;
  ignore (run (S.close s))

let test_scram256_tls () =
  let pki = setup () in
  shipped_over ~name:"scram256" ~brokers:[ "localhost:19093" ]
    ?tls:(tls (Config.Pem_inline pki.ca_pem))
    ?sasl:(sasl Config.Sasl_scram_sha_256)
    ()

let test_scram512_tls () =
  let pki = setup () in
  shipped_over ~name:"scram512" ~brokers:[ "localhost:19093" ]
    ?tls:(tls (Config.Pem_path pki.ca_file))
    ?sasl:(sasl Config.Sasl_scram_sha_512)
    ()

let test_plain_tls () =
  let pki = setup () in
  shipped_over ~name:"plaintls" ~brokers:[ "127.0.0.1:19093" ]
    ?tls:(tls (Config.Pem_path pki.ca_file))
    ?sasl:(sasl Config.Sasl_plain) ()

let test_plain_loopback () =
  ignore (setup ());
  shipped_over ~name:"plainlo" ~brokers:[ "localhost:19094" ]
    ?sasl:(sasl Config.Sasl_plain) ()

let test_bootstrap_failover () =
  ignore (setup ());
  (* the first bootstrap broker is down; the second answers *)
  shipped_over ~name:"failover" ~brokers:[ "127.0.0.1:19099"; "localhost:19092" ] ()

let expect_failure ~what k needle =
  let topic = "haltsql.audit.plain" in
  ignore topic;
  events := [];
  let s = make_sink k in
  write_n s ~from:0 1;
  (match run (S.flush s) with
  | Ok () -> Alcotest.failf "%s: delivery succeeded" what
  | Error e ->
      let has =
        let n = String.length needle in
        let rec go i =
          i + n <= String.length e && (String.sub e i n = needle || go (i + 1))
        in
        go 0
      in
      if not has then Alcotest.failf "%s: unexpected error %S" what e;
      Alcotest.(check bool)
        "no password in the error" false
        (let n = String.length password in
         let rec go i =
           i + n <= String.length e && (String.sub e i n = password || go (i + 1))
         in
         go 0));
  Alcotest.(check bool) "fail closed: unhealthy" false (S.healthy s);
  Alcotest.(check bool)
    "fail closed: write refused" true
    (Result.is_error (S.write s (record 1 [])));
  check_no_secret ~secret:password;
  ignore (run (S.close s))

let test_bad_password () =
  let pki = setup () in
  expect_failure ~what:"wrong SCRAM password"
    (kafka_cfg ~brokers:[ "localhost:19093" ]
       ?tls:(tls (Config.Pem_path pki.ca_file))
       ?sasl:
         (Some
            {
              Config.sasl_mechanism = Config.Sasl_scram_sha_512;
              sasl_username = "haltsql";
              sasl_password = "wrong-" ^ password;
            })
       "haltsql.audit.scram512")
    "SASL"

let test_untrusted_ca () =
  let pki = setup () in
  expect_failure ~what:"untrusted broker certificate"
    (kafka_cfg ~brokers:[ "localhost:19093" ]
       ?tls:(tls (Config.Pem_inline pki.rogue_ca_pem))
       ?sasl:(sasl Config.Sasl_scram_sha_256)
       "haltsql.audit.scram256")
    "TLS handshake"

let test_unknown_topic () =
  ignore (setup ());
  expect_failure ~what:"missing topic"
    (kafka_cfg "haltsql.does-not-exist")
    "UNKNOWN_TOPIC_OR_PARTITION"

let stop_broker () = ignore (docker_ok [ "stop"; "-t"; "10"; container ])

let start_broker () =
  ignore (docker_ok [ "start"; container ]);
  run (wait_ready ())

let wait_for what f =
  run
    (wait_until ~interval:0.2
       ~deadline:(Unix.gettimeofday () +. 60.)
       what
       (fun () -> Lwt.return (f ())))

let test_restart_buffer () =
  ignore (setup ());
  let topic = "haltsql.audit.restart-buffer" in
  create_topic topic;
  let s =
    make_sink ~on_error:Config.Stream_buffer ~run_id:"restart-buffer" (kafka_cfg topic)
  in
  S.start s;
  write_n s ~from:0 20;
  wait_for "first records delivered" (fun () -> (S.stats s).records_delivered = 20);
  stop_broker ();
  (* the broker is down: buffer mode keeps accepting *)
  write_n s ~from:20 20;
  wait_for "the outage to be noticed" (fun () -> not (S.stats s).delivering);
  write_n s ~from:40 5;
  Alcotest.(check bool) "healthy while buffering" true (S.healthy s);
  Alcotest.(check bool) "records buffered" true ((S.stats s).buffered_records >= 25);
  start_broker ();
  (* the background loop reconnects (new leader connection) and drains *)
  wait_for "buffer drained" (fun () -> (S.stats s).buffered_records = 0);
  Alcotest.(check bool) "delivering again" true (S.stats s).delivering;
  Alcotest.(check (result unit string)) "close" (Ok ()) (run (S.close s));
  let lines = check_shipped ~topic ~run_id:"restart-buffer" ~partitions:3 45 in
  Alcotest.(check int) "all 45 records, chain intact" 45 (verify_chain lines)

let test_restart_fail_closed () =
  ignore (setup ());
  let topic = "haltsql.audit.restart-fail" in
  create_topic topic;
  let s =
    make_sink ~on_error:Config.Stream_fail_closed ~run_id:"restart-fail" (kafka_cfg topic)
  in
  write_n s ~from:0 5;
  flush_ok s;
  stop_broker ();
  write_n s ~from:5 1;
  Alcotest.(check bool) "flush fails" true (Result.is_error (run (S.flush s)));
  Alcotest.(check bool) "unhealthy" false (S.healthy s);
  Alcotest.(check bool) "writes refused" true (Result.is_error (S.write s (record 99 [])));
  let m = Haltsql_siem.Siem.metrics_text [ s ] in
  Alcotest.(check bool)
    "healthy gauge is 0" true
    (List.mem
       {|haltsql_audit_stream_sink_healthy{sink="kafka://localhost:19092/haltsql.audit.restart-fail",type="kafka"} 0|}
       (String.split_on_char '\n' m));
  start_broker ();
  S.start s;
  wait_for "recovery" (fun () -> S.healthy s);
  write_n s ~from:6 4;
  flush_ok s;
  ignore (run (S.close s));
  let lines = check_shipped ~topic ~run_id:"restart-fail" ~partitions:3 10 in
  Alcotest.(check int) "refused record never entered the chain" 10 (verify_chain lines)

let test_python_verifier () =
  ignore (setup ());
  if not (Lazy.force python3) then (
    print_endline "SKIP: python3 not found";
    Alcotest.skip ());
  let topic = "haltsql.audit.pyverify" in
  create_topic ~partitions:1 topic;
  (* two processes, two chains in one partition *)
  List.iter
    (fun (run_id, n) ->
      let s = make_sink ~run_id (kafka_cfg topic) in
      write_n s ~from:0 n;
      flush_ok s;
      ignore (run (S.close s)))
    [ ("py-a", 7); ("py-b", 5) ];
  let out =
    docker_ok
      (kafka_sh "kafka-console-consumer.sh"
         [
           "--bootstrap-server";
           "localhost:19092";
           "--topic";
           topic;
           "--from-beginning";
           "--max-messages";
           "12";
           "--timeout-ms";
           "30000";
           "--property";
           "print.key=true";
           "--property";
           "key.separator=\t";
         ])
  in
  let verify text =
    let tmp = Filename.temp_file "haltsql-siem-kafka" ".tsv" in
    write_file tmp text;
    let r = run_python "verify_chain.py" [ "kafka"; tmp ] in
    Sys.remove tmp;
    r
  in
  let code, res = verify out in
  if code <> 0 || not (python_ok res) then Alcotest.failf "verify_chain.py kafka: %s" res;
  Alcotest.(check bool)
    "two chains" true
    (List.exists
       (fun l -> l = "OK: 12 records in 2 chain(s)")
       (String.split_on_char '\n' res));
  (* a modified record is detected *)
  let tampered =
    String.concat "\n"
      (List.map
         (fun l ->
           match String.index_opt l '"' with
           | Some _ when String.length l > 0 ->
               let r = Str_lite.replace_first ~sub:"req-0003" ~by:"req-9999" l in
               r
           | _ -> l)
         (String.split_on_char '\n' out))
  in
  let code, _ = verify tampered in
  Alcotest.(check int) "tampering detected" 1 code

let () =
  Alcotest.run "siem-kafka"
    [
      ( "kafka",
        [
          Alcotest.test_case "plaintext produce, consume, verify" `Slow test_plaintext;
          Alcotest.test_case "partitioner matches the Java client" `Slow
            test_java_partitioner;
          Alcotest.test_case "SASL SCRAM-SHA-256 over TLS" `Slow test_scram256_tls;
          Alcotest.test_case "SASL SCRAM-SHA-512 over TLS" `Slow test_scram512_tls;
          Alcotest.test_case "SASL PLAIN over TLS" `Slow test_plain_tls;
          Alcotest.test_case "SASL PLAIN on loopback" `Slow test_plain_loopback;
          Alcotest.test_case "bootstrap failover" `Slow test_bootstrap_failover;
          Alcotest.test_case "wrong password fails closed" `Slow test_bad_password;
          Alcotest.test_case "untrusted CA fails closed" `Slow test_untrusted_ca;
          Alcotest.test_case "unknown topic fails closed" `Slow test_unknown_topic;
          Alcotest.test_case "broker restart, on_error=buffer" `Slow test_restart_buffer;
          Alcotest.test_case "broker restart, on_error=fail_closed" `Slow
            test_restart_fail_closed;
          Alcotest.test_case "documented python verifier" `Slow test_python_verifier;
        ] );
    ]
