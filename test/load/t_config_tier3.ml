(* Tests for the tier-3 Config contract: elasticsearch and kafka audit sinks,
   remote policy bundle sources, OIDC policy_from_groups, opa and
   server.admin. Every validation error and the redaction of every new secret
   is covered. *)

open Haltsql_load
open Helpers

let h1 = String.make 64 'a'
let h2 = String.make 64 'b'
let no_env _ = None
let env_of l name = List.assoc_opt name l
let head = "apiVersion: haltsql.dev/v1\nkind: Config\n"

let pols =
  "policies:\n  - inline: {metadata: {name: p1}}\n  - inline: {metadata: {name: p2}}\n"

let cfg ?(env = no_env) ?resolve s =
  match yaml (head ^ s) with
  | Error e -> Error e
  | Ok j -> Config.of_json ~base_dir:"/etc/haltsql" ~env ?resolve j

let ok ?env ?resolve s = get_ok (cfg ?env ?resolve s)
let err ?env ?resolve ?path ~msg s = check_err ?path ~msg (cfg ?env ?resolve s)
let redacted_string x = Yojson.Safe.to_string (Config.to_json_redacted x)

let check_hidden s secrets =
  List.iter (fun v -> Alcotest.(check bool) ("hidden " ^ v) false (contains s v)) secrets

let check_shown s shown =
  List.iter (fun v -> Alcotest.(check bool) ("shown " ^ v) true (contains s v)) shown

(* ---------------------------------------------------------------------- *)
(* audit.sinks: elasticsearch                                             *)

let es extra = Printf.sprintf "audit:\n  sinks:\n    - type: elasticsearch\n%s" extra
let es_min = "      url: http://127.0.0.1:9200\n      index: haltsql-audit\n"
let s0 k = "audit.sinks[0]." ^ k

let the_stream x =
  match x.Config.stream_sinks with
  | [ s ] -> s
  | l -> Alcotest.failf "expected one stream sink, got %d" (List.length l)

let the_es x =
  match (the_stream x).stream with
  | Config.Stream_elasticsearch e -> e
  | Config.Stream_kafka _ -> Alcotest.fail "expected elasticsearch"

let es_cases =
  [
    tc "minimal elasticsearch sink with defaults" (fun () ->
        let x = ok (es es_min) in
        let s = the_stream x in
        let e = the_es x in
        Alcotest.(check (list string)) "urls" [ "http://127.0.0.1:9200" ] e.es_urls;
        Alcotest.(check bool) "index" true (e.es_target = Config.Es_index "haltsql-audit");
        Alcotest.(check bool) "auth" true (e.es_auth = None);
        Alcotest.(check (option string)) "pipeline" None e.es_pipeline;
        Alcotest.(check bool) "ca" true (e.es_ca = None);
        Alcotest.(check int) "timeout" 10_000 e.es_timeout_ms;
        Alcotest.(check int) "batch records" 500 e.es_batch.batch_max_records;
        Alcotest.(check int) "batch bytes" (5 * 1024 * 1024) e.es_batch.batch_max_bytes;
        Alcotest.(check int) "flush" 1000 e.es_batch.flush_interval_ms;
        Alcotest.(check bool)
          "on_error" true
          (s.stream_on_error = Config.Stream_fail_closed);
        Alcotest.(check int) "max buffer default" 10_000 s.max_buffer_records;
        Alcotest.(check int) "index" 0 s.sink_index;
        (* a stream-only list leaves no classic sinks *)
        Alcotest.(check int) "classic sinks" 0 (List.length x.sinks);
        Alcotest.(check int) "legacy sinks" 0 (List.length x.audit_sinks));
    tc "full elasticsearch sink" (fun () ->
        let x =
          ok
            (es
               "      urls: ['https://es-1.corp.example:9200', \
                'https://es-2.corp.example:9200/prefix']\n\
               \      data_stream: logs-haltsql-prod\n\
               \      auth: {username: haltsql, password: hunter2}\n\
               \      pipeline: haltsql-enrich\n\
               \      tls: {ca_file: certs/es-ca.pem}\n\
               \      timeout_ms: 2000\n\
               \      batch: {max_records: 1000, max_bytes: 2048, flush_interval_ms: 250}\n\
               \      on_error: buffer\n\
               \      max_buffer_records: 5000\n")
        in
        let s = the_stream x in
        let e = the_es x in
        Alcotest.(check int) "urls" 2 (List.length e.es_urls);
        Alcotest.(check bool)
          "data stream" true
          (e.es_target = Config.Es_data_stream "logs-haltsql-prod");
        Alcotest.(check bool)
          "basic" true
          (e.es_auth
          = Some (Config.Es_basic { username = "haltsql"; password = "hunter2" }));
        Alcotest.(check (option string)) "pipeline" (Some "haltsql-enrich") e.es_pipeline;
        Alcotest.(check bool)
          "ca absolute" true
          (e.es_ca = Some (Config.Pem_path "/etc/haltsql/certs/es-ca.pem"));
        Alcotest.(check int) "timeout" 2000 e.es_timeout_ms;
        Alcotest.(check int) "records" 1000 e.es_batch.batch_max_records;
        Alcotest.(check int) "bytes" 2048 e.es_batch.batch_max_bytes;
        Alcotest.(check int) "flush" 250 e.es_batch.flush_interval_ms;
        Alcotest.(check bool) "buffer" true (s.stream_on_error = Config.Stream_buffer);
        Alcotest.(check int) "max buffer" 5000 s.max_buffer_records);
    tc "elasticsearch api_key and drop" (fun () ->
        let x =
          ok (es (es_min ^ "      auth: {api_key: QUJDOkRFRg==}\n      on_error: drop\n"))
        in
        Alcotest.(check bool)
          "api key" true
          ((the_es x).es_auth = Some (Config.Es_api_key "QUJDOkRFRg=="));
        Alcotest.(check bool)
          "drop" true
          ((the_stream x).stream_on_error = Config.Stream_drop));
    tc "buffer default grows with batch size" (fun () ->
        let x =
          ok (es (es_min ^ "      batch: {max_records: 50000}\n      on_error: buffer\n"))
        in
        Alcotest.(check int) "max buffer" 50_000 (the_stream x).max_buffer_records);
    tc "mixed with classic sinks keeps order index" (fun () ->
        let x =
          ok
            "audit:\n\
            \  sinks:\n\
            \    - type: stdout\n\
            \    - {type: elasticsearch, url: 'http://localhost:9200', index: a}\n\
            \    - {type: file, path: /var/log/a.jsonl}\n"
        in
        Alcotest.(check int) "classic" 2 (List.length x.sinks);
        Alcotest.(check int) "legacy" 2 (List.length x.audit_sinks);
        Alcotest.(check int) "stream index" 1 (the_stream x).sink_index);
    tc "url or urls required" (fun () ->
        err ~path:(s0 "url") ~msg:"required (or urls)" (es "      index: a\n"));
    tc "url and urls exclusive" (fun () ->
        err ~path:"audit.sinks[0]" ~msg:"either url or urls"
          (es
             "      url: 'http://localhost:9200'\n\
             \      urls: ['http://localhost:9201']\n\
             \      index: a\n"));
    tc "urls must not be empty" (fun () ->
        err ~path:(s0 "urls") ~msg:"must not be empty"
          (es "      urls: []\n      index: a\n"));
    tc "urls must be unique" (fun () ->
        err ~path:(s0 "urls[1]") ~msg:"duplicate URL"
          (es
             "      urls: ['http://localhost:9200', 'http://localhost:9200']\n\
             \      index: a\n"));
    tc "plain http only for loopback" (fun () ->
        err ~path:(s0 "url") ~msg:"plain http is only allowed for loopback"
          (es "      url: 'http://es.corp.example:9200'\n      index: a\n"));
    tc "url without credentials or query" (fun () ->
        err ~path:(s0 "url") ~msg:"must not contain credentials"
          (es "      url: 'https://u:p@es.corp.example'\n      index: a\n");
        err ~path:(s0 "url") ~msg:"must not contain a query"
          (es "      url: 'https://es.corp.example/?x=1'\n      index: a\n");
        err ~path:(s0 "url") ~msg:"invalid URL"
          (es "      url: 'ftp://es.corp.example'\n      index: a\n"));
    tc "index or data_stream required" (fun () ->
        err ~path:(s0 "index") ~msg:"required (or data_stream)"
          (es "      url: 'http://localhost:9200'\n"));
    tc "index and data_stream exclusive" (fun () ->
        err ~path:"audit.sinks[0]" ~msg:"either index or data_stream"
          (es (es_min ^ "      data_stream: b\n")));
    tc "index name rules" (fun () ->
        List.iter
          (fun bad ->
            err ~path:(s0 "index") ~msg:"invalid index name"
              (es
                 (Printf.sprintf "      url: 'http://localhost:9200'\n      index: '%s'\n"
                    bad)))
          [
            "Upper"; "_x"; "-x"; "+x"; "."; ".."; "a b"; "a*b"; "a/b"; String.make 256 'a';
          ];
        err ~path:(s0 "data_stream") ~msg:"invalid data stream name"
          (es "      url: 'http://localhost:9200'\n      data_stream: 'A'\n"));
    tc "auth needs api_key or username/password" (fun () ->
        err ~path:(s0 "auth") ~msg:"needs api_key, or username and password"
          (es (es_min ^ "      auth: {}\n")));
    tc "auth api_key and basic exclusive" (fun () ->
        err ~path:(s0 "auth") ~msg:"either api_key or username/password"
          (es (es_min ^ "      auth: {api_key: k, username: u, password: p}\n")));
    tc "auth username needs password and vice versa" (fun () ->
        err ~path:(s0 "auth.password") ~msg:"required"
          (es (es_min ^ "      auth: {username: u}\n"));
        err ~path:(s0 "auth.username") ~msg:"required"
          (es (es_min ^ "      auth: {password: p}\n")));
    tc "auth username without colon, no CRLF secrets" (fun () ->
        err ~path:(s0 "auth.username") ~msg:"must not contain ':'"
          (es (es_min ^ "      auth: {username: 'a:b', password: p}\n"));
        err ~path:(s0 "auth.api_key") ~msg:"must not contain CR, LF"
          (es (es_min ^ "      auth: {api_key: \"a\\nb\"}\n")));
    tc "auth unknown key" (fun () ->
        err ~path:(s0 "auth.token") ~msg:"unknown key"
          (es (es_min ^ "      auth: {token: t}\n")));
    tc "pipeline name rules" (fun () ->
        err ~path:(s0 "pipeline") ~msg:"invalid pipeline name"
          (es (es_min ^ "      pipeline: 'a b'\n")));
    tc "tls only with https" (fun () ->
        err ~path:(s0 "tls") ~msg:"only used with https URLs"
          (es (es_min ^ "      tls: {ca_file: /ca.pem}\n"));
        err ~path:(s0 "tls.verify") ~msg:"unknown key"
          (es
             "      url: 'https://es.corp.example'\n\
             \      index: a\n\
             \      tls: {verify: false}\n"));
    tc "timeout range" (fun () ->
        err ~path:(s0 "timeout_ms") ~msg:"between 100 and 120000"
          (es (es_min ^ "      timeout_ms: 5\n")));
    tc "batch ranges" (fun () ->
        err ~path:(s0 "batch.max_records") ~msg:"between 1 and 100000"
          (es (es_min ^ "      batch: {max_records: 0}\n"));
        err ~path:(s0 "batch.max_bytes") ~msg:"between 1024 and 104857600"
          (es (es_min ^ "      batch: {max_bytes: 10}\n"));
        err
          ~path:(s0 "batch.flush_interval_ms")
          ~msg:"between 10 and 60000"
          (es (es_min ^ "      batch: {flush_interval_ms: 1}\n"));
        err ~path:(s0 "batch.max_seconds") ~msg:"unknown key"
          (es (es_min ^ "      batch: {max_seconds: 1}\n")));
    tc "on_error values" (fun () ->
        err ~path:(s0 "on_error") ~msg:"expected one of: fail_closed, buffer, drop"
          (es (es_min ^ "      on_error: retry\n")));
    tc "max_buffer_records only with buffer" (fun () ->
        err ~path:(s0 "max_buffer_records") ~msg:"only allowed when on_error is buffer"
          (es (es_min ^ "      max_buffer_records: 100\n"));
        err ~path:(s0 "max_buffer_records") ~msg:"only allowed when on_error is buffer"
          (es (es_min ^ "      on_error: drop\n      max_buffer_records: 100\n")));
    tc "max_buffer_records range and batch bound" (fun () ->
        err ~path:(s0 "max_buffer_records") ~msg:"between 1 and 1000000"
          (es (es_min ^ "      on_error: buffer\n      max_buffer_records: 0\n"));
        err ~path:(s0 "max_buffer_records") ~msg:"at least batch.max_records (500)"
          (es (es_min ^ "      on_error: buffer\n      max_buffer_records: 100\n")));
    tc "unknown elasticsearch key" (fun () ->
        err ~path:(s0 "bucket") ~msg:"unknown key" (es (es_min ^ "      bucket: x\n")));
    tc "classic sinks still reject stream keys" (fun () ->
        err ~path:(s0 "index") ~msg:"unknown key"
          "audit: {sinks: [{type: stdout, index: a}]}";
        err ~path:(s0 "on_error") ~msg:"invalid value \"drop\""
          "audit: {sinks: [{type: stdout, on_error: drop}]}");
    tc "unknown sink type lists the new types" (fun () ->
        err ~path:(s0 "type") ~msg:"elasticsearch, kafka"
          "audit: {sinks: [{type: splunk}]}");
  ]

(* ---------------------------------------------------------------------- *)
(* audit.sinks: kafka                                                     *)

let kafka extra = Printf.sprintf "audit:\n  sinks:\n    - type: kafka\n%s" extra
let kafka_min = "      brokers: ['localhost:9092']\n      topic: haltsql.audit\n"

let the_kafka x =
  match (the_stream x).stream with
  | Config.Stream_kafka k -> k
  | Config.Stream_elasticsearch _ -> Alcotest.fail "expected kafka"

let kafka_cases =
  [
    tc "minimal kafka sink with defaults" (fun () ->
        let x = ok (kafka kafka_min) in
        let k = the_kafka x in
        Alcotest.(check (list string)) "brokers" [ "localhost:9092" ] k.kafka_brokers;
        Alcotest.(check string) "topic" "haltsql.audit" k.kafka_topic;
        Alcotest.(check string) "client id" "haltsql" k.kafka_client_id;
        Alcotest.(check bool) "acks" true (k.kafka_acks = Config.Acks_all);
        Alcotest.(check bool) "tls" true (k.kafka_tls = None);
        Alcotest.(check bool) "sasl" true (k.kafka_sasl = None);
        Alcotest.(check int) "batch" 500 k.kafka_batch.batch_max_records;
        Alcotest.(check bool)
          "on_error" true
          ((the_stream x).stream_on_error = Config.Stream_fail_closed));
    tc "full kafka sink" (fun () ->
        let x =
          ok
            (kafka
               "      brokers: ['kafka-1.corp.example:9093', '10.0.0.7:9093', \
                '[2001:db8::1]:9093']\n\
               \      topic: haltsql-audit_v1\n\
               \      client_id: haltsql-prod\n\
               \      acks: 1\n\
               \      tls: {ca_file: /etc/kafka/ca.pem, cert_file: client.pem, key_file: \
                client.key}\n\
               \      sasl: {mechanism: scram-sha-512, username: haltsql, password: \
                s3cret}\n\
               \      batch: {max_records: 100, max_bytes: 65536, flush_interval_ms: 50}\n\
               \      on_error: buffer\n\
               \      max_buffer_records: 100\n")
        in
        let k = the_kafka x in
        Alcotest.(check int) "brokers" 3 (List.length k.kafka_brokers);
        Alcotest.(check string) "client id" "haltsql-prod" k.kafka_client_id;
        Alcotest.(check bool) "acks 1" true (k.kafka_acks = Config.Acks_leader);
        (match k.kafka_tls with
        | Some t ->
            Alcotest.(check bool)
              "ca" true
              (t.kafka_ca = Some (Config.Pem_path "/etc/kafka/ca.pem"));
            Alcotest.(check bool)
              "cert" true
              (t.kafka_cert = Some (Config.Pem_path "/etc/haltsql/client.pem"));
            Alcotest.(check bool)
              "key" true
              (t.kafka_key = Some (Config.Pem_path "/etc/haltsql/client.key"))
        | None -> Alcotest.fail "expected tls");
        Alcotest.(check bool)
          "sasl" true
          (k.kafka_sasl
          = Some
              {
                sasl_mechanism = Config.Sasl_scram_sha_512;
                sasl_username = "haltsql";
                sasl_password = "s3cret";
              });
        Alcotest.(check int) "max buffer" 100 (the_stream x).max_buffer_records);
    tc "acks variants" (fun () ->
        Alcotest.(check bool)
          "all" true
          ((the_kafka (ok (kafka (kafka_min ^ "      acks: all\n")))).kafka_acks
         = Config.Acks_all);
        Alcotest.(check bool)
          "'1'" true
          ((the_kafka (ok (kafka (kafka_min ^ "      acks: '1'\n")))).kafka_acks
         = Config.Acks_leader);
        err ~path:(s0 "acks") ~msg:"acks 0 is not supported"
          (kafka (kafka_min ^ "      acks: 0\n"));
        err ~path:(s0 "acks") ~msg:"expected one of: all, 1"
          (kafka (kafka_min ^ "      acks: -1\n")));
    tc "tls enabled false" (fun () ->
        let x = ok (kafka (kafka_min ^ "      tls: {enabled: false}\n")) in
        Alcotest.(check bool) "no tls" true ((the_kafka x).kafka_tls = None);
        err ~path:(s0 "tls.ca_file") ~msg:"only allowed when tls.enabled is true"
          (kafka (kafka_min ^ "      tls: {enabled: false, ca_file: /ca.pem}\n")));
    tc "tls empty block enables tls" (fun () ->
        let x = ok (kafka (kafka_min ^ "      tls: {}\n")) in
        Alcotest.(check bool)
          "tls" true
          ((the_kafka x).kafka_tls
          = Some { kafka_ca = None; kafka_cert = None; kafka_key = None }));
    tc "tls cert and key together" (fun () ->
        err ~path:(s0 "tls.key_file") ~msg:"required when cert_file is set"
          (kafka (kafka_min ^ "      tls: {cert_file: /c.pem}\n"));
        err ~path:(s0 "tls.cert_file") ~msg:"required when key_file is set"
          (kafka (kafka_min ^ "      tls: {key_file: /k.pem}\n")));
    tc "brokers required and non-empty" (fun () ->
        err ~path:(s0 "brokers") ~msg:"required" (kafka "      topic: t\n");
        err ~path:(s0 "brokers") ~msg:"must not be empty"
          (kafka "      brokers: []\n      topic: t\n"));
    tc "broker syntax" (fun () ->
        List.iter
          (fun b ->
            err ~path:(s0 "brokers[0]") ~msg:"invalid broker"
              (kafka (Printf.sprintf "      brokers: ['%s']\n      topic: t\n" b)))
          [
            "kafka";
            "kafka:";
            "kafka:0";
            "kafka:65536";
            "ka fka:9092";
            "-k:9092";
            "[zz]:9092";
          ]);
    tc "duplicate brokers" (fun () ->
        err ~path:(s0 "brokers[1]") ~msg:"duplicate broker"
          (kafka "      brokers: ['k:9092', 'k:9092']\n      topic: t\n"));
    tc "topic rules" (fun () ->
        err ~path:(s0 "topic") ~msg:"required" (kafka "      brokers: ['k:9092']\n");
        List.iter
          (fun t ->
            err ~path:(s0 "topic") ~msg:"invalid topic"
              (kafka (Printf.sprintf "      brokers: ['k:9092']\n      topic: '%s'\n" t)))
          [ "."; ".."; "a b"; "a/b"; String.make 250 'a' ]);
    tc "client_id rules" (fun () ->
        err ~path:(s0 "client_id") ~msg:"invalid client_id"
          (kafka (kafka_min ^ "      client_id: 'a b'\n")));
    tc "sasl fields" (fun () ->
        err ~path:(s0 "sasl.mechanism") ~msg:"required"
          (kafka (kafka_min ^ "      sasl: {username: u, password: p}\n"));
        err ~path:(s0 "sasl.username") ~msg:"required"
          (kafka (kafka_min ^ "      sasl: {mechanism: scram-sha-256, password: p}\n"));
        err ~path:(s0 "sasl.password") ~msg:"required"
          (kafka (kafka_min ^ "      sasl: {mechanism: scram-sha-256, username: u}\n"));
        err ~path:(s0 "sasl.mechanism") ~msg:"expected one of: plain, scram-sha-256"
          (kafka
             (kafka_min ^ "      sasl: {mechanism: gssapi, username: u, password: p}\n")));
    tc "sasl plain needs tls off loopback" (fun () ->
        err ~path:(s0 "sasl.mechanism") ~msg:"SASL PLAIN sends the password in clear text"
          (kafka
             "      brokers: ['kafka.corp.example:9092']\n\
             \      topic: t\n\
             \      sasl: {mechanism: plain, username: u, password: p}\n");
        (* regression: a DNS name starting with "127." is not loopback *)
        List.iter
          (fun b ->
            err ~path:(s0 "sasl.mechanism")
              ~msg:"SASL PLAIN sends the password in clear text"
              (kafka
                 (Printf.sprintf
                    "      brokers: ['%s:9092']\n\
                    \      topic: t\n\
                    \      sasl: {mechanism: plain, username: u, password: p}\n"
                    b)))
          [ "127.attacker.example"; "127.0.0.1.nip.io" ];
        (* allowed with tls, or on loopback *)
        ignore
          (ok
             (kafka
                "      brokers: ['kafka.corp.example:9093']\n\
                \      topic: t\n\
                \      tls: {}\n\
                \      sasl: {mechanism: plain, username: u, password: p}\n"));
        ignore
          (ok
             (kafka
                "      brokers: ['127.0.0.1:9092', 'localhost:9093', '[::1]:9094']\n\
                \      topic: t\n\
                \      sasl: {mechanism: plain, username: u, password: p}\n")));
    tc "kafka on_error and buffer rules" (fun () ->
        err ~path:(s0 "max_buffer_records") ~msg:"only allowed when on_error is buffer"
          (kafka (kafka_min ^ "      max_buffer_records: 1000\n"));
        err ~path:(s0 "on_error") ~msg:"invalid value"
          (kafka (kafka_min ^ "      on_error: ignore\n")));
    tc "unknown kafka key" (fun () ->
        err ~path:(s0 "url") ~msg:"unknown key" (kafka (kafka_min ^ "      url: x\n")));
  ]

(* ---------------------------------------------------------------------- *)
(* policies: bundle_source                                                *)

let src extra = Printf.sprintf "policies:\n  - public_keys: [/keys/release.pub]\n%s" extra
let p0 k = "policies[0]." ^ k

let the_source x =
  match x.Config.bundle_sources with
  | [ s ] -> s
  | l -> Alcotest.failf "expected one bundle source, got %d" (List.length l)

let oci_of x =
  match (the_source x).location with
  | Config.Source_oci o -> o
  | Config.Source_s3 _ | Config.Source_https _ -> Alcotest.fail "expected oci"

let bundle_source_cases =
  [
    tc "oci tag source with defaults" (fun () ->
        let x =
          ok (src "    bundle_source: {oci: 'ghcr.io/corp/haltsql/policies:prod'}\n")
        in
        let s = the_source x in
        let o = oci_of x in
        Alcotest.(check string) "ref" "ghcr.io/corp/haltsql/policies:prod" o.oci_reference;
        Alcotest.(check string) "registry" "ghcr.io" o.oci_registry;
        Alcotest.(check string) "repo" "corp/haltsql/policies" o.oci_repository;
        Alcotest.(check (option string)) "tag" (Some "prod") o.oci_tag;
        Alcotest.(check (option string)) "digest" None o.oci_digest;
        Alcotest.(check bool) "plain" false o.oci_plain_http;
        Alcotest.(check bool)
          "keys" true
          (s.source_public_keys = [ Config.Key_path "/keys/release.pub" ]);
        Alcotest.(check int) "poll" 60 s.poll_interval_s;
        Alcotest.(check (option string)) "cache" None s.cache_dir;
        Alcotest.(check bool) "auth" true (s.source_auth = None);
        Alcotest.(check (option string)) "prefix" None s.source_name_prefix;
        Alcotest.(check int) "no plain bundles" 0 (List.length x.policy_bundles));
    tc "oci digest, port, plain_http on loopback" (fun () ->
        let d = "sha256:" ^ String.make 64 'f' in
        let x =
          ok
            (src
               (Printf.sprintf
                  "    bundle_source: {oci: 'localhost:5000/policies@%s', plain_http: \
                   true}\n\
                  \    name_prefix: prod.\n\
                  \    poll_interval_s: 10\n\
                  \    cache_dir: cache/bundles\n\
                  \    auth: {username: robot, password: pw}\n"
                  d))
        in
        let s = the_source x in
        let o = oci_of x in
        Alcotest.(check string) "registry" "localhost:5000" o.oci_registry;
        Alcotest.(check (option string)) "tag" None o.oci_tag;
        Alcotest.(check (option string)) "digest" (Some d) o.oci_digest;
        Alcotest.(check bool) "plain" true o.oci_plain_http;
        Alcotest.(check (option string)) "prefix" (Some "prod.") s.source_name_prefix;
        Alcotest.(check int) "poll" 10 s.poll_interval_s;
        Alcotest.(check (option string))
          "cache" (Some "/etc/haltsql/cache/bundles") s.cache_dir;
        Alcotest.(check bool)
          "auth" true
          (s.source_auth
          = Some (Config.Source_basic { username = "robot"; password = "pw" })));
    tc "oci tag and digest together, token auth" (fun () ->
        let d = "sha512:" ^ String.make 128 '0' in
        let x =
          ok
            (src
               (Printf.sprintf
                  "    bundle_source: {oci: 'registry.corp.example:443/a/b:v1.2@%s'}\n\
                  \    auth: {token: tok}\n"
                  d))
        in
        let o = oci_of x in
        Alcotest.(check (option string)) "tag" (Some "v1.2") o.oci_tag;
        Alcotest.(check (option string)) "digest" (Some d) o.oci_digest;
        Alcotest.(check bool)
          "token" true
          ((the_source x).source_auth = Some (Config.Source_token "tok")));
    tc "invalid OCI references" (fun () ->
        List.iter
          (fun (r, m) ->
            err ~path:(p0 "bundle_source.oci") ~msg:m
              (src (Printf.sprintf "    bundle_source: {oci: '%s'}\n" r)))
          [
            ("policies:prod", "expected registry/repository");
            ("corp/policies:prod", "is not a registry host");
            ("ghcr.io/Corp/policies:prod", "invalid repository");
            ("ghcr.io/corp//p:prod", "invalid repository");
            ("ghcr.io/corp/p", "needs a :tag or an @sha256");
            ("ghcr.io/corp/p:-bad", "invalid tag");
            ("ghcr.io/corp/p@sha256:abc", "the digest must be");
            ("ghcr.io/corp/p@md5:" ^ String.make 32 'a', "the digest must be");
            ("ghcr.io/corp/p@sha256:" ^ String.make 64 'F', "the digest must be");
            ("gh cr.io/corp/p:x", "must not be empty or contain whitespace");
            ("bad_host!/p:x", "invalid registry");
          ]);
    tc "plain_http only on loopback and only with oci" (fun () ->
        err
          ~path:(p0 "bundle_source.plain_http")
          ~msg:"only allowed on loopback"
          (src "    bundle_source: {oci: 'registry.corp.example/p:x', plain_http: true}\n");
        (* regression: DNS names that merely start with "127." are not loopback *)
        List.iter
          (fun host ->
            err
              ~path:(p0 "bundle_source.plain_http")
              ~msg:"only allowed on loopback"
              (src
                 (Printf.sprintf
                    "    bundle_source: {oci: '%s:5000/p:x', plain_http: true}\n" host)))
          [ "127.evil.example"; "127.0.0.1.nip.io" ];
        ignore
          (ok (src "    bundle_source: {oci: '127.0.0.2:5000/p:x', plain_http: true}\n"));
        err
          ~path:(p0 "bundle_source.plain_http")
          ~msg:"only allowed with oci"
          (src "    bundle_source: {https: 'https://b.example/x', plain_http: true}\n"));
    tc "s3 source" (fun () ->
        let x =
          ok
            (src
               "    bundle_source:\n\
               \      s3:\n\
               \        bucket: corp-bundles\n\
               \        key: haltsql/prod.haltsqlbundle\n\
               \        region: us-east-1\n\
               \        endpoint: 'http://127.0.0.1:9000'\n\
               \        credentials: {source: static, access_key_id: AK, \
                secret_access_key: SK}\n")
        in
        match (the_source x).location with
        | Config.Source_s3 s ->
            Alcotest.(check string) "bucket" "corp-bundles" s.src_bucket;
            Alcotest.(check string) "key" "haltsql/prod.haltsqlbundle" s.src_key;
            Alcotest.(check string) "region" "us-east-1" s.src_region;
            Alcotest.(check (option string))
              "endpoint" (Some "http://127.0.0.1:9000") s.src_endpoint;
            Alcotest.(check bool)
              "creds" true
              (s.src_credentials
              = Config.S3_static
                  { access_key_id = "AK"; secret_access_key = "SK"; session_token = None }
              )
        | _ -> Alcotest.fail "expected s3");
    tc "s3 source defaults to env credentials" (fun () ->
        let x =
          ok (src "    bundle_source: {s3: {bucket: bbb, key: k, region: eu-west-1}}\n")
        in
        match (the_source x).location with
        | Config.Source_s3 s ->
            Alcotest.(check bool) "env" true (s.src_credentials = Config.S3_env)
        | _ -> Alcotest.fail "expected s3");
    tc "s3 source errors" (fun () ->
        err
          ~path:(p0 "bundle_source.s3.bucket")
          ~msg:"required"
          (src "    bundle_source: {s3: {key: k, region: r}}\n");
        err ~path:(p0 "bundle_source.s3.key") ~msg:"required"
          (src "    bundle_source: {s3: {bucket: bbb, region: r}}\n");
        err
          ~path:(p0 "bundle_source.s3.region")
          ~msg:"required"
          (src "    bundle_source: {s3: {bucket: bbb, key: k}}\n");
        err
          ~path:(p0 "bundle_source.s3.bucket")
          ~msg:"invalid bucket name"
          (src "    bundle_source: {s3: {bucket: B, key: k, region: r}}\n");
        err ~path:(p0 "bundle_source.s3.key") ~msg:"must not start with '/'"
          (src "    bundle_source: {s3: {bucket: bbb, key: /k, region: r}}\n");
        err
          ~path:(p0 "bundle_source.s3.region")
          ~msg:"invalid region"
          (src "    bundle_source: {s3: {bucket: bbb, key: k, region: US}}\n");
        err
          ~path:(p0 "bundle_source.s3.credentials.access_key_id")
          ~msg:"only allowed when source is static"
          (src
             "    bundle_source: {s3: {bucket: bbb, key: k, region: r, credentials: \
              {access_key_id: x}}}\n");
        err ~path:(p0 "auth") ~msg:"use bundle_source.s3.credentials"
          (src
             "    bundle_source: {s3: {bucket: bbb, key: k, region: r}}\n\
             \    auth: {token: t}\n"));
    tc "https source" (fun () ->
        let x =
          ok
            (src
               "    bundle_source: {https: \
                'https://bundles.corp.example/prod.haltsqlbundle'}\n")
        in
        Alcotest.(check bool)
          "https" true
          ((the_source x).location
         = Config.Source_https "https://bundles.corp.example/prod.haltsqlbundle");
        ignore (ok (src "    bundle_source: {https: 'http://127.0.0.1:8000/b'}\n"));
        err ~path:(p0 "bundle_source.https")
          ~msg:"plain http is only allowed for loopback"
          (src "    bundle_source: {https: 'http://bundles.corp.example/b'}\n");
        err ~path:(p0 "bundle_source.https") ~msg:"must not contain a query"
          (src "    bundle_source: {https: 'https://b.example/b?sig=x'}\n"));
    tc "exactly one location" (fun () ->
        err ~path:(p0 "bundle_source") ~msg:"needs one of oci, s3 or https"
          (src "    bundle_source: {}\n");
        err ~path:(p0 "bundle_source") ~msg:"use only one of oci, s3 or https"
          (src "    bundle_source: {oci: 'ghcr.io/a/b:c', https: 'https://x/y'}\n");
        err ~path:(p0 "bundle_source.git") ~msg:"unknown key"
          (src "    bundle_source: {git: x}\n"));
    tc "public_keys are mandatory" (fun () ->
        err ~path:(p0 "public_keys") ~msg:"required"
          "policies:\n  - bundle_source: {oci: 'ghcr.io/a/b:c'}\n";
        err ~path:(p0 "public_keys") ~msg:"must not be empty"
          "policies:\n  - {bundle_source: {oci: 'ghcr.io/a/b:c'}, public_keys: []}\n";
        err ~path:(p0 "public_keys[0]") ~msg:"must be a public key"
          "policies:\n\
          \  - bundle_source: {oci: 'ghcr.io/a/b:c'}\n\
          \    public_keys: ['-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----']\n");
    tc "poll interval range" (fun () ->
        err ~path:(p0 "poll_interval_s") ~msg:"between 10 and 86400"
          (src "    bundle_source: {oci: 'ghcr.io/a/b:c'}\n    poll_interval_s: 5\n"));
    tc "name_prefix rules" (fun () ->
        err ~path:(p0 "name_prefix") ~msg:"invalid name_prefix"
          (src "    bundle_source: {oci: 'ghcr.io/a/b:c'}\n    name_prefix: '.x'\n"));
    tc "auth shapes" (fun () ->
        let b = "    bundle_source: {oci: 'ghcr.io/a/b:c'}\n" in
        err ~path:(p0 "auth") ~msg:"needs token, or username and password"
          (src (b ^ "    auth: {}\n"));
        err ~path:(p0 "auth") ~msg:"either token or username/password"
          (src (b ^ "    auth: {token: t, username: u, password: p}\n"));
        err ~path:(p0 "auth.password") ~msg:"required"
          (src (b ^ "    auth: {username: u}\n"));
        err ~path:(p0 "auth.username") ~msg:"required"
          (src (b ^ "    auth: {password: p}\n"));
        err ~path:(p0 "auth.username") ~msg:"must not contain ':'"
          (src (b ^ "    auth: {username: 'a:b', password: p}\n")));
    tc "source-only keys rejected elsewhere" (fun () ->
        err ~path:(p0 "poll_interval_s") ~msg:"only allowed with bundle_source"
          "policies:\n  - {bundle: a.b, public_keys: [k], poll_interval_s: 60}\n";
        err ~path:(p0 "cache_dir") ~msg:"only allowed with bundle_source"
          "policies:\n  - {inline: {metadata: {name: p}}, cache_dir: /c}\n";
        err ~path:(p0 "auth") ~msg:"only allowed with bundle_source"
          "policies:\n  - {path: p.yaml, auth: {token: t}}\n");
    tc "bundle_source exclusive with other forms" (fun () ->
        err ~path:"policies[0]"
          ~msg:"only one of path, inline or bundle (or bundle_source)"
          (src "    bundle_source: {oci: 'ghcr.io/a/b:c'}\n    bundle: a.b\n");
        err ~path:"policies[0]"
          ~msg:"only one of path, inline or bundle (or bundle_source)"
          (src
             "    bundle_source: {oci: 'ghcr.io/a/b:c'}\n\
             \    inline: {metadata: {name: p}}\n"));
    tc "duplicate bundle source" (fun () ->
        err ~path:"policies[1].bundle_source" ~msg:"duplicate bundle source"
          "policies:\n\
          \  - {bundle_source: {oci: 'ghcr.io/a/b:c'}, public_keys: [k]}\n\
          \  - {bundle_source: {oci: 'ghcr.io/a/b:c'}, public_keys: [k2]}\n");
    tc "unknown policy refs accepted with a bundle source" (fun () ->
        let x =
          ok
            ("server: {auth: {tokens: [{name: a, token_sha256: " ^ h1
           ^ ", policy: remote-policy}]}}\n\
              policies:\n\
             \  - {bundle_source: {oci: 'ghcr.io/a/b:c'}, public_keys: [k]}\n")
        in
        Alcotest.(check int) "sources" 1 (List.length x.bundle_sources));
    tc "source name_prefix restricts unknown refs" (fun () ->
        let base =
          "server: {auth: {tokens: [{name: a, token_sha256: " ^ h1
          ^ ", policy: %s}]}}\n\
             policies:\n\
            \  - {bundle_source: {oci: 'ghcr.io/a/b:c'}, public_keys: [k], name_prefix: \
             prod.}\n"
        in
        ignore (ok (Str_replace.replace base "%s" "prod.analytics"));
        err ~path:"server.auth.tokens[0].policy"
          ~msg:"not matching any bundle name_prefix: prod."
          (Str_replace.replace base "%s" "dev.analytics"));
    tc "prefixes of bundles and sources combine" (fun () ->
        let base =
          "server: {auth: {tokens: [{name: a, token_sha256: " ^ h1
          ^ ", policy: %s}]}}\n\
             policies:\n\
            \  - {bundle: a.b, public_keys: [k], name_prefix: local.}\n\
            \  - {bundle_source: {oci: 'ghcr.io/a/b:c'}, public_keys: [k], name_prefix: \
             remote.}\n"
        in
        ignore (ok (Str_replace.replace base "%s" "local.x"));
        ignore (ok (Str_replace.replace base "%s" "remote.x"));
        err ~path:"server.auth.tokens[0].policy" ~msg:"local., remote."
          (Str_replace.replace base "%s" "other.x"));
    tc "a source without prefix accepts any unknown ref" (fun () ->
        ignore
          (ok
             ("server: {auth: {tokens: [{name: a, token_sha256: " ^ h1
            ^ ", policy: anything}]}}\n\
               policies:\n\
              \  - {bundle: a.b, public_keys: [k], name_prefix: local.}\n\
              \  - {bundle_source: {oci: 'ghcr.io/a/b:c'}, public_keys: [k]}\n")));
  ]

(* ---------------------------------------------------------------------- *)
(* server.auth.oidc[].policy_from_groups                                  *)

let oidc extra =
  Printf.sprintf
    "server:\n\
    \  auth:\n\
    \    oidc:\n\
    \      - name: corp\n\
    \        issuer: https://idp.corp.example\n\
    \        audiences: [haltsql]\n\
     %s%s"
    extra pols

let groups_block =
  "        policy_from_groups:\n\
  \          map:\n\
  \            - {group: data-admins, policy: p2}\n\
  \            - {group: analysts, policy: p1}\n"

let gp k = "server.auth.oidc[0].policy_from_groups." ^ k

let groups_cases =
  [
    tc "policy_from_groups decodes with defaults" (fun () ->
        let x = ok (oidc groups_block) in
        let o = List.hd x.oidc in
        let g = Option.get (Config.groups_policy_of x o) in
        Alcotest.(check string) "claim" "groups" g.groups_claim;
        Alcotest.(check (list (pair string string)))
          "rules"
          [ ("data-admins", "p2"); ("analysts", "p1") ]
          (List.map
             (fun (r : Config.group_rule) -> (r.group, r.group_policy))
             g.group_rules);
        Alcotest.(check (option string)) "default" None g.group_default;
        (* fail-closed placeholder for consumers that ignore the mapping *)
        Alcotest.(check bool)
          "placeholder" true
          (o.oidc_policy = Config.Oidc_from_claim { claim = "groups"; allowed = [] }));
    tc "policy_from_groups with claim path and default" (fun () ->
        let x =
          ok
            (oidc
               "        policy_from_groups:\n\
               \          claim: realm_access.roles\n\
               \          map: [{group: 'Data Analysts', policy: p1}]\n\
               \          default: p2\n")
        in
        let g = Option.get (Config.groups_policy_of x (List.hd x.oidc)) in
        Alcotest.(check string) "claim" "realm_access.roles" g.groups_claim;
        Alcotest.(check (option string)) "default" (Some "p2") g.group_default);
    tc "providers without groups have no mapping" (fun () ->
        let x = ok (oidc "        policy: p1\n") in
        Alcotest.(check bool)
          "none" true
          (Config.groups_policy_of x (List.hd x.oidc) = None);
        Alcotest.(check int) "empty" 0 (List.length x.oidc_group_policies));
    tc "select_group_policy: first rule in config order wins" (fun () ->
        let x = ok (oidc groups_block) in
        let g = Option.get (Config.groups_policy_of x (List.hd x.oidc)) in
        Alcotest.(check (option string))
          "both" (Some "p2")
          (Config.select_group_policy g [ "analysts"; "data-admins" ]);
        Alcotest.(check (option string))
          "one" (Some "p1")
          (Config.select_group_policy g [ "x"; "analysts" ]);
        Alcotest.(check (option string))
          "none" None
          (Config.select_group_policy g [ "x" ]);
        Alcotest.(check (option string)) "empty" None (Config.select_group_policy g []);
        let g' = { g with group_default = Some "p1" } in
        Alcotest.(check (option string))
          "default" (Some "p1")
          (Config.select_group_policy g' [ "x" ]));
    tc "select_group_policy is exact and case sensitive" (fun () ->
        let x = ok (oidc groups_block) in
        let g = Option.get (Config.groups_policy_of x (List.hd x.oidc)) in
        Alcotest.(check (option string))
          "case" None
          (Config.select_group_policy g [ "Analysts"; "analyst"; " analysts" ]));
    tc "groups_of_claim" (fun () ->
        Alcotest.(check (option (list string)))
          "string" (Some [ "a b" ])
          (Config.groups_of_claim (`String "a b"));
        Alcotest.(check (option (list string)))
          "array"
          (Some [ "a"; "b" ])
          (Config.groups_of_claim (`List [ `String "a"; `String "b" ]));
        Alcotest.(check (option (list string)))
          "empty array" (Some [])
          (Config.groups_of_claim (`List []));
        Alcotest.(check (option (list string)))
          "mixed array" None
          (Config.groups_of_claim (`List [ `String "a"; `Int 1 ]));
        Alcotest.(check (option (list string)))
          "int" None
          (Config.groups_of_claim (`Int 1));
        Alcotest.(check (option (list string)))
          "object" None
          (Config.groups_of_claim (`Assoc [ ("a", `String "b") ])));
    tc "mutually exclusive with policy and policy_claim" (fun () ->
        err ~path:"server.auth.oidc[0]"
          ~msg:"only one of policy, policy_claim or policy_from_groups"
          (oidc ("        policy: p1\n" ^ groups_block));
        err ~path:"server.auth.oidc[0]"
          ~msg:"only one of policy, policy_claim or policy_from_groups"
          (oidc
             ("        policy_claim: pol\n        allowed_policies: [p1]\n" ^ groups_block));
        err ~path:"server.auth.oidc[0].allowed_policies"
          ~msg:"only allowed with policy_claim"
          (oidc ("        allowed_policies: [p1]\n" ^ groups_block)));
    tc "binding still required" (fun () ->
        err ~path:"server.auth.oidc[0]" ~msg:"or policy_from_groups" (oidc ""));
    tc "map required and non-empty" (fun () ->
        err ~path:(gp "map") ~msg:"required"
          (oidc "        policy_from_groups: {claim: g}\n");
        err ~path:(gp "map") ~msg:"must not be empty"
          (oidc "        policy_from_groups: {map: []}\n"));
    tc "rule fields" (fun () ->
        err ~path:(gp "map[0].group") ~msg:"required"
          (oidc "        policy_from_groups: {map: [{policy: p1}]}\n");
        err ~path:(gp "map[0].policy") ~msg:"required"
          (oidc "        policy_from_groups: {map: [{group: g}]}\n");
        err ~path:(gp "map[0].group") ~msg:"must not be empty"
          (oidc "        policy_from_groups: {map: [{group: '', policy: p1}]}\n");
        err ~path:(gp "map[0].group") ~msg:"control characters"
          (oidc "        policy_from_groups: {map: [{group: \"a\\tb\", policy: p1}]}\n");
        err ~path:(gp "map[0].policy") ~msg:"invalid policy name"
          (oidc "        policy_from_groups: {map: [{group: g, policy: 'a b'}]}\n");
        err ~path:(gp "map[0].role") ~msg:"unknown key"
          (oidc "        policy_from_groups: {map: [{group: g, policy: p1, role: x}]}\n"));
    tc "duplicate group" (fun () ->
        err ~path:(gp "map[1].group") ~msg:"duplicate group \"g\""
          (oidc
             "        policy_from_groups: {map: [{group: g, policy: p1}, {group: g, \
              policy: p2}]}\n"));
    tc "invalid claim path" (fun () ->
        err ~path:(gp "claim") ~msg:"invalid claim path"
          (oidc
             "        policy_from_groups: {claim: 'a..b', map: [{group: g, policy: p1}]}\n"));
    tc "referenced policies must exist" (fun () ->
        err ~path:(gp "map[1].policy") ~msg:"unknown policy \"nope\""
          (oidc
             "        policy_from_groups: {map: [{group: a, policy: p1}, {group: b, \
              policy: nope}]}\n");
        err ~path:(gp "default") ~msg:"unknown policy \"nope\""
          (oidc
             "        policy_from_groups: {map: [{group: a, policy: p1}], default: nope}\n"));
    tc "group policies may come from prefixed bundles" (fun () ->
        let base =
          "server:\n\
          \  auth:\n\
          \    oidc:\n\
          \      - name: corp\n\
          \        issuer: https://idp.corp.example\n\
          \        audiences: [haltsql]\n\
          \        policy_from_groups: {map: [{group: a, policy: %s}]}\n\
           policies:\n\
          \  - {bundle: a.b, public_keys: [k], name_prefix: prod.}\n"
        in
        ignore (ok (Str_replace.replace base "%s" "prod.a"));
        err ~path:(gp "map[0].policy") ~msg:"not matching any bundle name_prefix"
          (Str_replace.replace base "%s" "dev.a"));
    tc "unknown policy_from_groups key" (fun () ->
        err ~path:(gp "groups") ~msg:"unknown key"
          (oidc "        policy_from_groups: {groups: x, map: [{group: g, policy: p1}]}\n"));
  ]

(* ---------------------------------------------------------------------- *)
(* opa                                                                    *)

let opa_min = "opa: {url: 'http://127.0.0.1:8181', decision_path: haltsql/allow}\n"

let opa_cases =
  [
    tc "absent by default" (fun () ->
        Alcotest.(check bool) "none" true ((ok "").opa = None));
    tc "minimal opa with defaults" (fun () ->
        let o = Option.get (ok opa_min).opa in
        Alcotest.(check string) "url" "http://127.0.0.1:8181" o.opa_url;
        Alcotest.(check string) "path" "haltsql/allow" o.decision_path;
        Alcotest.(check int) "timeout" 500 o.opa_timeout_ms;
        Alcotest.(check bool) "on_error" true (o.opa_on_error = Config.Opa_deny);
        Alcotest.(check (list (pair string string))) "headers" [] o.opa_headers;
        Alcotest.(check bool) "ca" true (o.opa_ca = None));
    tc "full opa" (fun () ->
        let o =
          Option.get
            (ok
               ~env:(env_of [ ("OPA_TOKEN", "opa-secret-token") ])
               "opa:\n\
               \  url: https://opa.corp.example:8181/base\n\
               \  decision_path: corp/sql/haltsql_v2/allow\n\
               \  timeout_ms: 5000\n\
               \  on_error: allow_haltsql_verdict\n\
               \  headers: {Authorization: 'Bearer ${env:OPA_TOKEN}'}\n\
               \  tls: {ca_file: opa-ca.pem}\n")
              .opa
        in
        Alcotest.(check int) "timeout" 5000 o.opa_timeout_ms;
        Alcotest.(check bool)
          "on_error" true
          (o.opa_on_error = Config.Opa_allow_haltsql_verdict);
        Alcotest.(check (list (pair string string)))
          "headers"
          [ ("Authorization", "Bearer opa-secret-token") ]
          o.opa_headers;
        Alcotest.(check bool)
          "ca" true
          (o.opa_ca = Some (Config.Pem_path "/etc/haltsql/opa-ca.pem")));
    tc "url and decision_path required" (fun () ->
        err ~path:"opa.url" ~msg:"required" "opa: {decision_path: a}";
        err ~path:"opa.decision_path" ~msg:"required" "opa: {url: 'https://opa'}");
    tc "url rules" (fun () ->
        err ~path:"opa.url" ~msg:"plain http is only allowed for loopback"
          "opa: {url: 'http://opa.corp.example:8181', decision_path: a}";
        err ~path:"opa.url" ~msg:"must not contain a query"
          "opa: {url: 'https://opa/?x', decision_path: a}";
        ignore (ok "opa: {url: 'http://localhost:8181', decision_path: a}");
        ignore (ok "opa: {url: 'http://[::1]:8181', decision_path: a}"));
    tc "decision_path rules" (fun () ->
        List.iter
          (fun (d, m) ->
            err ~path:"opa.decision_path" ~msg:m
              (Printf.sprintf "opa: {url: 'https://opa', decision_path: '%s'}" d))
          [
            ("/haltsql/allow", "without a leading");
            ("v1/data/haltsql/allow", "without a leading");
            ("haltsql//allow", "Rego identifiers");
            ("haltsql/allow/", "Rego identifiers");
            ("haltsql/1allow", "Rego identifiers");
            ("haltsql/al-low", "Rego identifiers");
            ("haltsql.allow x", "Rego identifiers");
          ];
        err ~path:"opa.decision_path" ~msg:"must not be empty"
          "opa: {url: 'https://opa', decision_path: ''}");
    tc "timeout range" (fun () ->
        err ~path:"opa.timeout_ms" ~msg:"between 10 and 5000"
          "opa: {url: 'https://opa', decision_path: a, timeout_ms: 5001}";
        err ~path:"opa.timeout_ms" ~msg:"between 10 and 5000"
          "opa: {url: 'https://opa', decision_path: a, timeout_ms: 9}");
    tc "on_error values" (fun () ->
        err ~path:"opa.on_error" ~msg:"expected one of: deny, allow_haltsql_verdict"
          "opa: {url: 'https://opa', decision_path: a, on_error: allow}");
    tc "headers validated" (fun () ->
        err ~path:"opa.headers.\"bad header\"" ~msg:"invalid HTTP header name"
          "opa: {url: 'https://opa', decision_path: a, headers: {'bad header': x}}";
        err ~path:"opa.headers.X" ~msg:"must not contain CR, LF"
          "opa: {url: 'https://opa', decision_path: a, headers: {X: \"a\\r\\nb\"}}");
    tc "tls only with https" (fun () ->
        err ~path:"opa.tls" ~msg:"only used with an https url"
          "opa: {url: 'http://127.0.0.1:8181', decision_path: a, tls: {ca_file: /ca}}");
    tc "unknown opa key" (fun () ->
        err ~path:"opa.policy" ~msg:"unknown key"
          "opa: {url: 'https://opa', decision_path: a, policy: x}");
  ]

(* ---------------------------------------------------------------------- *)
(* server.admin                                                           *)

let ids =
  "server:\n\
  \  tls: {cert: /c.pem, key: /k.pem, client_ca: /ca.pem, client_auth: optional}\n\
  \  auth:\n\
  \    tokens:\n\
  \      - {name: ops, token_sha256: " ^ h1
  ^ ", policy: p1}\n      - {name: agent, token_sha256: " ^ h2
  ^ ", policy: p2}\n\
    \    oidc:\n\
    \      - {name: corp, issuer: 'https://idp.corp.example', audiences: [haltsql], \
     policy: p1}\n\
    \    mtls:\n\
    \      identities:\n\
    \        - {spiffe_id: 'spiffe://corp.example/ns/ops/sa/admin', policy: p1}\n\
    \        - {subject_cn: ops-console, policy: p1}\n"

let admin extra = ids ^ "  admin:\n" ^ extra ^ pols

let admin_cases =
  [
    tc "disabled by default" (fun () ->
        let x = ok "" in
        Alcotest.(check bool) "default" true (x.admin = Config.default_admin);
        Alcotest.(check bool) "disabled" false x.admin.admin_enabled;
        Alcotest.(check int) "window" 86_400 x.admin.report_window_seconds;
        Alcotest.(check int) "tracked" 10_000 x.admin.max_tracked_queries);
    tc "admin with every caller kind" (fun () ->
        let x =
          ok
            (admin
               "    enabled: true\n\
               \    callers: ['token:ops', 'oidc:corp', \
                'mtls:spiffe://corp.example/ns/ops/sa/admin', 'mtls:ops-console']\n\
               \    report_window: 7d\n\
               \    max_tracked_queries: 500\n")
        in
        Alcotest.(check bool) "enabled" true x.admin.admin_enabled;
        Alcotest.(check bool)
          "callers" true
          (x.admin.admin_callers
          = [
              Config.Admin_token "ops";
              Config.Admin_oidc "corp";
              Config.Admin_mtls (Config.Spiffe_id "spiffe://corp.example/ns/ops/sa/admin");
              Config.Admin_mtls (Config.Subject_cn "ops-console");
            ]);
        Alcotest.(check int) "window" (7 * 86_400) x.admin.report_window_seconds;
        Alcotest.(check int) "tracked" 500 x.admin.max_tracked_queries);
    tc "report_window units" (fun () ->
        List.iter
          (fun (w, secs) ->
            let x =
              ok (admin (Printf.sprintf "    enabled: false\n    report_window: %s\n" w))
            in
            Alcotest.(check int) w secs x.admin.report_window_seconds)
          [ ("60s", 60); ("1m", 60); ("90m", 5400); ("24h", 86_400); ("30d", 2_592_000) ]);
    tc "report_window errors" (fun () ->
        List.iter
          (fun (w, m) ->
            err ~path:"server.admin.report_window" ~msg:m
              (admin (Printf.sprintf "    report_window: '%s'\n" w)))
          [
            ("59s", "between 1m and 30d");
            ("31d", "between 1m and 30d");
            ("24", "invalid duration");
            ("1w", "invalid duration");
            ("h", "invalid duration");
            ("-1h", "invalid duration");
            ("1.5h", "invalid duration");
            ("", "invalid duration");
          ];
        err ~path:"server.admin.report_window" ~msg:"expected a string"
          (admin "    report_window: 3600\n"));
    tc "enabled needs callers" (fun () ->
        err ~path:"server.admin.callers" ~msg:"required when admin.enabled is true"
          (admin "    enabled: true\n");
        err ~path:"server.admin.callers" ~msg:"must not be empty when admin.enabled"
          (admin "    enabled: true\n    callers: []\n"));
    tc "callers must name configured identities" (fun () ->
        err ~path:"server.admin.callers[0]" ~msg:"unknown token \"nobody\""
          (admin "    enabled: true\n    callers: ['token:nobody']\n");
        err ~path:"server.admin.callers[0]" ~msg:"unknown OIDC provider \"okta\""
          (admin "    enabled: true\n    callers: ['oidc:okta']\n");
        err ~path:"server.admin.callers[0]" ~msg:"unknown mTLS identity"
          (admin "    enabled: true\n    callers: ['mtls:spiffe://corp.example/other']\n");
        err ~path:"server.admin.callers[0]" ~msg:"no such subject_cn"
          (admin "    enabled: true\n    callers: ['mtls:someone']\n"));
    tc "caller syntax" (fun () ->
        err ~path:"server.admin.callers[0]" ~msg:"invalid admin caller \"ops\""
          (admin "    enabled: true\n    callers: [ops]\n");
        err ~path:"server.admin.callers[0]" ~msg:"invalid admin caller"
          (admin "    enabled: true\n    callers: ['anonymous']\n");
        err ~path:"server.admin.callers[0]" ~msg:"empty name after \"token:\""
          (admin "    enabled: true\n    callers: ['token:']\n");
        err ~path:"server.admin.callers[1]" ~msg:"duplicate admin caller"
          (admin "    enabled: true\n    callers: ['token:ops', 'token:ops']\n"));
    tc "max_tracked_queries range" (fun () ->
        err ~path:"server.admin.max_tracked_queries" ~msg:"between 1 and 1000000"
          (admin "    max_tracked_queries: 0\n"));
    tc "unknown admin key" (fun () ->
        err ~path:"server.admin.port" ~msg:"unknown key" (admin "    port: 9090\n"));
  ]

(* ---------------------------------------------------------------------- *)
(* Redaction, round trip and schema                                       *)

let full_config =
  ids ^ "  admin: {enabled: true, callers: ['token:ops'], report_window: 12h}\n"
  ^ "audit:\n\
    \  sinks:\n\
    \    - type: elasticsearch\n\
    \      url: 'https://es.corp.example:9200'\n\
    \      index: haltsql\n\
    \      auth: {username: es-user, password: '${env:ES_PASSWORD}'}\n\
    \    - type: elasticsearch\n\
    \      url: 'http://127.0.0.1:9200'\n\
    \      data_stream: logs-haltsql\n\
    \      auth: {api_key: '${vault:secret/data/es#api_key}'}\n\
    \    - type: kafka\n\
    \      brokers: ['kafka.corp.example:9093']\n\
    \      topic: audit\n\
    \      tls: {ca_file: /kafka-ca.pem, cert_file: /kafka-client.pem, key_file: \
     '${file:KEYFILE}'}\n\
    \      sasl: {mechanism: scram-sha-256, username: kafka-user, password: \
     '${env:KAFKA_PASSWORD}'}\n\
    \      on_error: buffer\n\
    \      max_buffer_records: 20000\n\
     policies:\n\
    \  - inline: {metadata: {name: p1}}\n\
    \  - inline: {metadata: {name: p2}}\n\
    \  - bundle_source: {oci: 'ghcr.io/corp/policies:prod'}\n\
    \    public_keys: [/keys/release.pub]\n\
    \    auth: {username: robot, password: '${env:OCI_PASSWORD}'}\n\
    \  - bundle_source: {https: 'https://bundles.corp.example/b.haltsqlbundle'}\n\
    \    public_keys: [/keys/release.pub]\n\
    \    auth: {token: '${env:HTTPS_TOKEN}'}\n\
    \  - bundle_source:\n\
    \      s3: {bucket: corp-bundles, key: prod.haltsqlbundle, region: us-east-1, \
     credentials: {source: static, access_key_id: '${env:S3_AK}', secret_access_key: \
     '${env:S3_SK}', session_token: '${env:S3_ST}'}}\n\
    \    public_keys: [/keys/release.pub]\n\
     opa:\n\
    \  url: 'https://opa.corp.example'\n\
    \  decision_path: haltsql/allow\n\
    \  headers: {Authorization: '${env:OPA_TOKEN}'}\n"

let secret_env =
  env_of
    [
      ("ES_PASSWORD", "es-password-SECRET");
      ("KAFKA_PASSWORD", "kafka-password-SECRET");
      ("OCI_PASSWORD", "oci-password-SECRET");
      ("HTTPS_TOKEN", "https-token-SECRET");
      ("S3_AK", "AKID-SECRET");
      ("S3_SK", "s3-secret-key-SECRET");
      ("S3_ST", "s3-session-SECRET");
      ("OPA_TOKEN", "opa-token-SECRET");
    ]

let resolver ~scheme ~reference =
  match (scheme, reference) with
  | "vault", "secret/data/es#api_key" -> Ok "es-api-key-SECRET"
  | _ -> Error "no such secret"

let key_file () =
  let f = Filename.temp_file "hs" ".key" in
  Out_channel.with_open_bin f (fun oc ->
      output_string oc
        "-----BEGIN PRIVATE KEY-----\nkafka-key-SECRET\n-----END PRIVATE KEY-----\n");
  f

let all_secrets =
  [
    "es-password-SECRET";
    "es-api-key-SECRET";
    "kafka-password-SECRET";
    "kafka-key-SECRET";
    "oci-password-SECRET";
    "https-token-SECRET";
    "AKID-SECRET";
    "s3-secret-key-SECRET";
    "s3-session-SECRET";
    "opa-token-SECRET";
  ]

let redaction_cases =
  [
    tc "every new secret is resolved and redacted" (fun () ->
        let kf = key_file () in
        let x =
          ok ~env:secret_env ~resolve:resolver
            (Str_replace.replace full_config "KEYFILE" kf)
        in
        (* resolved in the typed config *)
        (match List.map (fun (s : Config.stream_sink) -> s.stream) x.stream_sinks with
        | [
         Config.Stream_elasticsearch
           { es_auth = Some (Config.Es_basic { password; _ }); _ };
         Config.Stream_elasticsearch { es_auth = Some (Config.Es_api_key k); _ };
         Config.Stream_kafka { kafka_sasl = Some sasl; kafka_tls = Some t; _ };
        ] ->
            Alcotest.(check string) "es pw" "es-password-SECRET" password;
            Alcotest.(check string) "es key" "es-api-key-SECRET" k;
            Alcotest.(check string) "sasl" "kafka-password-SECRET" sasl.sasl_password;
            Alcotest.(check bool)
              "inline key" true
              (match t.kafka_key with
              | Some (Config.Pem_inline s) -> contains s "kafka-key-SECRET"
              | _ -> false)
        | _ -> Alcotest.fail "unexpected stream sinks");
        let s = redacted_string x in
        check_hidden s all_secrets;
        check_shown s
          [
            "es-user";
            "kafka-user";
            "robot";
            "\"Authorization\"";
            "https://opa.corp.example";
            "ghcr.io/corp/policies:prod";
            "corp-bundles";
            "/kafka-ca.pem";
            "/kafka-client.pem";
            "token:ops";
            "<redacted>";
          ]);
    tc "redacted json shape for new sections" (fun () ->
        let kf = key_file () in
        let x =
          ok ~env:secret_env ~resolve:resolver
            (Str_replace.replace full_config "KEYFILE" kf)
        in
        let j = Config.to_json_redacted x in
        let open Yojson.Safe.Util in
        let sinks = j |> member "audit" |> member "sinks" |> to_list in
        Alcotest.(check int) "sinks" 3 (List.length sinks);
        let es0 = List.nth sinks 0 in
        Alcotest.(check string) "type" "elasticsearch" (es0 |> member "type" |> to_string);
        Alcotest.(check string)
          "pw" "<redacted>"
          (es0 |> member "auth" |> member "password" |> to_string);
        Alcotest.(check string)
          "api key" "<redacted>"
          (List.nth sinks 1 |> member "auth" |> member "api_key" |> to_string);
        let k = List.nth sinks 2 in
        Alcotest.(check string)
          "kafka key" "<redacted>"
          (k |> member "tls" |> member "key_file" |> to_string);
        Alcotest.(check string)
          "sasl pw" "<redacted>"
          (k |> member "sasl" |> member "password" |> to_string);
        Alcotest.(check int) "buffer" 20000 (k |> member "max_buffer_records" |> to_int);
        let srcs = j |> member "bundle_sources" |> to_list in
        Alcotest.(check int) "sources" 3 (List.length srcs);
        Alcotest.(check string)
          "oci pw" "<redacted>"
          (List.nth srcs 0 |> member "auth" |> member "password" |> to_string);
        Alcotest.(check string)
          "https token" "<redacted>"
          (List.nth srcs 1 |> member "auth" |> member "token" |> to_string);
        Alcotest.(check string)
          "s3 sk" "<redacted>"
          (List.nth srcs 2 |> member "bundle_source" |> member "s3"
         |> member "credentials" |> member "secret_access_key" |> to_string);
        Alcotest.(check string)
          "opa header" "<redacted>"
          (j |> member "opa" |> member "headers" |> member "Authorization" |> to_string);
        Alcotest.(check int)
          "admin window" 43_200
          (j |> member "server" |> member "admin"
          |> member "report_window_seconds"
          |> to_int));
    tc "groups mapping rendered instead of the placeholder" (fun () ->
        let x = ok (oidc groups_block) in
        let j = Config.to_json_redacted x in
        let open Yojson.Safe.Util in
        let o = j |> member "server" |> member "auth" |> member "oidc" |> index 0 in
        Alcotest.(check bool) "no claim" true (member "policy_claim" o = `Null);
        Alcotest.(check string)
          "first group" "data-admins"
          (o |> member "policy_from_groups" |> member "map" |> index 0 |> member "group"
         |> to_string));
    tc "inline PEM ca values are not printed" (fun () ->
        let f = Filename.temp_file "hs" ".pem" in
        Out_channel.with_open_bin f (fun oc ->
            output_string oc
              "-----BEGIN CERTIFICATE-----\nCAPEMBODY\n-----END CERTIFICATE-----\n");
        let x =
          ok
            (Printf.sprintf
               "opa: {url: 'https://opa', decision_path: a, tls: {ca_file: '${file:%s}'}}"
               f)
        in
        let s = redacted_string x in
        Alcotest.(check bool) "body hidden" false (contains s "CAPEMBODY");
        Alcotest.(check bool) "marker" true (contains s "<inline PEM>"));
    tc "provider placeholders in new secrets need a resolver" (fun () ->
        err ~path:"audit.sinks[0].auth.api_key" ~msg:"secret provider not configured"
          (es (es_min ^ "      auth: {api_key: '${vault:secret/data/es#k}'}\n")));
    tc "unset env in a new secret is a located error" (fun () ->
        err ~path:"opa.headers.X" ~msg:"environment variable NOPE is not set"
          "opa: {url: 'https://opa', decision_path: a, headers: {X: '${env:NOPE}'}}");
    tc "schema covers the new keys" (fun () ->
        let s = Yojson.Safe.to_string Schemas.config in
        List.iter
          (fun k -> Alcotest.(check bool) k true (contains s ("\"" ^ k ^ "\"")))
          [
            "opa";
            "decision_path";
            "allow_haltsql_verdict";
            "admin";
            "report_window";
            "max_tracked_queries";
            "policy_from_groups";
            "bundle_source";
            "poll_interval_s";
            "cache_dir";
            "plain_http";
            "elasticsearch";
            "data_stream";
            "pipeline";
            "kafka";
            "brokers";
            "scram-sha-512";
            "max_buffer_records";
            "flush_interval_ms";
            "drop";
          ];
        let open Yojson.Safe.Util in
        Alcotest.(check bool)
          "top-level opa" true
          (List.mem "opa" (keys (member "properties" Schemas.config))));
    tc "existing example configs still load unchanged" (fun () ->
        let x =
          get_ok
            (Config.of_file
               ~env:
                 (env_of
                    [
                      ("HALTSQL_ANALYTICS_TOKEN_HASH", h1);
                      ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4317");
                    ])
               (ex "config/haltsql.yaml"))
        in
        Alcotest.(check int) "no stream sinks" 0 (List.length x.stream_sinks);
        Alcotest.(check int) "no sources" 0 (List.length x.bundle_sources);
        Alcotest.(check bool) "no opa" true (x.opa = None);
        Alcotest.(check bool) "admin off" true (x.admin = Config.default_admin));
  ]

let tests =
  [
    ("config-t3-elasticsearch", es_cases);
    ("config-t3-kafka", kafka_cases);
    ("config-t3-bundle-source", bundle_source_cases);
    ("config-t3-oidc-groups", groups_cases);
    ("config-t3-opa", opa_cases);
    ("config-t3-admin", admin_cases);
    ("config-t3-redaction", redaction_cases);
  ]
