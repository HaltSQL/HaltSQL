(* Pure unit tests for haltsql-server.siem: CRC-32C vectors, murmur2 (the Java
   client's partitioner), varints, RecordBatch v2 layout, Kafka response
   decoding, SCRAM (RFC 7677) and PBKDF2 (RFC 7914) vectors, the _bulk body and
   item classification, and the batching engine's policies driven by a scripted
   in-process transport (no network). *)

open Haltsql_siem
module Config = Haltsql_load.Config
module W = Kafka_wire

let run = Lwt_main.run

let hex s =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq s)))

let unhex h =
  String.init
    (String.length h / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (i * 2) 2)))

(* ---- CRC-32C ---- *)

let test_crc32c () =
  let check name expected s = Alcotest.(check int) name expected (Crc32c.string s) in
  check "123456789" 0xE3069283 "123456789";
  check "empty" 0 "";
  (* RFC 3720 (iSCSI) appendix B.4 *)
  check "32 zeros" 0x8A9136AA (String.make 32 '\000');
  check "32 0xff" 0x62A8AB43 (String.make 32 '\255');
  check "ascending" 0x46DD794E (String.init 32 Char.chr);
  check "descending" 0x113FDB5C (String.init 32 (fun i -> Char.chr (31 - i)));
  let s = "The quick brown fox jumps over the lazy dog" in
  Alcotest.(check int)
    "incremental" (Crc32c.string s)
    (Crc32c.string
       ~crc:(Crc32c.string (String.sub s 0 10))
       (String.sub s 10 (String.length s - 10)));
  Alcotest.(check int) "substring" (Crc32c.string "brown") (Crc32c.substring s 10 5)

(* ---- murmur2: vectors from Apache Kafka's UtilsTest ---- *)

let test_murmur2 () =
  List.iter
    (fun (s, v) -> Alcotest.(check int32) s v (W.murmur2 s))
    [
      ("21", -973932308l);
      ("foobar", -790332482l);
      ("a-little-bit-long-string", -985981536l);
      ("a-little-bit-longer-string", -1486304829l);
      ("lkjh234lh9fiuh90y23oiuhsafujhadof229phr9h19h89h8", -58897971l);
      ("abc", 479470107l);
    ];
  Alcotest.(check int)
    "partition is in range" 1
    (W.partition_for_key "21" ~partitions:1 + 1);
  for n = 1 to 20 do
    let p = W.partition_for_key "haltsql/host/run" ~partitions:n in
    Alcotest.(check bool) "in range" true (p >= 0 && p < n)
  done

(* ---- varints ---- *)

let test_varint () =
  let enc n =
    let b = Buffer.create 8 in
    W.zigzag_varint b n;
    hex (Buffer.contents b)
  in
  List.iter
    (fun (n, h) -> Alcotest.(check string) (string_of_int n) h (enc n))
    [
      (0, "00");
      (-1, "01");
      (1, "02");
      (63, "7e");
      (-64, "7f");
      (64, "8001");
      (300, "d804");
    ];
  List.iter
    (fun n ->
      let b = Buffer.create 8 in
      W.zigzag_varint b n;
      let pos = ref 0 in
      Alcotest.(check int) "roundtrip" n (W.read_zigzag_varint (Buffer.contents b) pos))
    [ 0; 1; -1; 127; -128; 1 lsl 20; -(1 lsl 31); max_int / 4; min_int / 4 ]

(* ---- RecordBatch v2 ---- *)

let test_record_batch_golden () =
  (* One record, key "k", value "v", timestamp 0: every byte follows from the
     RecordBatch v2 layout in the Kafka protocol guide. *)
  let b = W.record_batch ~timestamp_ms:0L [ { W.key = Some "k"; value = "v" } ] in
  let tail =
    "0000" ^ "00000000" ^ "0000000000000000" ^ "0000000000000000" ^ "ffffffffffffffff"
    ^ "ffff" ^ "ffffffff" ^ "00000001" ^ "10" ^ "00" ^ "00" ^ "00" ^ "02" ^ "6b" ^ "02"
    ^ "76" ^ "00"
  in
  let crc = Crc32c.string (unhex tail) in
  let expected =
    "0000000000000000" ^ "0000003a" ^ "ffffffff" ^ "02" ^ Printf.sprintf "%08x" crc ^ tail
  in
  Alcotest.(check string) "bytes" expected (hex b);
  Alcotest.(check int) "length" 70 (String.length b)

let test_record_batch_layout () =
  let records =
    List.init 5 (fun i ->
        {
          W.key = (if i = 2 then None else Some "chain");
          value = String.make (i * 70) 'x';
        })
  in
  let b = W.record_batch ~timestamp_ms:1_700_000_000_123L records in
  Alcotest.(check int64) "base offset" 0L (String.get_int64_be b 0);
  Alcotest.(check int32)
    "batch length"
    (Int32.of_int (String.length b - 12))
    (String.get_int32_be b 8);
  Alcotest.(check int32) "leader epoch" (-1l) (String.get_int32_be b 12);
  Alcotest.(check int) "magic" 2 (Char.code b.[16]);
  Alcotest.(check int) "attributes" 0 (String.get_int16_be b 21);
  Alcotest.(check int32) "last offset delta" 4l (String.get_int32_be b 23);
  Alcotest.(check int64) "base ts" 1_700_000_000_123L (String.get_int64_be b 27);
  Alcotest.(check int64) "max ts" 1_700_000_000_123L (String.get_int64_be b 35);
  Alcotest.(check int64) "producer id" (-1L) (String.get_int64_be b 43);
  Alcotest.(check int32) "count" 5l (String.get_int32_be b 57);
  let d = W.decode_record_batch b in
  Alcotest.(check bool) "crc" true d.crc_ok;
  Alcotest.(check int)
    "crc value"
    (Crc32c.substring b 21 (String.length b - 21))
    (Int32.to_int (String.get_int32_be b 17) land 0xFFFFFFFF);
  Alcotest.(check int) "records" 5 (List.length d.records);
  List.iter2
    (fun (a : W.record) (b : W.record) ->
      Alcotest.(check (option string)) "key" a.key b.key;
      Alcotest.(check string) "value" a.value b.value)
    records d.records;
  (* any flipped byte after the CRC field is detected *)
  let bad = Bytes.of_string b in
  Bytes.set bad 70 'y';
  Alcotest.(check bool)
    "tamper" false (W.decode_record_batch (Bytes.to_string bad)).crc_ok

(* ---- Kafka responses ---- *)

let i16 b n = Buffer.add_uint16_be b (n land 0xFFFF)
let i32 b n = Buffer.add_int32_be b (Int32.of_int n)
let i64 b n = Buffer.add_int64_be b (Int64.of_int n)

let str b s =
  i16 b (String.length s);
  Buffer.add_string b s

let metadata_v8 () =
  let b = Buffer.create 128 in
  i32 b 0 (* throttle *);
  i32 b 1;
  i32 b 1;
  str b "localhost";
  i32 b 19092;
  i16 b (-1) (* rack *);
  i16 b (-1) (* cluster id *);
  i32 b 1 (* controller *);
  i32 b 1 (* topics *);
  i16 b 0;
  str b "audit";
  Buffer.add_char b '\000';
  i32 b 2 (* partitions, out of order *);
  List.iter
    (fun p ->
      i16 b 0;
      i32 b p;
      i32 b 1 (* leader *);
      i32 b 0 (* epoch *);
      i32 b 1;
      i32 b 1 (* replicas *);
      i32 b 1;
      i32 b 1 (* isr *);
      i32 b 0 (* offline *))
    [ 1; 0 ];
  i32 b 0 (* topic authorized operations *);
  i32 b 0;
  Buffer.contents b

let test_decode_metadata () =
  let brokers, tm = W.decode_metadata ~version:8 ~topic:"audit" (metadata_v8 ()) in
  Alcotest.(check int) "brokers" 1 (List.length brokers);
  Alcotest.(check string) "host" "localhost" (List.hd brokers).host;
  Alcotest.(check int) "port" 19092 (List.hd brokers).port;
  Alcotest.(check (list int))
    "partitions sorted" [ 0; 1 ]
    (List.map (fun (p : W.partition_meta) -> p.partition) tm.partitions);
  Alcotest.check_raises "unknown topic"
    (W.Malformed "metadata response does not mention the topic") (fun () ->
      ignore (W.decode_metadata ~version:8 ~topic:"other" (metadata_v8 ())));
  (* every truncation is a Malformed, never another exception *)
  let s = metadata_v8 () in
  for n = 0 to String.length s - 1 do
    match W.decode_metadata ~version:8 ~topic:"audit" (String.sub s 0 n) with
    | _ -> Alcotest.failf "truncated at %d accepted" n
    | exception W.Malformed _ -> ()
  done;
  (* a huge array count is refused before allocating *)
  let b = Buffer.create 8 in
  i32 b 0;
  i32 b 0x7FFFFFF0;
  match W.decode_metadata ~version:8 ~topic:"audit" (Buffer.contents b) with
  | _ -> Alcotest.fail "huge count accepted"
  | exception W.Malformed _ -> ()

let test_decode_produce () =
  let resp ~version err =
    let b = Buffer.create 64 in
    i32 b 1;
    str b "audit";
    i32 b 1;
    i32 b 2 (* partition *);
    i16 b err;
    i64 b 42;
    i64 b (-1);
    if version >= 5 then i64 b 0;
    if version >= 8 then begin
      i32 b 0;
      str b "boom"
    end;
    i32 b 0 (* throttle *);
    Buffer.contents b
  in
  List.iter
    (fun version ->
      let err, off, msg =
        W.decode_produce ~version ~topic:"audit" ~partition:2 (resp ~version 6)
      in
      Alcotest.(check int) "error" 6 err;
      Alcotest.(check int64) "offset" 42L off;
      Alcotest.(check (option string))
        "msg"
        (if version >= 8 then Some "boom" else None)
        msg)
    [ 3; 5; 7; 8 ];
  Alcotest.(check bool) "6 refreshes" true (W.refresh_metadata 6);
  Alcotest.(check bool) "10 is not retriable" false (W.retriable 10);
  Alcotest.(check string) "name" "NOT_LEADER_OR_FOLLOWER" (W.error_name 6)

let test_frame () =
  let f = W.frame ~api_key:18 ~api_version:0 ~correlation_id:7l ~client_id:"haltsql" "" in
  Alcotest.(check string)
    "ApiVersions v0 frame"
    ("00000011" ^ "0012" ^ "0000" ^ "00000007" ^ "0007" ^ hex "haltsql")
    (hex f)

(* ---- SCRAM ---- *)

let test_scram_rfc7677 () =
  let cf = Scram.client_first ~nonce:"rOprNGfwEbeRWgbNEkqO" ~username:"user" () in
  Alcotest.(check string) "client-first" "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" cf.message;
  let server_first =
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
  in
  match Scram.client_final Scram.Sha256 ~password:"pencil" cf ~server_first with
  | Error e -> Alcotest.fail e
  | Ok (final, expected) ->
      Alcotest.(check string)
        "client-final"
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        final;
      Alcotest.(check string)
        "server signature" "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" expected;
      Alcotest.(check (result unit string))
        "server-final ok" (Ok ())
        (Scram.verify_server_final ~expected
           "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
      let is_error = function Ok () -> false | Error _ -> true in
      Alcotest.(check bool)
        "wrong signature" true
        (is_error
           (Scram.verify_server_final ~expected
              "v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
      Alcotest.(check bool)
        "server error" true
        (is_error (Scram.verify_server_final ~expected "e=invalid-proof"));
      Alcotest.(check bool)
        "garbage" true
        (is_error (Scram.verify_server_final ~expected "x"))

let test_scram_rejects () =
  let cf = Scram.client_first ~nonce:"abc" ~username:"u" () in
  let bad sf =
    match Scram.client_final Scram.Sha256 ~password:"p" cf ~server_first:sf with
    | Ok _ -> Alcotest.failf "accepted %s" sf
    | Error _ -> ()
  in
  bad "r=xyz123,s=c2FsdA==,i=4096" (* nonce not extended *);
  bad "r=abc,s=c2FsdA==,i=4096" (* nonce not longer *);
  bad "r=abcd,s=c2FsdA==,i=1" (* too few iterations *);
  bad "r=abcd,s=c2FsdA==,i=99999999";
  bad "m=ext,r=abcd,s=c2FsdA==,i=4096";
  bad "r=abcd,i=4096";
  Alcotest.(check string)
    "escaping" "n,,n=a=3Db=2Cc,r=n"
    (Scram.client_first ~nonce:"n" ~username:"a=b,c" ()).message;
  let n1 = (Scram.client_first ~username:"u" ()).nonce
  and n2 = (Scram.client_first ~username:"u" ()).nonce in
  Alcotest.(check bool) "random nonces" true (n1 <> n2 && String.length n1 >= 24)

(* SCRAM-SHA-512 has no RFC vector: check the client against an independent
   server-side computation (RFC 5802 section 3) written here with Digestif. *)
let test_scram_sha512_consistency () =
  let module H = Digestif.SHA512 in
  let hmac key m = H.(to_raw_string (hmac_string ~key m)) in
  let password = "s3cr3t-p@ss" and salt = "0123456789abcdef" and iterations = 4096 in
  let cf = Scram.client_first ~username:"haltsql" () in
  let server_nonce = cf.nonce ^ "SERVERPART" in
  let server_first =
    Printf.sprintf "r=%s,s=%s,i=%d" server_nonce (Base64.encode_string salt) iterations
  in
  match Scram.client_final Scram.Sha512 ~password cf ~server_first with
  | Error e -> Alcotest.fail e
  | Ok (final, expected) ->
      (* server: recompute, check the proof, sign *)
      let salted = Scram.hi Scram.Sha512 ~password ~salt ~iterations in
      let stored = H.(to_raw_string (digest_string (hmac salted "Client Key"))) in
      let without_proof = "c=biws,r=" ^ server_nonce in
      let auth = cf.bare ^ "," ^ server_first ^ "," ^ without_proof in
      let proof =
        match String.split_on_char ',' final |> List.rev with
        | p :: _ when String.length p > 2 ->
            Base64.decode_exn (String.sub p 2 (String.length p - 2))
        | _ -> Alcotest.fail "no proof"
      in
      let client_sig = hmac stored auth in
      let client_key =
        String.init (String.length proof) (fun i ->
            Char.chr (Char.code proof.[i] lxor Char.code client_sig.[i]))
      in
      Alcotest.(check string)
        "proof verifies" (hex stored)
        (hex H.(to_raw_string (digest_string client_key)));
      Alcotest.(check string)
        "server signature"
        (Base64.encode_string (hmac (hmac salted "Server Key") auth))
        expected

let test_pbkdf2_rfc7914 () =
  Alcotest.(check string)
    "c=1" "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    (hex (Scram.hi Scram.Sha256 ~password:"passwd" ~salt:"salt" ~iterations:1));
  Alcotest.(check string)
    "c=80000" "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
    (hex (Scram.hi Scram.Sha256 ~password:"Password" ~salt:"NaCl" ~iterations:80000))

(* ---- Elasticsearch ---- *)

let test_bulk_body () =
  let e = { Stream_sink.line = {|{"a":"x\"y","hash":"h1"}|}; hash = "h1" } in
  let doc =
    {|{"a":"x\"y","hash":"h1","event":{"original":"{\"a\":\"x\\\"y\",\"hash\":\"h1\"}"}}|}
  in
  Alcotest.(check string) "document" doc (Es_sink.document e.line);
  (match Yojson.Safe.from_string doc with
  | `Assoc kv -> (
      match List.assoc_opt "event" kv with
      | Some (`Assoc [ ("original", `String o) ]) ->
          Alcotest.(check string) "exact line" e.line o
      | _ -> Alcotest.fail "event.original")
  | _ -> Alcotest.fail "not an object");
  Alcotest.(check string)
    "index"
    ({|{"create":{"_index":"haltsql-audit","_id":"h1"}}|} ^ "\n" ^ doc ^ "\n")
    (Es_sink.bulk_body (Config.Es_index "haltsql-audit") [| e |]);
  Alcotest.(check string)
    "data stream"
    ({|{"create":{"_index":"logs-haltsql-prod","_id":"h1"}}|} ^ "\n" ^ doc ^ "\n")
    (Es_sink.bulk_body (Config.Es_data_stream "logs-haltsql-prod") [| e |])

let pp_item ppf = function
  | Stream_sink.Delivered -> Format.pp_print_string ppf "delivered"
  | Stream_sink.Retry _ -> Format.pp_print_string ppf "retry"
  | Stream_sink.Rejected { reason; detail } ->
      Format.fprintf ppf "rejected %s %s" reason detail

let item =
  Alcotest.testable pp_item (fun a b ->
      match (a, b) with
      | Stream_sink.Delivered, Stream_sink.Delivered -> true
      | Stream_sink.Retry _, Stream_sink.Retry _ -> true
      | Stream_sink.Rejected a, Stream_sink.Rejected b ->
          a.reason = b.reason && a.detail = b.detail
      | _ -> false)

let test_classify () =
  let body =
    {|{"errors":true,"items":[
      {"create":{"status":201}},
      {"create":{"status":409,"error":{"type":"version_conflict_engine_exception"}}},
      {"create":{"status":400,"error":{"type":"document_parsing_exception"}}},
      {"create":{"status":400,"error":{"type":"mapper_parsing_exception"}}},
      {"create":{"status":429,"error":{"type":"es_rejected_execution_exception"}}},
      {"create":{"status":503,"error":{"type":"unavailable_shards_exception"}}},
      {"create":{"status":400,"error":{"type":"illegal_argument_exception"}}},
      {"create":{"status":403,"error":{"type":"cluster_block_exception"}}}]}|}
  in
  match Es_sink.classify_items 8 body with
  | Error e -> Alcotest.fail e
  | Ok r ->
      Alcotest.(check (array item))
        "items"
        Stream_sink.
          [|
            Delivered;
            Delivered;
            Rejected { reason = "mapping"; detail = "document_parsing_exception" };
            Rejected { reason = "mapping"; detail = "mapper_parsing_exception" };
            Retry "";
            Retry "";
            Retry "";
            Retry "";
          |]
        r;
      Alcotest.(check bool)
        "count mismatch" true
        (Result.is_error (Es_sink.classify_items 7 body));
      Alcotest.(check bool)
        "garbage" true
        (Result.is_error (Es_sink.classify_items 1 "nope"))

let test_prepare () =
  (match Es_sink.prepare [ ("ts", `String "2026-01-01T00:00:00Z"); ("x", `Int 1) ] with
  | ("@timestamp", `String "2026-01-01T00:00:00Z") :: ("ts", _) :: _ -> ()
  | _ -> Alcotest.fail "copy of ts");
  (match Es_sink.prepare [ ("x", `Int 1) ] with
  | ("@timestamp", `String s) :: _ ->
      Alcotest.(check bool) "utc" true (s.[String.length s - 1] = 'Z')
  | _ -> Alcotest.fail "now");
  match Es_sink.prepare [ ("@timestamp", `String "t") ] with
  | [ ("@timestamp", `String "t") ] -> ()
  | _ -> Alcotest.fail "kept"

(* ---- the engine, with a scripted in-process transport ---- *)

let batch n =
  { Config.batch_max_records = n; batch_max_bytes = 1 lsl 20; flush_interval_ms = 1000 }

let fields i = [ ("i", `Int i) ]

let make ?(max_buffer = 100) ?(attempts = 2) ~on_error deliver =
  match
    Stream_sink.create ~max_attempts:attempts ~base_backoff:0. ~max_backoff:0.
      ~jitter:(fun () -> 1.)
      ~name:"test" ~kind:"kafka" ~batch:(batch 4) ~on_error ~max_buffer_records:max_buffer
      deliver
  with
  | Ok s -> s
  | Error e -> Alcotest.fail e

let test_engine_batches_and_chain () =
  let shipped = ref [] and sizes = ref [] in
  let deliver (es : Stream_sink.entry array) =
    sizes := Array.length es :: !sizes;
    shipped :=
      !shipped @ Array.to_list (Array.map (fun (e : Stream_sink.entry) -> e.line) es);
    Lwt.return (Ok (Array.map (fun _ -> Stream_sink.Delivered) es))
  in
  let s = make ~on_error:Config.Stream_fail_closed deliver in
  for i = 1 to 10 do
    Alcotest.(check (result unit string)) "write" (Ok ()) (Stream_sink.write s (fields i))
  done;
  Alcotest.(check (result unit string)) "flush" (Ok ()) (run (Stream_sink.flush s));
  Alcotest.(check (list int)) "batch sizes" [ 4; 4; 2 ] (List.rev !sizes);
  Alcotest.(check (result int (pair int string)))
    "chain" (Ok 10)
    (Haltsql_cloud.Audit_chain.verify_lines !shipped);
  Alcotest.(check int) "delivered" 10 (Stream_sink.stats s).records_delivered

let test_engine_partial_retry () =
  (* records whose "i" is odd fail once; only they are resent *)
  let seen = Hashtbl.create 8 and calls = ref [] in
  let deliver (es : Stream_sink.entry array) =
    calls := Array.length es :: !calls;
    Lwt.return
      (Ok
         (Array.map
            (fun (e : Stream_sink.entry) ->
              let i =
                match Yojson.Safe.from_string e.line with
                | `Assoc kv -> ( match List.assoc "i" kv with `Int i -> i | _ -> 0)
                | _ -> 0
              in
              if i = 3 then Stream_sink.Rejected { reason = "mapping"; detail = "t" }
              else if i mod 2 = 1 && not (Hashtbl.mem seen i) then begin
                Hashtbl.add seen i ();
                Stream_sink.Retry "busy"
              end
              else Stream_sink.Delivered)
            es))
  in
  let s = make ~on_error:Config.Stream_fail_closed deliver in
  for i = 0 to 3 do
    ignore (Stream_sink.write s (fields i))
  done;
  Alcotest.(check (result unit string)) "flush" (Ok ()) (run (Stream_sink.flush s));
  Alcotest.(check (list int)) "resent only the failed item" [ 4; 1 ] (List.rev !calls);
  let st = Stream_sink.stats s in
  Alcotest.(check int) "delivered" 3 st.records_delivered;
  Alcotest.(check (list (pair string int)))
    "dropped"
    [ ("mapping", 1) ]
    st.records_dropped;
  Alcotest.(check int) "retries" 1 st.retries;
  let m = Stream_sink.metrics_text [ s ] in
  let contains sub =
    let n = String.length sub in
    let rec go i = i + n <= String.length m && (String.sub m i n = sub || go (i + 1)) in
    go 0
  in
  Alcotest.(check bool)
    "metric" true
    (contains
       {|haltsql_audit_stream_sink_records_dropped_total{sink="test",type="kafka",reason="mapping"} 1|})

let failing _ = Lwt.return (Error "down")

let test_engine_fail_closed () =
  let s = make ~on_error:Config.Stream_fail_closed failing in
  ignore (Stream_sink.write s (fields 1));
  Alcotest.(check bool) "flush fails" true (Result.is_error (run (Stream_sink.flush s)));
  Alcotest.(check bool) "unhealthy" false (Stream_sink.healthy s);
  Alcotest.(check bool)
    "write refused" true
    (Result.is_error (Stream_sink.write s (fields 2)));
  let st = Stream_sink.stats s in
  Alcotest.(check int) "buffered" 1 st.buffered_records;
  Alcotest.(check int) "rejections" 1 st.write_rejections;
  Alcotest.(check int) "failures" 1 st.delivery_failures

let test_engine_buffer_bound () =
  let s = make ~max_buffer:6 ~on_error:Config.Stream_buffer failing in
  ignore (Stream_sink.write s (fields 0));
  ignore (run (Stream_sink.flush s));
  for i = 1 to 5 do
    Alcotest.(check (result unit string))
      "buffered write" (Ok ())
      (Stream_sink.write s (fields i))
  done;
  Alcotest.(check bool) "full: unhealthy" false (Stream_sink.healthy s);
  Alcotest.(check bool)
    "full: refused" true
    (Result.is_error (Stream_sink.write s (fields 6)))

let test_engine_drop () =
  let up = ref false and got = ref [] in
  let deliver (es : Stream_sink.entry array) =
    if !up then begin
      got := !got @ Array.to_list (Array.map (fun (e : Stream_sink.entry) -> e.line) es);
      Lwt.return (Ok (Array.map (fun _ -> Stream_sink.Delivered) es))
    end
    else Lwt.return (Error "down")
  in
  let s = make ~on_error:Config.Stream_drop deliver in
  ignore (Stream_sink.write s (fields 0));
  ignore (run (Stream_sink.flush s));
  Alcotest.(check (result unit string))
    "dropped write is Ok" (Ok ())
    (Stream_sink.write s (fields 1));
  Alcotest.(check bool) "always healthy" true (Stream_sink.healthy s);
  Alcotest.(check (list (pair string int)))
    "counted"
    [ ("on_error_drop", 1) ]
    (Stream_sink.stats s).records_dropped;
  up := true;
  Alcotest.(check (result unit string)) "recovers" (Ok ()) (run (Stream_sink.flush s));
  ignore (Stream_sink.write s (fields 2));
  ignore (run (Stream_sink.flush s));
  (* the dropped record was never sealed: the shipped chain is intact *)
  Alcotest.(check (result int (pair int string)))
    "chain intact" (Ok 2)
    (Haltsql_cloud.Audit_chain.verify_lines !got)

let test_engine_background () =
  let got = ref 0 in
  let deliver (es : Stream_sink.entry array) =
    got := !got + Array.length es;
    Lwt.return (Ok (Array.map (fun _ -> Stream_sink.Delivered) es))
  in
  let s =
    match
      Stream_sink.create ~name:"bg" ~kind:"elasticsearch"
        ~batch:
          {
            Config.batch_max_records = 100;
            batch_max_bytes = 1 lsl 20;
            flush_interval_ms = 20;
          }
        ~on_error:Config.Stream_fail_closed ~max_buffer_records:1000 deliver
    with
    | Ok s -> s
    | Error e -> Alcotest.fail e
  in
  Stream_sink.start s;
  for i = 1 to 3 do
    ignore (Stream_sink.write s (fields i))
  done;
  run (Lwt_unix.sleep 0.3);
  Alcotest.(check int) "shipped by the interval" 3 !got;
  Alcotest.(check (result unit string)) "close" (Ok ()) (run (Stream_sink.close s));
  Alcotest.(check bool)
    "closed refuses" true
    (Result.is_error (Stream_sink.write s (fields 9)))

let () =
  Alcotest.run "siem-unit"
    [
      ( "kafka-encoding",
        [
          Alcotest.test_case "crc32c vectors" `Quick test_crc32c;
          Alcotest.test_case "murmur2 vectors" `Quick test_murmur2;
          Alcotest.test_case "varints" `Quick test_varint;
          Alcotest.test_case "record batch golden" `Quick test_record_batch_golden;
          Alcotest.test_case "record batch layout" `Quick test_record_batch_layout;
          Alcotest.test_case "metadata decoding" `Quick test_decode_metadata;
          Alcotest.test_case "produce decoding" `Quick test_decode_produce;
          Alcotest.test_case "request frame" `Quick test_frame;
        ] );
      ( "scram",
        [
          Alcotest.test_case "RFC 7677 SCRAM-SHA-256" `Quick test_scram_rfc7677;
          Alcotest.test_case "rejects bad server messages" `Quick test_scram_rejects;
          Alcotest.test_case "SCRAM-SHA-512 consistency" `Quick
            test_scram_sha512_consistency;
          Alcotest.test_case "PBKDF2 RFC 7914" `Quick test_pbkdf2_rfc7914;
        ] );
      ( "elasticsearch",
        [
          Alcotest.test_case "bulk body" `Quick test_bulk_body;
          Alcotest.test_case "item classification" `Quick test_classify;
          Alcotest.test_case "@timestamp" `Quick test_prepare;
        ] );
      ( "engine",
        [
          Alcotest.test_case "batches and chain" `Quick test_engine_batches_and_chain;
          Alcotest.test_case "partial retry" `Quick test_engine_partial_retry;
          Alcotest.test_case "fail closed" `Quick test_engine_fail_closed;
          Alcotest.test_case "buffer bound" `Quick test_engine_buffer_bound;
          Alcotest.test_case "drop" `Quick test_engine_drop;
          Alcotest.test_case "background flush" `Quick test_engine_background;
        ] );
    ]
