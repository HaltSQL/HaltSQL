(* console/02-records: audit ingestion (files, directories, globs, rotation, S3, GCS),
   queries search, record detail (trail, reasons, custody), raw SQL and chain checks. *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console

let genesis = String.make 64 '0'

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  go 0

(** Seals records into one hash chain like the server's sinks; returns the JSON lines. *)
let seal ?(prev = genesis) records =
  let _, lines =
    List.fold_left
      (fun (prev, acc) j ->
        match j with
        | `Assoc kv ->
            let body =
              List.filter (fun (k, _) -> k <> "prev_hash" && k <> "hash") kv
              @ [ ("prev_hash", `String prev) ]
            in
            let h = Haltsql.sha256_hex (prev ^ Yojson.Safe.to_string (`Assoc body)) in
            (h, Yojson.Safe.to_string (`Assoc (body @ [ ("hash", `String h) ])) :: acc)
        | _ -> assert false)
      (prev, []) records
  in
  List.rev lines

let recs ?(prefix = "r") n =
  List.init n (fun i -> server_record ~request_id:(Printf.sprintf "%s%d" prefix i) ())

let write_file ?(append = false) path lines =
  let flags =
    if append then [ Open_wronly; Open_append; Open_creat; Open_binary ]
    else [ Open_wronly; Open_trunc; Open_creat; Open_binary ]
  in
  let oc = open_out_gen flags 0o600 path in
  List.iter
    (fun l ->
      output_string oc l;
      output_char oc '\n')
    lines;
  close_out oc

let audit_cfg ?role sources =
  config ?role
    ~extra:[ ("audit", `Assoc [ ("sources", `List sources); ("poll_seconds", `Int 1) ]) ]
    ()

let file_src ?(verifier = "haltsql-1") path =
  `Assoc [ ("verifier", `String verifier); ("file", `String path) ]

let ids (r : running) =
  C.Index.fold r.ctx.index ~init:[] ~f:(fun acc e -> e.C.Index.request_id :: acc)
  |> List.rev

let poll ?env (r : running) =
  let st = C.Ingest.create ?env r.ctx.config in
  fun () -> C.Ingest.poll_once r.ctx st

let status_field (r : running) i name =
  match C.Ingest.status r.ctx with `List l -> member name (List.nth l i) | _ -> `Null

(* ---- ingestion ---- *)

let ingest_tests =
  [
    ( "file append and partial line",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        let f = Filename.concat d "audit.jsonl" in
        let lines = seal (recs 6) in
        write_file f (List.filteri (fun i _ -> i < 3) lines);
        with_console ~background:false
          (audit_cfg [ file_src f ])
          (fun r ->
            let poll = poll r in
            let* () = poll () in
            Alcotest.(check int) "3 records" 3 (C.Index.size r.ctx.index);
            let* () = poll () in
            Alcotest.(check int) "read once" 3 (C.Index.size r.ctx.index);
            (* two complete lines plus half of the sixth *)
            write_file ~append:true f [ List.nth lines 3; List.nth lines 4 ];
            let sixth = List.nth lines 5 in
            let half = String.length sixth / 2 in
            let oc = open_out_gen [ Open_wronly; Open_append; Open_binary ] 0o600 f in
            output_string oc (String.sub sixth 0 half);
            close_out oc;
            let* () = poll () in
            Alcotest.(check int) "complete lines only" 5 (C.Index.size r.ctx.index);
            let oc = open_out_gen [ Open_wronly; Open_append; Open_binary ] 0o600 f in
            output_string oc (String.sub sixth half (String.length sixth - half) ^ "\n");
            close_out oc;
            let* () = poll () in
            Alcotest.(check (list string))
              "all, in order"
              [ "r0"; "r1"; "r2"; "r3"; "r4"; "r5" ]
              (ids r);
            let s = C.Index.verifier_stream r.ctx.index "haltsql-1" in
            Alcotest.(check (list int))
              "seq" [ 0; 1; 2; 3; 4; 5 ]
              (List.map (fun e -> e.C.Index.seq) s);
            Alcotest.(check string) "location" (f ^ "#L6") (List.nth s 5).C.Index.location;
            Alcotest.(check string)
              "status records" "6"
              (Yojson.Safe.to_string (status_field r 0 "records"));
            Alcotest.(check bool) "no error" true (status_field r 0 "error" = `Null);
            Lwt.return_unit) );
    ( "truncation and rotation restart from 0",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        let f = Filename.concat d "audit.jsonl" in
        write_file f (seal (recs ~prefix:"a" 3));
        with_console ~background:false
          (audit_cfg [ file_src f ])
          (fun r ->
            let poll = poll r in
            let* () = poll () in
            Alcotest.(check int) "first" 3 (C.Index.size r.ctx.index);
            (* truncated in place *)
            write_file f (seal (recs ~prefix:"b" 1));
            let* () = poll () in
            Alcotest.(check int) "after truncation" 4 (C.Index.size r.ctx.index);
            Alcotest.(check bool) "b0" true (C.Index.find r.ctx.index "b0" <> None);
            (* replaced by a new, larger file (new inode) *)
            let tmp = Filename.concat d "next.tmp" in
            write_file tmp (seal (recs ~prefix:"c" 5));
            Sys.rename tmp f;
            let* () = poll () in
            Alcotest.(check int) "after rotation" 9 (C.Index.size r.ctx.index);
            let s = C.Index.verifier_stream r.ctx.index "haltsql-1" in
            Alcotest.(check (list int))
              "seq keeps increasing" (List.init 9 Fun.id)
              (List.map (fun e -> e.C.Index.seq) s);
            Lwt.return_unit) );
    ( "directory with auto verifier names",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        write_file (Filename.concat d "haltsql-a.jsonl") (seal (recs ~prefix:"a" 2));
        write_file
          (Filename.concat d "haltsql-b.log")
          ("not json" :: "{\"msg\":\"a log line\"}" :: seal (recs ~prefix:"b" 3));
        write_file (Filename.concat d "notes.txt") (seal (recs ~prefix:"x" 1));
        with_console ~background:false
          (audit_cfg [ file_src ~verifier:"auto" d ])
          (fun r ->
            let* () = poll r () in
            Alcotest.(check int) "records" 5 (C.Index.size r.ctx.index);
            Alcotest.(check (list string))
              "verifiers" [ "haltsql-a"; "haltsql-b" ]
              (C.Index.verifiers r.ctx.index);
            Alcotest.(check bool) "txt ignored" true (C.Index.find r.ctx.index "x0" = None);
            Alcotest.(check (list int))
              "seq per verifier" [ 0; 1; 2 ]
              (List.map
                 (fun e -> e.C.Index.seq)
                 (C.Index.verifier_stream r.ctx.index "haltsql-b"));
            Lwt.return_unit) );
    ( "glob",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        write_file (Filename.concat d "audit-1.jsonl") (seal (recs ~prefix:"a" 2));
        write_file (Filename.concat d "audit-2.jsonl") (seal (recs ~prefix:"b" 2));
        write_file (Filename.concat d "other.jsonl") (seal (recs ~prefix:"c" 2));
        with_console ~background:false
          (audit_cfg [ file_src (Filename.concat d "audit-*.jsonl") ])
          (fun r ->
            let* () = poll r () in
            Alcotest.(check (list string)) "matched" [ "a0"; "a1"; "b0"; "b1" ] (ids r);
            Lwt.return_unit) );
    ( "missing file reports an error",
      `Quick,
      fun () ->
        with_console ~background:false
          (audit_cfg [ file_src "/nonexistent/haltsql/audit.jsonl" ])
          (fun r ->
            let* () = poll r () in
            Alcotest.(check bool) "error" true (status_field r 0 "error" <> `Null);
            Lwt.return_unit) );
    ( "object names",
      `Quick,
      fun () ->
        let sha = String.make 64 'a' in
        Alcotest.(check (option string))
          "host" (Some "haltsql-2")
          (C.Ingest.host_of_object_name
             ("p/2026/11/07/13/haltsql-2-20261107T130000.000001Z.42-0000000412-" ^ sha
            ^ ".jsonl"));
        Alcotest.(check (option string))
          "not an object name" None
          (C.Ingest.host_of_object_name "audit.jsonl");
        Alcotest.(check string)
          "configured wins" "v"
          (C.Ingest.infer_verifier ~configured:"v" "x.jsonl");
        Alcotest.(check string)
          "basename" "audit"
          (C.Ingest.infer_verifier ~configured:"auto" "/var/log/audit.jsonl") );
  ]

(* ---- fake object stores ---- *)

let with_http handler f =
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
  let server =
    Cohttp_lwt_unix.Server.make ~callback:(fun _ req _body -> handler req) ()
  in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~stop:stop_p ~mode:(`TCP (`Socket fd)) server);
  Lwt.finalize
    (fun () -> f port)
    (fun () ->
      Lwt.wakeup_later stop ();
      Lwt.return_unit)

let object_key ~prefix ~host ~seq body =
  Printf.sprintf "%s2026/11/07/13/%s-20261107T130000.000001Z.42-%010d-%s.jsonl" prefix
    host seq (Haltsql.sha256_hex body)

let respond ?(headers = []) body =
  Cohttp_lwt_unix.Server.respond_string
    ~headers:(Cohttp.Header.of_list headers)
    ~status:`OK ~body ()

let objects_tests =
  [
    ( "s3 objects read once, host as verifier",
      `Quick,
      fun () ->
        let lines = seal (recs ~prefix:"s" 4) in
        let body1 = String.concat "\n" (List.filteri (fun i _ -> i < 2) lines) ^ "\n" in
        let body2 = String.concat "\n" (List.filteri (fun i _ -> i >= 2) lines) ^ "\n" in
        let k1 = object_key ~prefix:"haltsql/" ~host:"haltsql-2" ~seq:1 body1 in
        let k2 = object_key ~prefix:"haltsql/" ~host:"haltsql-2" ~seq:2 body2 in
        let store = ref [ (k1, body1) ] in
        let gets = ref 0 in
        let handler req =
          let uri = Cohttp.Request.uri req in
          let path = Uri.pct_decode (Uri.path uri) in
          if Uri.get_query_param uri "list-type" = Some "2" then
            respond
              ("<ListBucketResult>"
              ^ String.concat ""
                  (List.map
                     (fun (k, _) -> "<Contents><Key>" ^ k ^ "</Key></Contents>")
                     !store)
              ^ "<IsTruncated>false</IsTruncated></ListBucketResult>")
          else
            let key =
              String.sub path 8 (String.length path - 8)
              (* "/bucket/" *)
            in
            incr gets;
            match List.assoc_opt key !store with
            | Some b -> respond b
            | None -> Cohttp_lwt_unix.Server.respond_string ~status:`Not_found ~body:"" ()
        in
        Lwt_main.run
          (with_http handler (fun port ->
               let env = function
                 | "AWS_ACCESS_KEY_ID" -> Some "AKIDEXAMPLE"
                 | "AWS_SECRET_ACCESS_KEY" -> Some "secret"
                 | _ -> None
               in
               let cfg =
                 audit_cfg
                   [
                     `Assoc
                       [
                         ("verifier", `String "auto");
                         ("s3", `String "s3://bucket/haltsql/");
                         ("region", `String "us-east-1");
                         ("endpoint", `String (Printf.sprintf "http://127.0.0.1:%d" port));
                       ];
                   ]
               in
               let* r = start ~background:false cfg in
               Lwt.finalize
                 (fun () ->
                   let poll = poll ~env r in
                   let* () = poll () in
                   Alcotest.(check int) "first object" 2 (C.Index.size r.ctx.index);
                   store := !store @ [ (k2, body2) ];
                   let* () = poll () in
                   Alcotest.(check int) "second object" 4 (C.Index.size r.ctx.index);
                   Alcotest.(check int) "each object fetched once" 2 !gets;
                   Alcotest.(check (list string))
                     "verifier from object name" [ "haltsql-2" ]
                     (C.Index.verifiers r.ctx.index);
                   let e = Option.get (C.Index.find r.ctx.index "s3") in
                   Alcotest.(check string)
                     "location"
                     ("s3://bucket/" ^ k2 ^ "#L2")
                     e.C.Index.location;
                   let* code, rec_ = get r "/api/v1/records/s3" in
                   Alcotest.(check int) "record" 200 code;
                   Alcotest.(check string)
                     "intact across objects" "\"intact\""
                     (Yojson.Safe.to_string (member "custody.chain_state" rec_));
                   Alcotest.(check string)
                     "verify command"
                     (Printf.sprintf
                        "\"haltsql audit verify s3://bucket/haltsql/ --host haltsql-2 \
                         --region us-east-1 --endpoint http://127.0.0.1:%d\""
                        port)
                     (Yojson.Safe.to_string (member "custody.verify_command" rec_));
                   Lwt.return_unit)
                 (fun () ->
                   Helpers.stop r;
                   Lwt.return_unit))) );
    ( "gcs objects",
      `Quick,
      fun () ->
        let lines = seal (recs ~prefix:"g" 3) in
        let body = String.concat "\n" lines ^ "\n" in
        let k = object_key ~prefix:"audit/" ~host:"haltsql-9" ~seq:0 body in
        let auth_sent = ref false in
        let handler req =
          let uri = Cohttp.Request.uri req in
          let path = Uri.pct_decode (Uri.path uri) in
          let auth = Cohttp.Header.get (Cohttp.Request.headers req) "authorization" in
          if String.starts_with ~prefix:"/computeMetadata/" path then
            respond
              ~headers:[ ("metadata-flavor", "Google") ]
              "{\"access_token\":\"tok\",\"expires_in\":3600}"
          else begin
            if auth <> None then auth_sent := true;
            if path = "/storage/v1/b/bkt/o" then
              respond (Printf.sprintf "{\"items\":[{\"name\":%S}]}" k)
            else if path = "/storage/v1/b/bkt/o/" ^ k then respond body
            else Cohttp_lwt_unix.Server.respond_string ~status:`Not_found ~body:"" ()
          end
        in
        Lwt_main.run
          (with_http handler (fun port ->
               let host = Printf.sprintf "http://127.0.0.1:%d" port in
               let env = function
                 | "STORAGE_EMULATOR_HOST" | "GCE_METADATA_HOST" -> Some host
                 | _ -> None
               in
               let cfg =
                 audit_cfg
                   [
                     `Assoc
                       [
                         ("verifier", `String "auto"); ("gcs", `String "gs://bkt/audit/");
                       ];
                   ]
               in
               let* r = start ~background:false cfg in
               Lwt.finalize
                 (fun () ->
                   let* () = poll ~env r () in
                   Alcotest.(check int) "records" 3 (C.Index.size r.ctx.index);
                   Alcotest.(check bool)
                     "no credentials sent to the emulator" false !auth_sent;
                   Alcotest.(check (list string))
                     "verifier" [ "haltsql-9" ]
                     (C.Index.verifiers r.ctx.index);
                   let* _, rec_ = get r "/api/v1/records/g1" in
                   Alcotest.(check bool)
                     "gcs verify command" true
                     (match member "custody.verify_command" rec_ with
                     | `String s ->
                         String.starts_with ~prefix:"gcloud storage cp -r gs://bkt/audit/"
                           s
                         && String.ends_with ~suffix:"--host haltsql-9" s
                     | _ -> false);
                   Lwt.return_unit)
                 (fun () ->
                   Helpers.stop r;
                   Lwt.return_unit))) );
  ]

(* ---- chain of custody ---- *)

let load_lines ?(verifier = "haltsql-1") (r : running) lines =
  load_records ~verifier r (List.map Yojson.Safe.from_string lines)

let chain_tests =
  [
    ( "intact chain, neighbours, file command",
      `Quick,
      fun () ->
        let d = temp_dir "chain" in
        let f = Filename.concat d "audit.jsonl" in
        write_file f (seal (recs 5));
        with_console ~background:false
          (audit_cfg [ file_src f ])
          (fun r ->
            let* () = poll r () in
            let* code, j = get r "/api/v1/records/r2" in
            Alcotest.(check int) "200" 200 code;
            let c = member "custody" j in
            Alcotest.(check string)
              "intact" "\"intact\""
              (Yojson.Safe.to_string (member "chain_state" c));
            Alcotest.(check int)
              "seq" 2
              (match member "seq" c with `Int n -> n | _ -> -1);
            Alcotest.(check int)
              "neighbours" 4
              (match member "neighbours" c with `List l -> List.length l | _ -> 0);
            Alcotest.(check string)
              "command"
              ("\"haltsql audit verify " ^ f ^ "\"")
              (Yojson.Safe.to_string (member "verify_command" c));
            Alcotest.(check string)
              "location"
              ("\"" ^ f ^ "#L3\"")
              (Yojson.Safe.to_string (member "location" c));
            Lwt.return_unit) );
    ( "tampered record breaks the chain",
      `Quick,
      fun () ->
        let lines = seal (recs 5) in
        let tampered =
          List.mapi
            (fun i l ->
              if i = 2 then
                match Yojson.Safe.from_string l with
                | `Assoc kv ->
                    Yojson.Safe.to_string
                      (`Assoc
                         (List.map
                            (fun (k, v) ->
                              if k = "caller" then (k, `String "token:someone-else")
                              else (k, v))
                            kv))
                | _ -> l
              else l)
            lines
        in
        with_console ~background:false (config ~role:"analyst" ()) (fun r ->
            load_lines r tampered;
            let* _, j = get r "/api/v1/records/r3" in
            Alcotest.(check string)
              "broken" "\"broken\""
              (Yojson.Safe.to_string (member "custody.chain_state" j));
            Alcotest.(check string)
              "first break at the tampered record" "\"r2\""
              (Yojson.Safe.to_string (member "custody.first_break.request_id" j));
            let* code, c = post r "/api/v1/records/r3/verify-chain" (`Assoc []) in
            Alcotest.(check int) "verify-chain" 200 code;
            Alcotest.(check string)
              "still broken" "\"broken\""
              (Yojson.Safe.to_string (member "chain_state" c));
            (match member "chains" (C.Chain.status r.ctx) with
            | `List [ ch ] ->
                Alcotest.(check string)
                  "chain_status" "\"broken\""
                  (Yojson.Safe.to_string (member "state" ch));
                Alcotest.(check string)
                  "records" "5"
                  (Yojson.Safe.to_string (member "records" ch))
            | _ -> Alcotest.fail "chain_status not updated");
            let* _, acts = get r "/api/v1/activity?action=record.verify_chain" in
            Alcotest.(check int)
              "logged" 1
              (match member "entries" acts with `List l -> List.length l | _ -> 0);
            Lwt.return_unit) );
    ( "restarts, unchained records and check_all",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            (* two chains (a restart at genesis) for one verifier, one unchained record
               for another *)
            load_lines r (seal (recs ~prefix:"a" 3) @ seal (recs ~prefix:"b" 2));
            load_records ~verifier:"legacy" r
              [
                `Assoc
                  (List.filter
                     (fun (k, _) -> k <> "hash" && k <> "prev_hash")
                     (match server_record ~request_id:"u0" () with
                     | `Assoc kv -> kv
                     | _ -> []));
              ];
            C.Chain.check_all r.ctx;
            let state v =
              match member "chains" (C.Chain.status r.ctx) with
              | `List l ->
                  List.find_map
                    (fun c ->
                      if member "verifier" c = `String v then
                        Some (Yojson.Safe.to_string (member "state" c))
                      else None)
                    l
              | _ -> None
            in
            Alcotest.(check (option string))
              "restart ok" (Some "\"intact\"") (state "haltsql-1");
            Alcotest.(check (option string))
              "unchained" (Some "\"unknown\"") (state "legacy");
            let* _, j = get r "/api/v1/records/u0" in
            Alcotest.(check string)
              "record unknown" "\"unknown\""
              (Yojson.Safe.to_string (member "custody.chain_state" j));
            Lwt.return_unit) );
  ]

(* ---- trail ---- *)

let policy_yaml =
  "apiVersion: haltsql.dev/v1\n\
   kind: Policy\n\
   metadata: {name: shop}\n\
   search_path: [app]\n\
   statements: { allow: [select] }\n\
   require_limit: { max: 100 }\n\
   tenancy:\n\
  \  mode: bound\n\
  \  keys: { tenant: \"${ctx.tenant_id}\" }\n\
   tables:\n\
  \  app.customers:\n\
  \    columns: [id, tenant_id, name]\n\
  \    tenant_column: tenant_id\n"

let shop_policy () =
  match Haltsql.Policy_load.of_string Haltsql.Docload.Yaml policy_yaml with
  | Ok p -> p
  | Error errs ->
      Alcotest.failf "policy: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string errs))

let stage name j =
  match member "trail" j with
  | `List l -> (
      match List.find_opt (fun s -> member "stage" s = `String name) l with
      | Some s -> ( match member "state" s with `String x -> x | _ -> "?")
      | None -> "missing")
  | _ -> "no trail"

let trail_tests =
  [
    ( "trail from codes",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            load_records r
              [
                server_record ~request_id:"ten" ~allowed:false
                  ~codes:[ "E_TENANT_MISMATCH" ] ();
                server_record ~request_id:"parse" ~allowed:false ~codes:[ "E_PARSE" ] ();
                server_record ~request_id:"opa" ~allowed:false
                  ~codes:[ "E_EXTERNAL_POLICY" ] ();
                server_record ~request_id:"shadow" ~allowed:true ~shadow:true
                  ~codes:[ "E_LIMIT_REQUIRED" ] ();
                server_record ~request_id:"ok" ();
              ];
            let* _, ten = get r "/api/v1/records/ten" in
            Alcotest.(check (list string))
              "tenancy denial"
              [ "passed"; "passed"; "denied"; "passed"; "passed"; "not_run"; "denied" ]
              (List.map
                 (fun s -> stage s ten)
                 [ "parse"; "tables"; "tenancy"; "limit"; "functions"; "opa"; "verdict" ]);
            Alcotest.(check string)
              "source" "\"codes\""
              (Yojson.Safe.to_string (member "trail_source" ten));
            (match member "reasons" ten with
            | `List [ x ] ->
                Alcotest.(check string)
                  "code" "\"E_TENANT_MISMATCH\""
                  (Yojson.Safe.to_string (member "code" x))
            | _ -> Alcotest.fail "one reason");
            let* _, p = get r "/api/v1/records/parse" in
            Alcotest.(check (list string))
              "parse stops everything"
              [
                "denied"; "not_run"; "not_run"; "not_run"; "not_run"; "not_run"; "denied";
              ]
              (List.map
                 (fun s -> stage s p)
                 [ "parse"; "tables"; "tenancy"; "limit"; "functions"; "opa"; "verdict" ]);
            let* _, o = get r "/api/v1/records/opa" in
            Alcotest.(check (list string))
              "opa denied after haltsql allowed"
              [ "passed"; "denied"; "denied" ]
              (List.map (fun s -> stage s o) [ "tenancy"; "opa"; "verdict" ]);
            let* _, s = get r "/api/v1/records/shadow" in
            Alcotest.(check (list string))
              "shadow"
              [ "denied"; "passed"; "passed" ]
              (List.map (fun x -> stage x s) [ "limit"; "opa"; "verdict" ]);
            let* _, ok = get r "/api/v1/records/ok" in
            Alcotest.(check string) "allowed" "passed" (stage "verdict" ok);
            let* nf = get r "/api/v1/records/nope" in
            check_status "unknown record" 404 nf;
            Lwt.return_unit) );
    ( "trail from re-verification",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            C.Policy_set.set r.ctx @@ [ ("shop", shop_policy ()) ];
            load_records r
              [
                server_record ~request_id:"col" ~policy:"shop" ~allowed:false
                  ~codes:[ "E_COLUMN_DENIED" ]
                  ~sql:"SELECT email FROM app.customers WHERE tenant_id = $1 LIMIT 5" ();
                server_record ~request_id:"nosql" ~policy:"shop" ~allowed:false
                  ~codes:[ "E_COLUMN_DENIED" ] ();
              ];
            let* _, j = get r "/api/v1/records/col" in
            Alcotest.(check string)
              "source" "\"reverified\""
              (Yojson.Safe.to_string (member "trail_source" j));
            Alcotest.(check string) "tables denied" "denied" (stage "tables" j);
            Alcotest.(check string)
              "redacted by default" "\"redacted\""
              (Yojson.Safe.to_string (member "reasons_detail" j));
            (match member "reasons" j with
            | `List (x :: _) ->
                Alcotest.(check string)
                  "rule" "\"columns.denied\""
                  (Yojson.Safe.to_string (member "rule" x));
                Alcotest.(check bool)
                  "generic message" false
                  (contains (Yojson.Safe.to_string j) "email")
            | _ -> Alcotest.fail "reasons");
            (* admin has no see_raw_sql *)
            let* denied = get ~reason:"x" r "/api/v1/records/col?details=full" in
            check_status "admin full details" 403 denied;
            Alcotest.(check string)
              "loaded version" "true"
              (string_of_bool (member "policy.loaded_version" j <> `Null));
            let* _, n = get r "/api/v1/records/nosql" in
            Alcotest.(check string)
              "no sql: codes" "\"codes\""
              (Yojson.Safe.to_string (member "trail_source" n));
            Lwt.return_unit) );
  ]

(* ---- search ---- *)

let proxy_record ~id ~tables : Yojson.Safe.t =
  `Assoc
    [
      ("ts", `String (C.Api.iso8601 (Unix.gettimeofday ())));
      ("event", `String "statement");
      ("session", `String id);
      ("user", `String "pg:alice");
      ("policy", `String "analytics");
      ("allowed", `Bool true);
      ("reasons", `List []);
      ("shadow_reasons", `List []);
      ("tables", `List (List.map (fun t -> `String t) tables));
      ("fingerprint", `String "ffff000011112222");
    ]

let count j = match member "records" j with `List l -> List.length l | _ -> -1

let search_tests =
  [
    ( "filters and pagination",
      `Quick,
      fun () ->
        with_console ~background:false (config ~role:"dev" ()) (fun r ->
            let now = Unix.gettimeofday () in
            load_records r
              [
                server_record ~request_id:"0001-a" ~ts:(now -. 7200.) ~caller:"token:bot"
                  ~sql:"SELECT 1" ();
                server_record ~request_id:"0002-b" ~ts:(now -. 60.) ~allowed:false
                  ~codes:[ "E_TENANT_MISMATCH" ] ~policy:"support" ();
                server_record ~request_id:"0003-c" ~ts:(now -. 30.) ~allowed:true
                  ~shadow:true ~codes:[ "E_LIMIT_REQUIRED" ] ();
              ];
            load_records ~verifier:"proxy-1" r
              [ proxy_record ~id:"sess" ~tables:[ "app.orders" ] ];
            let q path =
              let* code, j = get r path in
              Alcotest.(check int) path 200 code;
              Lwt.return j
            in
            let* all = q "/api/v1/queries" in
            Alcotest.(check int) "all" 4 (count all);
            Alcotest.(check string)
              "total" "4"
              (Yojson.Safe.to_string (member "total" all));
            (match member "records" all with
            | `List l ->
                List.iter
                  (fun x -> Alcotest.(check bool) "no sql" true (member "sql" x = `Null))
                  l;
                Alcotest.(check string)
                  "newest first" "\"0001-a\""
                  (Yojson.Safe.to_string (member "request_id" (List.nth l 3)))
            | _ -> ());
            let* d = q "/api/v1/queries?outcome=denied" in
            Alcotest.(check int) "denied" 1 (count d);
            let* s = q "/api/v1/queries?outcome=shadow_denied" in
            Alcotest.(check int) "shadow" 1 (count s);
            let* c = q "/api/v1/queries?code=E_TENANT_MISMATCH" in
            Alcotest.(check int) "code" 1 (count c);
            let* p = q "/api/v1/queries?policy=support" in
            Alcotest.(check int) "policy" 1 (count p);
            let* cl = q "/api/v1/queries?caller=bot" in
            Alcotest.(check int) "caller" 1 (count cl);
            let* t = q "/api/v1/queries?table=orders" in
            Alcotest.(check int) "table" 1 (count t);
            let* v = q "/api/v1/queries?verifier=proxy-1" in
            Alcotest.(check int) "verifier" 1 (count v);
            let* fp = q "/api/v1/queries?fingerprint=ffff" in
            Alcotest.(check int) "fingerprint" 1 (count fp);
            let* qq = q "/api/v1/queries?q=0002" in
            Alcotest.(check int) "q prefix" 1 (count qq);
            let since = C.Api.iso8601 (now -. 3600.) in
            let* tm = q ("/api/v1/queries?since=" ^ since) in
            Alcotest.(check int) "since" 3 (count tm);
            let* rg = q "/api/v1/queries?range=1h" in
            Alcotest.(check int) "range" 3 (count rg);
            let* p1 = q "/api/v1/queries?limit=3" in
            Alcotest.(check int) "page 1" 3 (count p1);
            let cursor =
              match member "next_cursor" p1 with
              | `String c -> c
              | _ -> Alcotest.fail "cursor"
            in
            let* p2 = q ("/api/v1/queries?limit=3&cursor=" ^ cursor) in
            Alcotest.(check int) "page 2" 1 (count p2);
            Alcotest.(check bool) "last page" true (member "next_cursor" p2 = `Null);
            let* bad = get r "/api/v1/queries?outcome=maybe" in
            check_status "bad outcome" 400 bad;
            let* bad = get r "/api/v1/queries?since=yesterday" in
            check_status "bad since" 400 bad;
            let* bad = get r "/api/v1/queries?limit=9999" in
            check_status "bad limit" 400 bad;
            Lwt.return_unit) );
  ]

(* ---- raw SQL ---- *)

let sql_tests =
  let records =
    [
      server_record ~request_id:"withsql" ~sql:"SELECT secret FROM t" ();
      server_record ~request_id:"nosql" ();
    ]
  in
  [
    ( "analyst needs a reason, view is logged",
      `Quick,
      fun () ->
        with_console ~background:false (config ~role:"analyst" ()) (fun r ->
            load_records r records;
            let* code, e = get r "/api/v1/records/withsql/sql" in
            Alcotest.(check int) "no reason" 403 code;
            Alcotest.(check string)
              "REASON_REQUIRED" "\"REASON_REQUIRED\""
              (Yojson.Safe.to_string (member "error.code" e));
            let* code, j =
              get ~reason:"CASE-1042 triage" r "/api/v1/records/withsql/sql"
            in
            Alcotest.(check int) "with reason" 200 code;
            Alcotest.(check string)
              "sql" "\"SELECT secret FROM t\""
              (Yojson.Safe.to_string (member "sql" j));
            Alcotest.(check bool) "logged" true (member "logged" j = `Bool true);
            let* nf = get ~reason:"x" r "/api/v1/records/nosql/sql" in
            check_status "not logged" 404 nf;
            let* nf = get ~reason:"x" r "/api/v1/records/missing/sql" in
            check_status "unknown" 404 nf;
            let* _, acts = get r "/api/v1/activity?action=record.view_sql" in
            (match member "entries" acts with
            | `List [ a ] ->
                Alcotest.(check string)
                  "reason" "\"CASE-1042 triage\""
                  (Yojson.Safe.to_string (member "reason" a));
                Alcotest.(check string)
                  "target" "\"withsql\""
                  (Yojson.Safe.to_string (member "target" a));
                Alcotest.(check bool)
                  "no sql in the log" false
                  (contains (Yojson.Safe.to_string a) "SELECT secret")
            | _ -> Alcotest.fail "one activity entry");
            (* the detail view never carries the SQL *)
            let* _, d = get r "/api/v1/records/withsql" in
            Alcotest.(check bool)
              "detail without sql" false
              (contains (Yojson.Safe.to_string d) "SELECT secret");
            Alcotest.(check bool)
              "has_raw_sql" true
              (member "record.has_raw_sql" d = `Bool true);
            Lwt.return_unit) );
    ( "dev and admin cannot see raw SQL",
      `Quick,
      fun () ->
        List.iter
          (fun role ->
            with_console ~background:false (config ~role ()) (fun r ->
                load_records r records;
                let* code, e = get ~reason:"because" r "/api/v1/records/withsql/sql" in
                Alcotest.(check int) (role ^ " forbidden") 403 code;
                Alcotest.(check string)
                  "FORBIDDEN" "\"FORBIDDEN\""
                  (Yojson.Safe.to_string (member "error.code" e));
                Lwt.return_unit))
          [ "dev"; "admin" ] );
  ]

(* ---- review fixes (#28) ---- *)

let state_of_record r id =
  let* _, j = get r ("/api/v1/records/" ^ id) in
  Lwt.return (match member "custody.chain_state" j with `String s -> s | _ -> "missing")

let rotation_tests =
  [
    ( "copytruncate that regrows past the old offset is read from the start",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        let f = Filename.concat d "audit.jsonl" in
        let lines = seal (recs 10) in
        write_file f (List.filteri (fun i _ -> i < 3) lines);
        with_console ~background:false
          (audit_cfg [ file_src f ])
          (fun r ->
            let poll = poll r in
            let* () = poll () in
            Alcotest.(check int) "first" 3 (C.Index.size r.ctx.index);
            (* r3, r4 written, then copied away and the file truncated in place; the
               writer goes on with r5..r9, past the old offset *)
            write_file ~append:true f [ List.nth lines 3; List.nth lines 4 ];
            write_file f (List.filteri (fun i _ -> i >= 5) lines);
            let* () = poll () in
            List.iter
              (fun i ->
                let id = Printf.sprintf "r%d" i in
                Alcotest.(check bool) id true (C.Index.find r.ctx.index id <> None))
              [ 5; 6; 7; 8; 9 ];
            Alcotest.(check int) "no partial records" 8 (C.Index.size r.ctx.index);
            let* st = state_of_record r "r7" in
            Alcotest.(check string) "a gap, not a broken chain" "gap" st;
            C.Chain.check_all r.ctx;
            Alcotest.(check string)
              "status" "\"gap\""
              (match member "chains" (C.Chain.status r.ctx) with
              | `List [ c ] -> Yojson.Safe.to_string (member "state" c)
              | _ -> "none");
            Lwt.return_unit) );
    ( "rename rotation reads the old file's tail first",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        let f = Filename.concat d "audit.jsonl" in
        let lines = seal (recs 7) in
        write_file f (List.filteri (fun i _ -> i < 3) lines);
        with_console ~background:false
          (audit_cfg [ file_src f ])
          (fun r ->
            let poll = poll r in
            let* () = poll () in
            write_file ~append:true f [ List.nth lines 3; List.nth lines 4 ];
            Sys.rename f (Filename.concat d "audit.jsonl.1");
            write_file f [ List.nth lines 5; List.nth lines 6 ];
            let* () = poll () in
            Alcotest.(check (list string))
              "nothing lost, in order"
              [ "r0"; "r1"; "r2"; "r3"; "r4"; "r5"; "r6" ]
              (List.map
                 (fun e -> e.C.Index.request_id)
                 (C.Index.verifier_stream r.ctx.index "haltsql-1"));
            let* st = state_of_record r "r6" in
            Alcotest.(check string) "intact" "intact" st;
            Lwt.return_unit) );
    ( "a glob matching rotated names does not duplicate records",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        let f = Filename.concat d "audit.jsonl" in
        let lines = seal (recs 5) in
        write_file f (List.filteri (fun i _ -> i < 3) lines);
        with_console ~background:false
          (audit_cfg [ file_src (Filename.concat d "audit.jsonl*") ])
          (fun r ->
            let poll = poll r in
            let* () = poll () in
            Sys.rename f (Filename.concat d "audit.jsonl.1");
            write_file f (List.filteri (fun i _ -> i >= 3) lines);
            let* () = poll () in
            let* () = poll () in
            Alcotest.(check int) "each record once" 5 (C.Index.size r.ctx.index);
            Alcotest.(check int)
              "stream" 5
              (List.length (C.Index.verifier_stream r.ctx.index "haltsql-1"));
            let* st = state_of_record r "r4" in
            Alcotest.(check string) "intact" "intact" st;
            Lwt.return_unit) );
    ( "an over-long line is skipped and still counted",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        let f = Filename.concat d "audit.jsonl" in
        let lines = seal (recs 2) in
        write_file f [ List.nth lines 0; String.make (1536 * 1024) 'x'; List.nth lines 1 ];
        let cfg =
          config
            ~extra:
              [
                ( "audit",
                  `Assoc [ ("sources", `List [ file_src f ]); ("max_line_mb", `Int 1) ] );
              ]
            ()
        in
        with_console ~background:false cfg (fun r ->
            let* () = poll r () in
            Alcotest.(check int) "two records" 2 (C.Index.size r.ctx.index);
            Alcotest.(check string)
              "line numbers" (f ^ "#L3")
              (Option.get (C.Index.find r.ctx.index "r1")).C.Index.location;
            Lwt.return_unit) );
    ( "overlapping sources read a file once; duplicates are rejected",
      `Quick,
      fun () ->
        let d = temp_dir "ingest" in
        let f = Filename.concat d "audit.jsonl" in
        write_file f (seal (recs 3));
        with_console ~background:false
          (audit_cfg [ file_src f; file_src ~verifier:"auto" d ])
          (fun r ->
            let* () = poll r () in
            Alcotest.(check int) "once" 3 (C.Index.size r.ctx.index);
            Alcotest.(check (list string))
              "no phantom verifier" [ "haltsql-1" ]
              (C.Index.verifiers r.ctx.index);
            Alcotest.(check string)
              "overlap reported"
              (Yojson.Safe.to_string (`List [ `String f ]))
              (Yojson.Safe.to_string (status_field r 1 "overlaps"));
            Lwt.return_unit);
        Alcotest.(check bool)
          "same file twice is invalid" true
          (match audit_cfg [ file_src f; file_src ~verifier:"other" f ] with
          | _ -> false
          | exception _ -> true) );
  ]

(* An S3 fake holding [store] (key -> body); [fail] keys answer 500. Records list
   requests' start-after values. *)
let s3_fake ~store ~fail ~starts req =
  let uri = Cohttp.Request.uri req in
  let path = Uri.pct_decode (Uri.path uri) in
  if Uri.get_query_param uri "list-type" = Some "2" then begin
    starts := Uri.get_query_param uri "start-after" :: !starts;
    respond
      ("<ListBucketResult>"
      ^ String.concat ""
          (List.map (fun (k, _) -> "<Contents><Key>" ^ k ^ "</Key></Contents>") !store)
      ^ "<IsTruncated>false</IsTruncated></ListBucketResult>")
  end
  else
    let key = String.sub path 8 (String.length path - 8) in
    if List.mem key !fail then
      Cohttp_lwt_unix.Server.respond_string ~status:`Internal_server_error ~body:"" ()
    else
      match List.assoc_opt key !store with
      | Some b -> respond b
      | None -> Cohttp_lwt_unix.Server.respond_string ~status:`Not_found ~body:"" ()

let s3_env = function
  | "AWS_ACCESS_KEY_ID" -> Some "AKIDEXAMPLE"
  | "AWS_SECRET_ACCESS_KEY" -> Some "secret"
  | _ -> None

let s3_cfg ?(extra = []) port =
  config
    ~extra:
      [
        ( "audit",
          `Assoc
            ([
               ( "sources",
                 `List
                   [
                     `Assoc
                       [
                         ("verifier", `String "auto");
                         ("s3", `String "s3://bucket/haltsql/");
                         ("region", `String "us-east-1");
                         ("endpoint", `String (Printf.sprintf "http://127.0.0.1:%d" port));
                       ];
                   ] );
             ]
            @ extra) );
      ]
    ()

let object_fix_tests =
  [
    ( "a failing object does not block other hosts and is skipped after N reads",
      `Quick,
      fun () ->
        let lines = seal (recs ~prefix:"a" 6) in
        let body l = String.concat "\n" l ^ "\n" in
        let part i = body (List.filteri (fun j _ -> j / 2 = i) lines) in
        let ka i = object_key ~prefix:"haltsql/" ~host:"hosta" ~seq:i (part i) in
        let bbody = body (seal (recs ~prefix:"b" 2)) in
        let kb = object_key ~prefix:"haltsql/" ~host:"hostb" ~seq:0 bbody in
        let store = ref [ (ka 0, part 0); (ka 1, part 1); (ka 2, part 2); (kb, bbody) ] in
        let fail = ref [ ka 1 ] and starts = ref [] in
        Lwt_main.run
          (with_http (s3_fake ~store ~fail ~starts) (fun port ->
               let* r =
                 start ~background:false
                   (s3_cfg ~extra:[ ("object_attempts", `Int 2) ] port)
               in
               Lwt.finalize
                 (fun () ->
                   let poll = poll ~env:s3_env r in
                   let* () = poll () in
                   Alcotest.(check bool)
                     "other host read" true
                     (C.Index.find r.ctx.index "b1" <> None);
                   Alcotest.(check bool)
                     "same host held back (order)" true
                     (C.Index.find r.ctx.index "a4" = None);
                   Alcotest.(check bool)
                     "error reported" true
                     (status_field r 0 "error" <> `Null);
                   let* () = poll () in
                   Alcotest.(check bool)
                     "later object read after the skip" true
                     (C.Index.find r.ctx.index "a5" <> None);
                   (match status_field r 0 "skipped_objects" with
                   | `List [ x ] ->
                       Alcotest.(check string)
                         "skipped key"
                         (Yojson.Safe.to_string (`String (ka 1)))
                         (Yojson.Safe.to_string (member "key" x))
                   | j -> Alcotest.failf "skipped_objects: %s" (Yojson.Safe.to_string j));
                   let* st = state_of_record r "a5" in
                   Alcotest.(check string) "gap, not broken" "gap" st;
                   let* () = poll () in
                   Alcotest.(check int) "no re-reads" 6 (C.Index.size r.ctx.index);
                   Lwt.return_unit)
                 (fun () ->
                   Helpers.stop r;
                   Lwt.return_unit))) );
    ( "listings start inside the retention window",
      `Quick,
      fun () ->
        let store = ref [] and fail = ref [] and starts = ref [] in
        Lwt_main.run
          (with_http (s3_fake ~store ~fail ~starts) (fun port ->
               let* r = start ~background:false (s3_cfg port) in
               Lwt.finalize
                 (fun () ->
                   let poll = poll ~env:s3_env r in
                   let* () = poll () in
                   let* () = poll () in
                   let partition t =
                     let tm = Unix.gmtime t in
                     Printf.sprintf "haltsql/%04d/%02d/%02d/%02d/" (tm.tm_year + 1900)
                       (tm.tm_mon + 1) tm.tm_mday tm.tm_hour
                   in
                   let now = Unix.gettimeofday () in
                   (match List.rev !starts with
                   | [ Some full; Some recent ] ->
                       Alcotest.(check string)
                         "full listing from the retention start"
                         (partition (now -. (168. *. 3600.)))
                         full;
                       Alcotest.(check string)
                         "then the last hour only"
                         (partition (now -. 3600.))
                         recent
                   | l ->
                       Alcotest.failf "start-after: %s"
                         (String.concat "," (List.map (Option.value ~default:"none") l)));
                   Lwt.return_unit)
                 (fun () ->
                   Helpers.stop r;
                   Lwt.return_unit))) );
    ( "emulator host is checked and a bad client is not memoized",
      `Quick,
      fun () ->
        let lines = seal (recs ~prefix:"g" 2) in
        let body = String.concat "\n" lines ^ "\n" in
        let k = object_key ~prefix:"audit/" ~host:"haltsql-9" ~seq:0 body in
        let handler req =
          let path = Uri.pct_decode (Uri.path (Cohttp.Request.uri req)) in
          if path = "/storage/v1/b/bkt/o" then
            respond (Printf.sprintf "{\"items\":[{\"name\":%S}]}" k)
          else if path = "/storage/v1/b/bkt/o/" ^ k then respond body
          else Cohttp_lwt_unix.Server.respond_string ~status:`Not_found ~body:"" ()
        in
        Lwt_main.run
          (with_http handler (fun port ->
               let emulator = ref "http://storage.example.com" in
               let env = function
                 | "STORAGE_EMULATOR_HOST" -> Some !emulator
                 | _ -> None
               in
               let cfg =
                 audit_cfg
                   [
                     `Assoc
                       [
                         ("verifier", `String "auto"); ("gcs", `String "gs://bkt/audit/");
                       ];
                   ]
               in
               let* r = start ~background:false cfg in
               Lwt.finalize
                 (fun () ->
                   let poll = poll ~env r in
                   let* () = poll () in
                   Alcotest.(check bool)
                     "non-loopback http refused" true
                     (match status_field r 0 "error" with
                     | `String m -> contains m "loopback"
                     | _ -> false);
                   emulator := Printf.sprintf "127.0.0.1:%d" port;
                   let* () = poll () in
                   Alcotest.(check int) "rebuilt next poll" 2 (C.Index.size r.ctx.index);
                   Lwt.return_unit)
                 (fun () ->
                   Helpers.stop r;
                   Lwt.return_unit))) );
  ]

(* Adds entries with explicit seq and location. *)
let add_lines ?(verifier = "haltsql-1") ~from ~location (r : running) lines =
  List.iteri
    (fun i l ->
      match
        C.Index.entry_of_json ~verifier
          ~location:(Printf.sprintf "%s#L%d" location (from + i + 1))
          ~seq:(from + i) ~now:(Unix.gettimeofday ()) (Yojson.Safe.from_string l)
      with
      | Some e -> C.Index.add r.ctx.index e
      | None -> Alcotest.fail "not an audit record")
    lines

let chain_fix_tests =
  [
    ( "incremental chain state follows appends, tampering and eviction",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            let lines = seal (recs 8) in
            add_lines r ~from:0 ~location:"a.jsonl"
              (List.filteri (fun i _ -> i < 5) lines);
            let c = C.Chain.get r.ctx "haltsql-1" in
            Alcotest.(check (pair string int))
              "first" ("intact", 5)
              (C.Chain.state_of c, C.Chain.records c);
            add_lines r ~from:5 ~location:"a.jsonl"
              (List.filteri (fun i _ -> i >= 5) lines);
            let c = C.Chain.get r.ctx "haltsql-1" in
            Alcotest.(check (pair string int))
              "appended" ("intact", 8)
              (C.Chain.state_of c, C.Chain.records c);
            (* a record that does not link to the previous one *)
            let stray = seal ~prev:(String.make 64 'f') (recs ~prefix:"x" 1) in
            add_lines r ~from:8 ~location:"a.jsonl" stray;
            Alcotest.(check string)
              "broken" "broken"
              (C.Chain.state_of (C.Chain.get r.ctx "haltsql-1"));
            (* the broken record leaves the window: what is left is intact again *)
            C.Index.expire r.ctx.index ~now:(Unix.gettimeofday () +. (8. *. 86400.));
            let c = C.Chain.get r.ctx "haltsql-1" in
            Alcotest.(check string) "all evicted" "unknown" (C.Chain.state_of c);
            C.Chain.check_all r.ctx;
            Alcotest.(check bool)
              "dropped from status" true
              (member "chains" (C.Chain.status r.ctx) = `List []);
            Lwt.return_unit) );
    ( "interleaved chains under one verifier are checked separately",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            let a = seal (recs ~prefix:"a" 3) and b = seal (recs ~prefix:"b" 3) in
            let ka = object_key ~prefix:"p/" ~host:"h1" ~seq:0 "x" in
            let kb = object_key ~prefix:"p/" ~host:"h2" ~seq:0 "y" in
            List.iteri
              (fun i (l, k) -> add_lines r ~from:i ~location:("s3://bkt/" ^ k) [ l ])
              (List.concat (List.map2 (fun x y -> [ (x, ka); (y, kb) ]) a b));
            let c = C.Chain.get r.ctx "haltsql-1" in
            Alcotest.(check (pair string int))
              "intact" ("intact", 6)
              (C.Chain.state_of c, C.Chain.records c);
            Lwt.return_unit) );
    ( "verify-chain calls share one walk",
      `Quick,
      fun () ->
        with_console ~background:false (config ~role:"analyst" ()) (fun r ->
            load_lines r (seal (recs 50));
            let* results =
              Lwt_list.map_p
                (fun () -> post r "/api/v1/records/r3/verify-chain" (`Assoc []))
                [ (); (); () ]
            in
            List.iter
              (fun (code, c) ->
                Alcotest.(check int) "200" 200 code;
                Alcotest.(check string)
                  "intact" "\"intact\""
                  (Yojson.Safe.to_string (member "chain_state" c)))
              results;
            let walked = (C.Chain.get r.ctx "haltsql-1").C.Chain.full_at in
            let* _ = post r "/api/v1/records/r3/verify-chain" (`Assoc []) in
            Alcotest.(check bool)
              "not walked again right away" true
              ((C.Chain.get r.ctx "haltsql-1").C.Chain.full_at = walked);
            Lwt.return_unit) );
  ]

(* The shop policy in literal tenancy mode: a mismatch message quotes the literal. *)
let literal_policy () =
  let pat = "mode: bound" in
  let i =
    let rec find i =
      if String.sub policy_yaml i (String.length pat) = pat then i else find (i + 1)
    in
    find 0
  in
  let yaml =
    String.sub policy_yaml 0 i ^ "mode: literal"
    ^ String.sub policy_yaml
        (i + String.length pat)
        (String.length policy_yaml - i - String.length pat)
  in
  match Haltsql.Policy_load.of_string Haltsql.Docload.Yaml yaml with
  | Ok p -> p
  | Error errs ->
      Alcotest.failf "policy: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string errs))

let tenant_policy_record =
  match
    server_record ~request_id:"xt" ~policy:"shop" ~allowed:false
      ~codes:[ "E_TENANT_MISMATCH" ]
      ~sql:"SELECT id FROM app.customers WHERE tenant_id = 'globex-secret-7731' LIMIT 5"
      ()
  with
  | `Assoc kv -> `Assoc (kv @ [ ("context", `Assoc [ ("tenant_id", `String "acme") ]) ])
  | j -> j

let redaction_tests =
  [
    ( "re-verified literals need see_raw_sql and a reason",
      `Quick,
      fun () ->
        let leaks j = contains (Yojson.Safe.to_string j) "globex-secret-7731" in
        List.iter
          (fun role ->
            with_console ~background:false (config ~role ()) (fun r ->
                C.Policy_set.set r.ctx [ ("shop", literal_policy ()) ];
                load_records r [ tenant_policy_record ];
                let* code, j = get r "/api/v1/records/xt" in
                Alcotest.(check int) (role ^ " 200") 200 code;
                Alcotest.(check string)
                  "reverified" "\"reverified\""
                  (Yojson.Safe.to_string (member "trail_source" j));
                Alcotest.(check bool) (role ^ " sees no literal") false (leaks j);
                Lwt.return_unit))
          [ "dev"; "admin"; "analyst" ];
        with_console ~background:false (config ~role:"analyst" ()) (fun r ->
            C.Policy_set.set r.ctx [ ("shop", literal_policy ()) ];
            load_records r [ tenant_policy_record ];
            let* nr = get r "/api/v1/records/xt?details=full" in
            check_status "reason required" 403 nr;
            let* code, j =
              get ~reason:"CASE-7 triage" r "/api/v1/records/xt?details=full"
            in
            Alcotest.(check int) "with reason" 200 code;
            Alcotest.(check string)
              "full" "\"full\""
              (Yojson.Safe.to_string (member "reasons_detail" j));
            Alcotest.(check bool) "literal shown" true (leaks j);
            let* _, acts = get r "/api/v1/activity?action=record.view_details" in
            (match member "entries" acts with
            | `List [ a ] ->
                Alcotest.(check string)
                  "reason logged" "\"CASE-7 triage\""
                  (Yojson.Safe.to_string (member "reason" a))
            | _ -> Alcotest.fail "one activity entry");
            Lwt.return_unit);
        with_console ~background:false (config ~role:"dev" ()) (fun r ->
            load_records r [ tenant_policy_record ];
            let* d = get ~reason:"x" r "/api/v1/records/xt?details=full" in
            check_status "dev cannot ask for details" 403 d;
            Lwt.return_unit) );
  ]

let keyset_tests =
  [
    ( "pages are stable while records arrive, ties included",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            let now = Unix.gettimeofday () in
            load_records r
              (List.init 5 (fun i ->
                   server_record ~request_id:(Printf.sprintf "k%d" i)
                     ~ts:(now -. float_of_int (100 - i))
                     ()));
            let ids j =
              match member "records" j with
              | `List l ->
                  List.map
                    (fun x ->
                      match member "request_id" x with `String s -> s | _ -> "?")
                    l
              | _ -> []
            in
            let* _, p1 = get r "/api/v1/queries?limit=2" in
            Alcotest.(check (list string)) "page 1" [ "k4"; "k3" ] (ids p1);
            Alcotest.(check string)
              "total" "5"
              (Yojson.Safe.to_string (member "total" p1));
            let cursor = match member "next_cursor" p1 with `String c -> c | _ -> "" in
            C.Index.add r.ctx.index
              (Option.get
                 (C.Index.entry_of_json ~verifier:"haltsql-1" ~location:"n#L1" ~seq:99
                    ~now
                    (server_record ~request_id:"new" ~ts:now ())));
            let* _, p2 = get r ("/api/v1/queries?limit=2&cursor=" ^ cursor) in
            Alcotest.(check (list string)) "page 2 unshifted" [ "k2"; "k1" ] (ids p2);
            Alcotest.(check bool) "no total after page 1" true (member "total" p2 = `Null);
            Lwt.return_unit);
        with_console ~background:false (config ()) (fun r ->
            let ts = Unix.gettimeofday () -. 10. in
            load_records r
              (List.init 4 (fun i ->
                   server_record ~request_id:(Printf.sprintf "t%d" i) ~ts ()));
            let rec walk cursor acc =
              let path =
                "/api/v1/queries?limit=1"
                ^ match cursor with Some c -> "&cursor=" ^ c | None -> ""
              in
              let* _, j = get r path in
              let acc =
                acc
                @
                match member "records" j with
                | `List [ x ] -> [ Yojson.Safe.to_string (member "request_id" x) ]
                | _ -> []
              in
              match member "next_cursor" j with
              | `String c -> walk (Some c) acc
              | _ -> Lwt.return acc
            in
            let* all = walk None [] in
            Alcotest.(check int)
              "four distinct" 4
              (List.length (List.sort_uniq compare all));
            Alcotest.(check int) "four pages" 4 (List.length all);
            let* bad = get r "/api/v1/queries?cursor=Mg" in
            check_status "old offset cursor" 400 bad;
            Lwt.return_unit) );
  ]

let () =
  Alcotest.run "console-records"
    [
      ("ingest", ingest_tests);
      ("objects", objects_tests);
      ("chain", chain_tests);
      ("trail", trail_tests);
      ("search", search_tests);
      ("sql", sql_tests);
      ("rotation", rotation_tests);
      ("object fixes", object_fix_tests);
      ("chain fixes", chain_fix_tests);
      ("redaction", redaction_tests);
      ("keyset", keyset_tests);
    ]
