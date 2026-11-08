(* `haltsql audit verify s3://...` against a REAL MinIO server in Docker (container
   haltsql-audit-minio, host ports 16000-16001). The objects are written by the real
   S3 sink (Haltsql_cloud.S3_sink, SigV4 PUTs); the verifier lists and downloads them
   with SigV4 (ListObjectsV2 + GET). Tampering is done through the S3 API itself.

   Skips cleanly when Docker or a MinIO image is unavailable. The image is
   HALTSQL_MINIO_IMAGE, else the first of minio/minio:latest and pgsty/minio:latest
   (a build of the MinIO server) present locally; nothing is pulled. *)

module Config = Haltsql.Config
module C = Haltsql_cloud

let container = "haltsql-audit-minio"
let port = 16000
let console_port = 16001
let endpoint = Printf.sprintf "http://127.0.0.1:%d" port

(* test-only root credentials of the throwaway container *)
let access_key = "haltsqlaudit"
let secret_key = "haltsql-audit-minio-test-only"
let bucket = "haltsql-audit"
let region = "us-east-1"
let quiet cmd = Unix.system (cmd ^ " >/dev/null 2>&1") = Unix.WEXITED 0
let docker_ok () = quiet "docker info --format '{{.ServerVersion}}'"

let image () =
  let candidates =
    (match Sys.getenv_opt "HALTSQL_MINIO_IMAGE" with Some i -> [ i ] | None -> [])
    @ [ "minio/minio:latest"; "pgsty/minio:latest" ]
  in
  List.find_opt (fun i -> quiet ("docker image inspect " ^ Filename.quote i)) candidates

let creds =
  {
    C.Sigv4.access_key_id = access_key;
    secret_access_key = secret_key;
    session_token = None;
  }

let s3_request meth path ?(body = "") () =
  let uri = Uri.of_string (endpoint ^ path) in
  let headers =
    C.Sigv4.sign ~s3:true creds ~service:"s3" ~region ~time:(Unix.gettimeofday ())
      ~meth:(Cohttp.Code.string_of_method meth)
      ~uri ~headers:[] ~payload:body
  in
  Lwt_main.run (C.Http.request ~timeout:10. ~headers ~body meth uri)

let healthy () =
  match
    Lwt_main.run
      (C.Http.request ~timeout:2. `GET (Uri.of_string (endpoint ^ "/minio/health/live")))
  with
  | Ok r -> r.status = 200
  | Error _ -> false

let start_minio img =
  let cmd =
    Printf.sprintf
      "docker run -d --name %s -p 127.0.0.1:%d:9000 -p 127.0.0.1:%d:9001 -e \
       MINIO_ROOT_USER=%s -e MINIO_ROOT_PASSWORD=%s %s server /data --console-address \
       :9001"
      container port console_port access_key secret_key (Filename.quote img)
  in
  (* Docker may still be releasing the ports of a previous run: retry *)
  let rec attempt n =
    ignore (quiet ("docker rm -f " ^ container));
    quiet cmd
    || n > 0
       &&
       (Unix.sleepf 0.5;
        attempt (n - 1))
  in
  if not (attempt 20) then Error "docker run failed"
  else begin
    at_exit (fun () -> ignore (quiet ("docker rm -f " ^ container)));
    let rec wait n =
      if healthy () then Ok ()
      else if n = 0 then Error "MinIO did not become healthy"
      else (
        Unix.sleepf 0.25;
        wait (n - 1))
    in
    wait 120
  end

let skip_reason, ready =
  if List.mem (Sys.getenv_opt "HALTSQL_SKIP_DOCKER") [ Some "1"; Some "true"; Some "yes" ]
  then (Some "HALTSQL_SKIP_DOCKER is set", false)
  else if not (docker_ok ()) then (Some "Docker is not available", false)
  else
    match image () with
    | None -> (Some "no MinIO image present locally (set HALTSQL_MINIO_IMAGE)", false)
    | Some img -> (
        match start_minio img with Ok () -> (None, true) | Error e -> (Some e, false))

(* ------------------------------------------------------------ helpers *)

let prefix = "haltsql/audit/"

let sink_cfg =
  {
    Config.s3_bucket = bucket;
    s3_prefix = prefix;
    s3_region = region;
    s3_endpoint = Some endpoint;
    s3_object_lock = None;
    s3_batch = { Config.max_records = 3; max_seconds = 3600 };
    s3_credentials =
      Config.S3_static
        {
          access_key_id = access_key;
          secret_access_key = secret_key;
          session_token = None;
        };
    s3_spool_dir = None;
  }

let record i : (string * Yojson.Safe.t) list =
  [
    ("ts", `String "2026-11-07T12:00:00Z"); ("event", `String "statement"); ("n", `Int i);
  ]

let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p
let cli = Option.map absolute (Sys.getenv_opt "HALTSQL_AUDIT_CLI")

let run_cli ?(key = access_key) ?(secret = secret_key) args =
  let bin = Option.get cli in
  let out = Filename.temp_file "minio_cli" ".out" in
  let fd = Unix.openfile out [ Unix.O_WRONLY; Unix.O_TRUNC ] 0o600 in
  let devnull = Unix.openfile "/dev/null" [ Unix.O_RDWR ] 0 in
  let env =
    Array.append
      (Array.of_list
         (List.filter
            (fun kv -> not (String.length kv > 4 && String.sub kv 0 4 = "AWS_"))
            (Array.to_list (Unix.environment ()))))
      [|
        "AWS_ACCESS_KEY_ID=" ^ key;
        "AWS_SECRET_ACCESS_KEY=" ^ secret;
        "AWS_EC2_METADATA_DISABLED=true";
      |]
  in
  let pid =
    Unix.create_process_env bin
      (Array.of_list (bin :: "audit" :: "verify" :: "--endpoint" :: endpoint :: args))
      env devnull fd fd
  in
  Unix.close fd;
  Unix.close devnull;
  let rec wait () =
    try snd (Unix.waitpid [] pid) with Unix.Unix_error (Unix.EINTR, _, _) -> wait ()
  in
  let st = wait () in
  let o = In_channel.with_open_bin out In_channel.input_all in
  Sys.remove out;
  ((match st with Unix.WEXITED c -> c | _ -> -1), o)

let list_keys () =
  match s3_request `GET ("/" ^ bucket ^ "?list-type=2&prefix=" ^ prefix) () with
  | Ok r when r.status = 200 ->
      let parts = String.split_on_char '<' r.body in
      List.filter_map
        (fun p ->
          if String.length p > 4 && String.sub p 0 4 = "Key>" then
            Some (String.sub p 4 (String.length p - 4))
          else None)
        parts
      |> List.sort compare
  | Ok r -> Alcotest.failf "list: HTTP %d" r.status
  | Error e -> Alcotest.failf "list: %s" e

let url = Printf.sprintf "s3://%s/%s" bucket prefix

(* ------------------------------------------------------------- tests *)

let setup =
  lazy begin
    (match s3_request `PUT ("/" ^ bucket) () with
    | Ok r when r.status = 200 || r.status = 409 -> ()
    | Ok r -> Alcotest.failf "create bucket: HTTP %d" r.status
    | Error e -> Alcotest.failf "create bucket: %s" e);
    match C.S3_sink.create ~host:"proxy-a" ~on_error:Config.Fail_closed sink_cfg with
    | Error e -> Alcotest.fail e
    | Ok s -> (
        for i = 1 to 10 do
          match C.Object_sink.write s (record i) with
          | Ok () -> ()
          | Error e -> Alcotest.fail e
        done;
        match Lwt_main.run (C.Object_sink.close s) with
        | Ok () -> ()
        | Error e -> Alcotest.failf "upload to MinIO: %s" e)
  end

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let t_verify_ok () =
  Lazy.force setup;
  Alcotest.(check int) "4 objects in MinIO" 4 (List.length (list_keys ()));
  let code, out = run_cli [ "--json"; url ] in
  if code <> 0 then Alcotest.failf "exit %d: %s" code out;
  let j = Yojson.Safe.from_string out in
  let open Yojson.Safe.Util in
  let inp = List.hd (to_list (member "inputs" j)) in
  Alcotest.(check int) "records" 10 (to_int (member "records" inp));
  Alcotest.(check int) "objects" 4 (to_int (member "objects" inp));
  Alcotest.(check string) "kind" "s3" (to_string (member "kind" inp))

let t_bad_credentials () =
  Lazy.force setup;
  let code, out = run_cli ~secret:"wrong-secret-value" [ url ] in
  Alcotest.(check int) "exit 2" 2 code;
  Alcotest.(check bool) "403 reported" true (contains out "403");
  Alcotest.(check bool) "secret not echoed" false (contains out "wrong-secret-value")

let t_missing_bucket () =
  let code, _ = run_cli [ "s3://no-such-haltsql-bucket/x/" ] in
  Alcotest.(check int) "exit 2" 2 code

let t_forged_object () =
  Lazy.force setup;
  (* a forged object claiming an existing seq, uploaded through the S3 API *)
  let k = List.hd (list_keys ()) in
  let body = "{\"forged\":true}\n" in
  let sha = Digestif.SHA256.(to_hex (digest_string body)) in
  let k2 = String.sub k 0 (String.length k - 6 - 64) ^ sha ^ ".jsonl" in
  (match s3_request `PUT ("/" ^ bucket ^ "/" ^ k2) ~body () with
  | Ok r when r.status = 200 -> ()
  | Ok r -> Alcotest.failf "PUT: HTTP %d" r.status
  | Error e -> Alcotest.fail e);
  let code, out = run_cli [ url ] in
  Alcotest.(check int) "exit 1" 1 code;
  Alcotest.(check bool) "conflict reported" true (contains out "conflicting_objects");
  ignore (s3_request `DELETE ("/" ^ bucket ^ "/" ^ k2) ())

let t_deleted_object () =
  Lazy.force setup;
  let k = List.nth (list_keys ()) 1 in
  (match s3_request `DELETE ("/" ^ bucket ^ "/" ^ k) () with
  | Ok r when r.status = 204 || r.status = 200 -> ()
  | Ok r -> Alcotest.failf "DELETE: HTTP %d" r.status
  | Error e -> Alcotest.fail e);
  let code, out = run_cli [ "--json"; url ] in
  Alcotest.(check int) "exit 1" 1 code;
  let j = Yojson.Safe.from_string out in
  let open Yojson.Safe.Util in
  let kinds =
    List.map
      (fun p -> to_string (member "kind" p))
      (to_list (member "problems" (List.hd (to_list (member "inputs" j)))))
  in
  Alcotest.(check bool) "seq gap" true (List.mem "seq_gap" kinds);
  Alcotest.(check string)
    "first broken" "seq_gap"
    (to_string (member "kind" (member "first_broken" j)))

let () =
  let tests =
    match (skip_reason, cli) with
    | Some r, _ ->
        [ Alcotest.test_case ("SKIPPED: " ^ r) `Quick (fun () -> Alcotest.skip ()) ]
    | None, None ->
        [
          Alcotest.test_case "SKIPPED: HALTSQL_AUDIT_CLI not set" `Quick (fun () ->
              Alcotest.skip ());
        ]
    | None, Some _ ->
        ignore ready;
        [
          Alcotest.test_case "objects written by the S3 sink verify" `Quick t_verify_ok;
          Alcotest.test_case "wrong credentials -> exit 2" `Quick t_bad_credentials;
          Alcotest.test_case "missing bucket -> exit 2" `Quick t_missing_bucket;
          Alcotest.test_case "forged object -> exit 1" `Quick t_forged_object;
          Alcotest.test_case "deleted object -> exit 1" `Quick t_deleted_object;
        ]
  in
  Alcotest.run "audit-verify-minio" [ ("s3", tests) ]
