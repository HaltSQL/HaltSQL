open Lwt.Infix
module C = Haltsql_cloud
module S = C.Sigv4
module Config = Haltsql_load.Config

let run = Lwt_main.run
let () = Mirage_crypto_rng_unix.use_default ()

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let rec wait_until ?(timeout = 6.) cond =
  if cond () then Lwt.return true
  else if timeout <= 0. then Lwt.return false
  else Lwt_unix.sleep 0.05 >>= fun () -> wait_until ~timeout:(timeout -. 0.05) cond

let env_of l k = List.assoc_opt k l
let b64 s = Base64.encode_string s
let md5_b64 s = b64 Digestif.MD5.(to_raw_string (digest_string s))
let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let tmp_dir () =
  let d =
    Filename.concat
      (Filename.get_temp_dir_name ())
      (Printf.sprintf "haltsql_cloud_%d_%d" (Unix.getpid ()) (Random.bits ()))
  in
  Unix.mkdir d 0o700;
  d

let tmp_file ?(ext = ".txt") contents =
  let f = Filename.temp_file "haltsql_cloud" ext in
  Out_channel.with_open_bin f (fun oc -> output_string oc contents);
  f

let query_param req k = Uri.get_query_param (Cohttp.Request.uri req) k

(* ================= SigV4 (AWS published examples) ================= *)

let ex_creds =
  {
    S.access_key_id = "AKIDEXAMPLE";
    secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    session_token = None;
  }

let t_20150830 = 1440938160. (* 2015-08-30T12:36:00Z *)

let suite_sig ~meth ~path ~query ~headers ~payload =
  let creq, _ =
    S.canonical_request ~meth
      ~canonical_uri:(S.canonical_uri ~s3:false path)
      ~query ~headers ~payload_hash:(S.sha256_hex payload)
  in
  let scope =
    S.credential_scope ~date:"20150830" ~region:"us-east-1" ~service:"service"
  in
  let sts =
    S.string_to_sign ~amz_date:"20150830T123600Z" ~scope ~canonical_request:creq
  in
  ( creq,
    sts,
    S.signature
      ~signing_key:
        (S.signing_key ~secret:ex_creds.secret_access_key ~date:"20150830"
           ~region:"us-east-1" ~service:"service")
      sts )

let test_sigv4_get_vanilla () =
  let creq, sts, sg =
    suite_sig ~meth:"GET" ~path:"/" ~query:[]
      ~headers:[ ("Host", "example.amazonaws.com"); ("X-Amz-Date", "20150830T123600Z") ]
      ~payload:""
  in
  Alcotest.(check string)
    "canonical request"
    "GET\n\
     /\n\n\
     host:example.amazonaws.com\n\
     x-amz-date:20150830T123600Z\n\n\
     host;x-amz-date\n\
     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    creq;
  Alcotest.(check string)
    "string to sign"
    "AWS4-HMAC-SHA256\n\
     20150830T123600Z\n\
     20150830/us-east-1/service/aws4_request\n\
     bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
    sts;
  Alcotest.(check string)
    "signature" "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" sg;
  (* The high-level signer adds exactly host + x-amz-date for this request. *)
  let hs =
    S.sign ex_creds ~service:"service" ~region:"us-east-1" ~time:t_20150830 ~meth:"GET"
      ~uri:(Uri.of_string "https://example.amazonaws.com/")
      ~headers:[] ~payload:""
  in
  Alcotest.(check (option string))
    "authorization header"
    (Some
       "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
        SignedHeaders=host;x-amz-date, \
        Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
    (List.assoc_opt "authorization" hs)

let test_sigv4_query_order () =
  let _, _, sg =
    suite_sig ~meth:"GET" ~path:"/"
      ~query:[ ("Param2", "value2"); ("Param1", "value1") ]
      ~headers:[ ("Host", "example.amazonaws.com"); ("X-Amz-Date", "20150830T123600Z") ]
      ~payload:""
  in
  Alcotest.(check string)
    "get-vanilla-query-order-key-case"
    "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500" sg

let test_sigv4_post_vanilla () =
  let _, _, sg =
    suite_sig ~meth:"POST" ~path:"/" ~query:[]
      ~headers:[ ("Host", "example.amazonaws.com"); ("X-Amz-Date", "20150830T123600Z") ]
      ~payload:""
  in
  Alcotest.(check string)
    "post-vanilla" "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b" sg

let to_hex s =
  String.concat ""
    (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let test_sigv4_iam () =
  Alcotest.(check string)
    "derived signing key (IAM docs)"
    "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    (to_hex
       (S.signing_key ~secret:ex_creds.secret_access_key ~date:"20150830"
          ~region:"us-east-1" ~service:"iam"));
  let creq, _ =
    S.canonical_request ~meth:"GET" ~canonical_uri:"/"
      ~query:[ ("Action", "ListUsers"); ("Version", "2010-05-08") ]
      ~headers:
        [
          ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
          ("Host", "iam.amazonaws.com");
          ("X-Amz-Date", "20150830T123600Z");
        ]
      ~payload_hash:(S.sha256_hex "")
  in
  Alcotest.(check string)
    "canonical request hash"
    "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59" (S.sha256_hex creq);
  let sts =
    S.string_to_sign ~amz_date:"20150830T123600Z"
      ~scope:"20150830/us-east-1/iam/aws4_request" ~canonical_request:creq
  in
  Alcotest.(check string)
    "signature" "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    (S.signature
       ~signing_key:
         (S.signing_key ~secret:ex_creds.secret_access_key ~date:"20150830"
            ~region:"us-east-1" ~service:"iam")
       sts)

let s3_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

let s3_sig ~meth ~path ~headers ~payload_hash =
  let creq, _ =
    S.canonical_request ~meth
      ~canonical_uri:(S.canonical_uri ~s3:true path)
      ~query:[] ~headers ~payload_hash
  in
  let sts =
    S.string_to_sign ~amz_date:"20130524T000000Z"
      ~scope:"20130524/us-east-1/s3/aws4_request" ~canonical_request:creq
  in
  S.signature
    ~signing_key:
      (S.signing_key ~secret:s3_secret ~date:"20130524" ~region:"us-east-1" ~service:"s3")
    sts

let test_sigv4_s3_examples () =
  let empty = S.sha256_hex "" in
  Alcotest.(check string)
    "S3 GET object (range)"
    "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    (s3_sig ~meth:"GET" ~path:"/test.txt"
       ~headers:
         [
           ("Host", "examplebucket.s3.amazonaws.com");
           ("Range", "bytes=0-9");
           ("x-amz-content-sha256", empty);
           ("x-amz-date", "20130524T000000Z");
         ]
       ~payload_hash:empty);
  let body = "Welcome to Amazon S3." in
  let ph = S.sha256_hex body in
  Alcotest.(check string)
    "payload hash" "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" ph;
  Alcotest.(check string)
    "S3 PUT object" "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    (s3_sig ~meth:"PUT" ~path:"/test%24file.text"
       ~headers:
         [
           ("Date", "Fri, 24 May 2013 00:00:00 GMT");
           ("Host", "examplebucket.s3.amazonaws.com");
           ("x-amz-date", "20130524T000000Z");
           ("x-amz-storage-class", "REDUCED_REDUNDANCY");
           ("x-amz-content-sha256", ph);
         ]
       ~payload_hash:ph)

let test_sigv4_helpers () =
  Alcotest.(check string) "amz date" "20150830T123600Z" (S.amz_date t_20150830);
  let block, signed =
    S.canonical_headers
      [ ("My-Header1", "  a   b   c  "); ("my-header1", "d"); ("Host", "h") ]
  in
  Alcotest.(check string) "collapse + combine" "host:h\nmy-header1:a b c,d\n" block;
  Alcotest.(check string) "signed" "host;my-header1" signed;
  Alcotest.(check string)
    "strict query encoding" "a%20b=c%2Fd&z="
    (S.canonical_query [ ("z", ""); ("a b", "c/d") ]);
  Alcotest.(check string)
    "non-S3 double encoding" "/a%2520b"
    (S.canonical_uri ~s3:false "/a%20b");
  Alcotest.(check string)
    "S3 single encoding" "/a%20b"
    (S.canonical_uri ~s3:true "/a%20b");
  (* regression: sub-delims are encoded however the wire spells them *)
  Alcotest.(check string)
    "S3 sub-delims (raw)" "/b/audit/app%3Dx/a%3Ab%2Bd%40e%2C%3B%20f~g"
    (S.canonical_uri ~s3:true "/b/audit/app=x/a:b+d@e,;%20f~g");
  Alcotest.(check string)
    "S3 sub-delims (encoded)" "/b/audit/app%3Dx/a%3Ab%2Bd%40e%2C%3B%20f~g"
    (S.canonical_uri ~s3:true "/b/audit/app%3Dx/a%3Ab%2Bd%40e%2C%3B%20f%7Eg");
  Alcotest.(check string)
    "S3 canonical path of a normalised Uri" "/p%3Dx/a%3Ab%2Bd%40e"
    (S.canonical_uri ~s3:true (Uri.path (Uri.of_string "https://h/p%3Dx/a%3Ab%2Bd%40e")));
  match
    S.parse_authorization
      "AWS4-HMAC-SHA256 Credential=AK/20150830/us-east-1/s3/aws4_request, \
       SignedHeaders=host;x-amz-date, Signature=abc"
  with
  | Some a ->
      Alcotest.(check string)
        "credential" "AK/20150830/us-east-1/s3/aws4_request" a.credential;
      Alcotest.(check (list string))
        "signed headers" [ "host"; "x-amz-date" ] a.signed_headers;
      Alcotest.(check string) "sig" "abc" a.signature_hex
  | None -> Alcotest.fail "parse_authorization"

(* What S3-compatible servers do (e.g. MinIO's s3utils.EncodePath): decode
   the received path, then encode every byte outside A-Za-z0-9 - _ . ~ /.
   Written independently of Sigv4 so a client-side bug cannot hide here. *)
let server_s3_canonical_path wire =
  let decoded = Uri.pct_decode wire in
  let b = Buffer.create (String.length decoded * 3) in
  String.iter
    (fun c ->
      match c with
      | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '_' | '.' | '~' | '/' ->
          Buffer.add_char b c
      | c -> Buffer.add_string b (Printf.sprintf "%%%02X" (Char.code c)))
    decoded;
  let p = Buffer.contents b in
  if p = "" then "/" else p

(* Server-side SigV4 verification, as a real AWS endpoint would do it. *)
let verify_sigv4 ~secrets ~service ~region req body =
  let h n = Fake_http.header req n in
  match Option.bind (h "authorization") S.parse_authorization with
  | None -> Error "MissingAuthenticationToken"
  | Some a -> (
      match String.split_on_char '/' a.credential with
      | [ akid; date; reg; svc; "aws4_request" ] when reg = region && svc = service -> (
          match List.assoc_opt akid secrets with
          | None -> Error "InvalidAccessKeyId"
          | Some secret ->
              if
                not
                  (List.mem "host" a.signed_headers
                  && List.mem "x-amz-date" a.signed_headers)
              then Error "host/x-amz-date not signed"
              else
                let payload_hash =
                  match h "x-amz-content-sha256" with
                  | Some p -> p
                  | None -> sha256_hex body
                in
                if payload_hash <> sha256_hex body then Error "XAmzContentSHA256Mismatch"
                else
                  let uri = Cohttp.Request.uri req in
                  let query =
                    List.concat_map
                      (fun (k, vs) ->
                        List.map (fun v -> (k, v)) (if vs = [] then [ "" ] else vs))
                      (Uri.query uri)
                  in
                  let headers =
                    List.map
                      (fun n -> (n, Option.value ~default:"" (h n)))
                      a.signed_headers
                  in
                  let creq, _ =
                    S.canonical_request
                      ~meth:(Cohttp.Code.string_of_method (Cohttp.Request.meth req))
                      ~canonical_uri:
                        (if service = "s3" then server_s3_canonical_path (Uri.path uri)
                         else S.canonical_uri ~s3:false (Uri.path uri))
                      ~query ~headers ~payload_hash
                  in
                  let amz = Option.value ~default:"" (h "x-amz-date") in
                  let sts =
                    S.string_to_sign ~amz_date:amz
                      ~scope:(S.credential_scope ~date ~region ~service)
                      ~canonical_request:creq
                  in
                  let expect =
                    S.signature
                      ~signing_key:(S.signing_key ~secret ~date ~region ~service)
                      sts
                  in
                  if String.sub amz 0 8 <> date then Error "date mismatch"
                  else if expect = a.signature_hex then Ok akid
                  else Error "SignatureDoesNotMatch")
      | _ -> Error "malformed credential scope")

(* ================= Fake S3 ================= *)

type s3_mode =
  | S3_ok
  | S3_fail of int * string
  | S3_expired of string (* akid considered expired *)

type fake_s3 = {
  srv : Fake_http.t;
  objects : (string, string * (string * string) list) Hashtbl.t;
  mutable mode : s3_mode;
  mutable puts : int;
  mutable sig_errors : string list;
}

let s3_error status code =
  Fake_http.respond ~status
    (Printf.sprintf
       "<?xml version=\"1.0\"?><Error><Code>%s</Code><Message>m</Message></Error>" code)

let start_s3 ?(secrets = [ ("AKIDTEST", "secretkey") ]) () =
  let rec st =
    lazy
      {
        srv =
          Fake_http.start (fun req body ->
              let st = Lazy.force st in
              st.puts <- st.puts + 1;
              let h n = Fake_http.header req n in
              match verify_sigv4 ~secrets ~service:"s3" ~region:"us-east-1" req body with
              | Error e ->
                  st.sig_errors <- e :: st.sig_errors;
                  s3_error 403 e
              | Ok akid -> (
                  match st.mode with
                  | S3_fail (code, c) -> s3_error code c
                  | S3_expired a when a = akid -> s3_error 403 "ExpiredToken"
                  | _ ->
                      if h "content-md5" <> Some (md5_b64 body) then
                        s3_error 400 "BadDigest"
                      else if
                        h "x-amz-checksum-sha256"
                        <> Some (b64 Digestif.SHA256.(to_raw_string (digest_string body)))
                      then s3_error 400 "XAmzContentChecksumMismatch"
                      else
                        let key = Fake_http.path req in
                        if Hashtbl.mem st.objects key && h "if-none-match" = Some "*" then
                          s3_error 412 "PreconditionFailed"
                        else begin
                          let hs =
                            Cohttp.Header.to_list (Cohttp.Request.headers req)
                            |> List.map (fun (k, v) -> (String.lowercase_ascii k, v))
                          in
                          Hashtbl.replace st.objects key (body, hs);
                          Fake_http.respond ~headers:[ ("etag", "\"x\"") ] ""
                        end));
        objects = Hashtbl.create 8;
        mode = S3_ok;
        puts = 0;
        sig_errors = [];
      }
  in
  Lazy.force st

let sorted_objects (f : fake_s3) =
  Hashtbl.fold (fun k (b, h) acc -> (k, b, h) :: acc) f.objects [] |> List.sort compare

let all_lines objs =
  List.concat_map
    (fun (_, b, _) -> String.split_on_char '\n' b |> List.filter (( <> ) ""))
    objs

let s3_cfg ?(lock = Some { Config.lock_mode = Config.Compliance; retain_days = 30 })
    ?(max_records = 3) ?(max_seconds = 1)
    ?(creds =
      Config.S3_static
        {
          access_key_id = "AKIDTEST";
          secret_access_key = "secretkey";
          session_token = Some "sess-tok";
        }) (f : fake_s3) =
  {
    Config.s3_bucket = "audit-bkt";
    s3_prefix = "haltsql/audit/";
    s3_region = "us-east-1";
    s3_endpoint = Some (Fake_http.url f.srv "");
    s3_object_lock = lock;
    s3_batch = { Config.max_records; max_seconds };
    s3_credentials = creds;
    s3_spool_dir = None;
  }

let rec_fields i =
  [
    ("ts", `String "2023-11-14T22:13:20Z");
    ("request_id", `String (Printf.sprintf "r%d" i));
    ("allowed", `Bool (i mod 2 = 0));
  ]

let get_ok = function Ok x -> x | Error e -> Alcotest.failf "unexpected error: %s" e

let write_n sink a b =
  for i = a to b do
    get_ok (C.Object_sink.write sink (rec_fields i))
  done

let fixed_now () = 1700000000. (* 2023-11-14T22:13:20Z *)

let test_s3_upload_and_chain () =
  run
    (let f = start_s3 () in
     let sink =
       get_ok
         (C.S3_sink.create ~now:fixed_now ~host:"testhost" ~run_id:"run1"
            ~on_error:Config.Fail_closed (s3_cfg f))
     in
     write_n sink 1 7;
     Alcotest.(check int)
       "two batches closed by size" 2 (C.Object_sink.stats sink).pending_objects;
     C.Object_sink.flush sink >|= fun r ->
     f.srv.stop ();
     get_ok r;
     Alcotest.(check (list string)) "no signature errors" [] f.sig_errors;
     let objs = sorted_objects f in
     Alcotest.(check int) "3 objects" 3 (List.length objs);
     List.iteri
       (fun i (k, body, hs) ->
         let expect =
           Printf.sprintf
             "/audit-bkt/haltsql/audit/2023/11/14/22/testhost-run1-%010d-%s.jsonl" i
             (sha256_hex body)
         in
         Alcotest.(check string) (Printf.sprintf "key %d" i) expect k;
         Alcotest.(check (option string))
           "lock mode" (Some "COMPLIANCE")
           (List.assoc_opt "x-amz-object-lock-mode" hs);
         Alcotest.(check (option string))
           "retain until" (Some "2023-12-14T22:13:20Z")
           (List.assoc_opt "x-amz-object-lock-retain-until-date" hs);
         Alcotest.(check (option string))
           "session token sent" (Some "sess-tok")
           (List.assoc_opt "x-amz-security-token" hs);
         Alcotest.(check (option string))
           "create-only" (Some "*")
           (List.assoc_opt "if-none-match" hs);
         Alcotest.(check (option string))
           "content type" (Some "application/x-ndjson")
           (List.assoc_opt "content-type" hs);
         Alcotest.(check bool)
           "token is signed" true
           (contains
              (Option.value ~default:"" (List.assoc_opt "authorization" hs))
              "x-amz-security-token"))
       objs;
     Alcotest.(check (list int))
       "records per object" [ 3; 3; 1 ]
       (List.map
          (fun (_, b, _) ->
            List.length (String.split_on_char '\n' b |> List.filter (( <> ) "")))
          objs);
     Alcotest.(check (result int (pair int string)))
       "one chain across objects" (Ok 7)
       (C.Audit_chain.verify_lines (all_lines objs));
     let st = C.Object_sink.stats sink in
     Alcotest.(check int) "uploaded" 3 st.objects_uploaded;
     Alcotest.(check int) "nothing buffered" 0 st.buffered_records;
     Alcotest.(check (option string))
       "chain head is last hash"
       (C.Audit_chain.hash_of_line (List.nth (all_lines objs) 6))
       (Some st.chain_head))

(* Regression: a Hive-style prefix with sub-delims (and a space) must sign
   correctly; ocaml-uri normalises %3D etc. back to raw characters on the
   wire, while the server canonicalises the decoded key. *)
let test_s3_special_char_prefix () =
  run
    (let f = start_s3 () in
     let cfg =
       { (s3_cfg ~lock:None f) with s3_prefix = "audit/app=haltsql/a+b:c d@e,f;g/" }
     in
     let sink =
       get_ok
         (C.S3_sink.create ~now:fixed_now ~host:"h" ~run_id:"r1" ~max_attempts:1
            ~on_error:Config.Fail_closed cfg)
     in
     write_n sink 1 2;
     C.Object_sink.flush sink >|= fun r ->
     f.srv.stop ();
     Alcotest.(check (list string)) "no signature errors" [] f.sig_errors;
     get_ok r;
     Alcotest.(check bool) "sink healthy" true (C.Object_sink.healthy sink);
     match sorted_objects f with
     | [ (k, _, _) ] ->
         let expect =
           "/audit-bkt/audit/app=haltsql/a+b:c d@e,f;g/2023/11/14/22/h-r1-0000000000-"
         in
         Alcotest.(check string)
           "decoded key stored" expect
           (String.sub (Uri.pct_decode k) 0 (String.length expect))
     | l -> Alcotest.failf "%d objects" (List.length l))

let test_s3_no_lock_412 () =
  run
    (let f = start_s3 () in
     let cfg = s3_cfg ~lock:None f in
     let creds = C.Aws_creds.create (C.Aws_creds.source_of_s3 cfg.s3_credentials) in
     C.S3_sink.put_object ~now:fixed_now ~credentials:creds cfg ~key:"k/1.jsonl"
       ~body:"x\n"
     >>= fun r1 ->
     C.S3_sink.put_object ~now:fixed_now ~credentials:creds cfg ~key:"k/1.jsonl"
       ~body:"x\n"
     >|= fun r2 ->
     f.srv.stop ();
     Alcotest.(check bool) "first put" true (r1 = Ok ());
     Alcotest.(check bool) "412 (already stored) counts as delivered" true (r2 = Ok ());
     match sorted_objects f with
     | [ (_, _, hs) ] ->
         Alcotest.(check (option string))
           "no lock header" None
           (List.assoc_opt "x-amz-object-lock-mode" hs)
     | l -> Alcotest.failf "%d objects" (List.length l))

let test_s3_permanent () =
  run
    (let f = start_s3 () in
     f.mode <- S3_fail (403, "AccessDenied");
     let sink =
       get_ok
         (C.S3_sink.create ~max_attempts:3 ~on_error:Config.Fail_closed
            (s3_cfg ~max_records:1 f))
     in
     write_n sink 1 1;
     C.Object_sink.flush sink >|= fun r ->
     f.srv.stop ();
     Alcotest.(check (result unit string))
       "error" (Error "S3 PUT returned HTTP 403 AccessDenied") r;
     Alcotest.(check int) "permanent errors are not retried" 1 f.puts)

let test_s3_bad_signature_rejected () =
  run
    (let f = start_s3 () in
     let cfg =
       s3_cfg
         ~creds:
           (Config.S3_static
              {
                access_key_id = "AKIDTEST";
                secret_access_key = "WRONG";
                session_token = None;
              })
         f
     in
     let sink =
       get_ok (C.S3_sink.create ~max_attempts:1 ~on_error:Config.Fail_closed cfg)
     in
     write_n sink 1 1;
     C.Object_sink.flush sink >|= fun r ->
     f.srv.stop ();
     Alcotest.(check bool) "fake rejects a wrong secret" true (Result.is_error r);
     Alcotest.(check (list string))
       "server-side recompute caught it" [ "SignatureDoesNotMatch" ] f.sig_errors)

let test_s3_fail_closed () =
  run
    (let f = start_s3 () in
     f.mode <- S3_fail (500, "InternalError");
     let events = ref [] in
     let sink =
       get_ok
         (C.S3_sink.create ~max_attempts:2 ~base_backoff:0.01
            ~on_event:(fun e -> events := e :: !events)
            ~on_error:Config.Fail_closed (s3_cfg ~max_records:2 f))
     in
     write_n sink 1 2;
     C.Object_sink.flush sink >>= fun r ->
     Alcotest.(check (result unit string))
       "flush fails" (Error "S3 PUT returned HTTP 500 InternalError") r;
     Alcotest.(check int) "2 attempts" 2 f.puts;
     Alcotest.(check bool) "unhealthy" false (C.Object_sink.healthy sink);
     (match C.Object_sink.write sink (rec_fields 3) with
     | Error m ->
         Alcotest.(check string)
           "write refused (server returns 503)"
           "audit sink s3://audit-bkt/haltsql/audit/ unavailable: S3 PUT returned HTTP \
            500 InternalError"
           m
     | Ok () -> Alcotest.fail "fail_closed sink accepted a write");
     Alcotest.(check int) "rejections" 1 (C.Object_sink.stats sink).write_rejections;
     (* Recovery: the background loop retries the held object. *)
     f.mode <- S3_ok;
     C.Object_sink.start sink;
     wait_until (fun () -> C.Object_sink.healthy sink) >>= fun healed ->
     Alcotest.(check bool) "healthy again" true healed;
     Alcotest.(check bool)
       "recovery event" true
       (List.mem "audit sink s3://audit-bkt/haltsql/audit/ recovered" !events);
     write_n sink 3 4;
     C.Object_sink.close sink >|= fun r ->
     f.srv.stop ();
     get_ok r;
     let objs = sorted_objects f in
     Alcotest.(check (result int (pair int string)))
       "no record lost, chain intact" (Ok 4)
       (C.Audit_chain.verify_lines (all_lines objs)))

let test_s3_buffer_mode () =
  run
    (let f = start_s3 () in
     f.mode <- S3_fail (503, "SlowDown");
     let sink =
       get_ok
         (C.S3_sink.create ~max_attempts:1 ~max_buffer_records:4 ~on_error:Config.Buffer
            (s3_cfg ~max_records:2 f))
     in
     write_n sink 1 2;
     C.Object_sink.flush sink >>= fun r ->
     Alcotest.(check bool) "upload failed" true (Result.is_error r);
     Alcotest.(check bool) "buffer mode keeps accepting" true (C.Object_sink.healthy sink);
     write_n sink 3 4;
     (match C.Object_sink.write sink (rec_fields 5) with
     | Error m ->
         Alcotest.(check string)
           "bounded"
           "audit sink s3://audit-bkt/haltsql/audit/ buffer full (4 records awaiting \
            upload)"
           m
     | Ok () -> Alcotest.fail "buffer grew past its bound");
     Alcotest.(check bool) "full buffer is unhealthy" false (C.Object_sink.healthy sink);
     let st = C.Object_sink.stats sink in
     Alcotest.(check int) "buffered" 4 st.buffered_records;
     Alcotest.(check int) "failures" 1 st.upload_failures;
     let m = C.Object_sink.metrics_text [ sink ] in
     Alcotest.(check bool)
       "alert metric" true
       (contains m
          "haltsql_audit_sink_buffered_records{sink=\"s3://audit-bkt/haltsql/audit/\"} 4");
     Alcotest.(check bool)
       "health metric" true
       (contains m "haltsql_audit_sink_healthy{sink=\"s3://audit-bkt/haltsql/audit/\"} 0");
     f.mode <- S3_ok;
     C.Object_sink.flush sink >|= fun r ->
     f.srv.stop ();
     get_ok r;
     Alcotest.(check int) "drained" 0 (C.Object_sink.stats sink).buffered_records;
     Alcotest.(check (result int (pair int string)))
       "4 records, one chain" (Ok 4)
       (C.Audit_chain.verify_lines (all_lines (sorted_objects f))))

let test_s3_spool_recovery () =
  run
    (let f = start_s3 () in
     f.mode <- S3_fail (503, "SlowDown");
     let dir = tmp_dir () in
     let cfg = s3_cfg ~max_records:10 ~max_seconds:3600 f in
     let s1 =
       get_ok
         (C.S3_sink.create ~spool_dir:dir ~max_attempts:1 ~on_error:Config.Buffer cfg)
     in
     write_n s1 1 3;
     let head1 = (C.Object_sink.stats s1).chain_head in
     Alcotest.(check bool)
       "records spooled before write returns" true
       (Sys.file_exists (Filename.concat dir "current.jsonl"));
     (* "crash": s1 is abandoned without a flush *)
     let s2 =
       get_ok
         (C.S3_sink.create ~spool_dir:dir ~max_attempts:1 ~on_error:Config.Buffer cfg)
     in
     let st = C.Object_sink.stats s2 in
     Alcotest.(check int) "re-queued object" 1 st.pending_objects;
     Alcotest.(check int) "re-queued records" 3 st.buffered_records;
     Alcotest.(check string) "chain continues from the spool" head1 st.chain_head;
     write_n s2 4 5;
     f.mode <- S3_ok;
     C.Object_sink.close s2 >|= fun r ->
     f.srv.stop ();
     get_ok r;
     Alcotest.(check (result int (pair int string)))
       "5 records across restart" (Ok 5)
       (C.Audit_chain.verify_lines (all_lines (sorted_objects f)));
     Alcotest.(check (array string))
       "spool emptied after upload (only the chain head remains)" [| "head.json" |]
       (Sys.readdir dir))

(* ---- restarts: chain and sequence continuity (regression) ---- *)

(* An in-memory create-only store: a second PUT of an existing name succeeds
   without storing anything, like S3's 412 on If-None-Match (counted as
   delivered). [lose_response] stores the object but reports a failure. *)
let mem_store () =
  let objs = Hashtbl.create 8 in
  let lose = ref false in
  let up ~key ~body =
    if not (Hashtbl.mem objs key) then Hashtbl.replace objs key body;
    Lwt.return (if !lose then Error (C.Object_sink.Retryable "response lost") else Ok ())
  in
  (objs, lose, up)

let mem_lines objs =
  Hashtbl.fold (fun k v acc -> (k, v) :: acc) objs []
  |> List.sort compare
  |> List.concat_map (fun (_, b) ->
      String.split_on_char '\n' b |> List.filter (( <> ) ""))

let mk_sink ?spool_dir ?run_id ?(now = fixed_now) ?(max_records = 2) up =
  C.Object_sink.create ~now ~host:"h" ?run_id ?spool_dir ~max_attempts:1 ~name:"mem"
    ~prefix:"a/"
    ~batch:{ Config.max_records; max_seconds = 3600 }
    ~on_error:Config.Buffer up

let test_restart_without_spool_no_collision () =
  run
    (let objs, _, up = mem_store () in
     let s1 = get_ok (mk_sink up) and s2 = get_ok (mk_sink up) in
     write_n s1 1 2;
     write_n s2 1 2;
     C.Object_sink.flush s1 >>= fun r1 ->
     C.Object_sink.flush s2 >|= fun r2 ->
     get_ok r1;
     get_ok r2;
     let keys = Hashtbl.fold (fun k _ acc -> k :: acc) objs [] |> List.sort compare in
     Alcotest.(check int) "two runs, two distinct objects" 2 (List.length keys);
     match keys with
     | [ k1; k2 ] ->
         let run_of k = List.nth (String.split_on_char '-' (Filename.basename k)) 1 in
         Alcotest.(check bool) "distinct run ids" true (run_of k1 <> run_of k2)
     | _ -> assert false)

let test_restart_with_spool_continues_chain () =
  run
    (let objs, _, up = mem_store () in
     let dir = tmp_dir () in
     let s1 = get_ok (mk_sink ~spool_dir:dir ~run_id:"runA" up) in
     write_n s1 1 4;
     C.Object_sink.close s1 >>= fun r ->
     get_ok r;
     let head1 = (C.Object_sink.stats s1).chain_head in
     Alcotest.(check (array string))
       "every batch uploaded" [| "head.json" |] (Sys.readdir dir);
     (* restart: the spool holds no batch, only the persisted head *)
     let s2 = get_ok (mk_sink ~spool_dir:dir ~run_id:"runB" up) in
     Alcotest.(check string)
       "chain resumes from the persisted head" head1 (C.Object_sink.stats s2).chain_head;
     write_n s2 5 6;
     C.Object_sink.close s2 >|= fun r ->
     get_ok r;
     let keys = Hashtbl.fold (fun k _ acc -> k :: acc) objs [] |> List.sort compare in
     Alcotest.(check (list string))
       "names: run then continuing seq"
       [ "h-runA-0000000000"; "h-runA-0000000001"; "h-runB-0000000002" ]
       (List.map (fun k -> String.sub (Filename.basename k) 0 17) keys);
     Alcotest.(check (result int (pair int string)))
       "one chain across the restart" (Ok 6)
       (C.Audit_chain.verify_lines (mem_lines objs));
     (* deleting the first run's objects is now detected *)
     Hashtbl.filter_map_inplace
       (fun k v -> if contains k "-runA-" then None else Some v)
       objs;
     Alcotest.(check bool)
       "truncation at the restart boundary breaks verification" true
       (Result.is_error (C.Audit_chain.verify_lines (mem_lines objs))))

let test_spool_crash_after_upload_no_duplicate () =
  run
    (let objs, lose, up = mem_store () in
     let dir = tmp_dir () in
     let s1 = get_ok (mk_sink ~spool_dir:dir ~run_id:"runA" up) in
     write_n s1 1 2;
     (* the PUT lands, but the process dies before it learns so *)
     lose := true;
     C.Object_sink.flush s1 >>= fun r ->
     Alcotest.(check bool) "upload reported failed" true (Result.is_error r);
     Alcotest.(check int) "stored once" 1 (Hashtbl.length objs);
     lose := false;
     (* restart an hour later under a new run id *)
     let later () = fixed_now () +. 7200. in
     let s2 = get_ok (mk_sink ~spool_dir:dir ~run_id:"runB" ~now:later up) in
     Alcotest.(check int) "re-queued" 1 (C.Object_sink.stats s2).pending_objects;
     C.Object_sink.close s2 >|= fun r ->
     get_ok r;
     Alcotest.(check int) "same object name reused: no duplicate" 1 (Hashtbl.length objs);
     Alcotest.(check (result int (pair int string)))
       "chain" (Ok 2)
       (C.Audit_chain.verify_lines (mem_lines objs));
     Alcotest.(check (array string)) "spool cleaned" [| "head.json" |] (Sys.readdir dir))

let test_spool_corrupt_head_fails_closed () =
  let dir = tmp_dir () in
  Out_channel.with_open_bin (Filename.concat dir "head.json") (fun oc ->
      output_string oc {|{"seq":3,"prev":"nothex"}|});
  let _, _, up = mem_store () in
  (match mk_sink ~spool_dir:dir up with
  | Error e -> Alcotest.(check bool) "names the state file" true (contains e "head.json")
  | Ok _ -> Alcotest.fail "corrupt head.json must refuse to start");
  match mk_sink ~run_id:"bad-id" up with
  | Error e -> Alcotest.(check bool) "run id validated" true (contains e "run_id")
  | Ok _ -> Alcotest.fail "run id with '-' must be rejected"

(* ---- IMDSv2 and credential refresh ---- *)

let start_imds ?(lifetime = 3600.) () =
  let n = ref 0 in
  let srv =
    Fake_http.start (fun req _ ->
        let h = Fake_http.header req in
        match (Cohttp.Request.meth req, Fake_http.path req) with
        | `PUT, "/latest/api/token" ->
            if h "x-aws-ec2-metadata-token-ttl-seconds" = Some "21600" then
              Fake_http.respond "imds-session"
            else Fake_http.respond ~status:400 ""
        | `GET, p when h "x-aws-ec2-metadata-token" <> Some "imds-session" ->
            ignore p;
            Fake_http.respond ~status:401 ""
        | `GET, "/latest/meta-data/iam/security-credentials/" ->
            Fake_http.respond "haltsql-role\n"
        | `GET, "/latest/meta-data/iam/security-credentials/haltsql-role" ->
            incr n;
            Fake_http.respond
              (Yojson.Safe.to_string
                 (`Assoc
                    [
                      ("Code", `String "Success");
                      ("AccessKeyId", `String (Printf.sprintf "AKID%d" !n));
                      ("SecretAccessKey", `String (Printf.sprintf "secret%d" !n));
                      ("Token", `String (Printf.sprintf "tok%d" !n));
                      ( "Expiration",
                        `String (C.Cloud_util.rfc3339 (Unix.gettimeofday () +. lifetime))
                      );
                    ]))
        | _ -> Fake_http.respond ~status:404 "")
  in
  (srv, n)

let test_s3_expired_credentials_refresh () =
  run
    (let imds, _ = start_imds () in
     let f = start_s3 ~secrets:[ ("AKID1", "secret1"); ("AKID2", "secret2") ] () in
     f.mode <- S3_expired "AKID1";
     let env = env_of [ ("AWS_EC2_METADATA_SERVICE_ENDPOINT", Fake_http.url imds "") ] in
     let creds = C.Aws_creds.create ~env ~region:"us-east-1" C.Aws_creds.Instance in
     let sink =
       get_ok
         (C.S3_sink.create ~credentials:creds ~max_attempts:3 ~base_backoff:0.01
            ~on_error:Config.Fail_closed
            (s3_cfg ~creds:Config.S3_instance f))
     in
     write_n sink 1 1;
     C.Object_sink.flush sink >|= fun r ->
     f.srv.stop ();
     imds.stop ();
     get_ok r;
     Alcotest.(check int) "credentials fetched twice" 2 (C.Aws_creds.fetch_count creds);
     match sorted_objects f with
     | [ (_, _, hs) ] ->
         Alcotest.(check bool)
           "stored with refreshed key" true
           (contains (List.assoc "authorization" hs) "Credential=AKID2/");
         Alcotest.(check (option string))
           "session token" (Some "tok2")
           (List.assoc_opt "x-amz-security-token" hs)
     | l -> Alcotest.failf "%d objects" (List.length l))

let test_creds_refresh_margin () =
  run
    (let imds, n = start_imds ~lifetime:100. () in
     let env = env_of [ ("AWS_EC2_METADATA_SERVICE_ENDPOINT", Fake_http.url imds "") ] in
     let eager = C.Aws_creds.create ~env ~refresh_margin:300. C.Aws_creds.Instance in
     C.Aws_creds.get eager >>= fun a ->
     C.Aws_creds.get eager >>= fun b ->
     Alcotest.(check int)
       "refreshed: within margin of expiry" 2
       (C.Aws_creds.fetch_count eager);
     Alcotest.(check string) "first" "AKID1" (get_ok a).access_key_id;
     Alcotest.(check string) "second" "AKID2" (get_ok b).access_key_id;
     let lazy_ = C.Aws_creds.create ~env ~refresh_margin:10. C.Aws_creds.Instance in
     C.Aws_creds.get lazy_ >>= fun _ ->
     C.Aws_creds.get lazy_ >>= fun _ ->
     Alcotest.(check int) "cached while fresh" 1 (C.Aws_creds.fetch_count lazy_);
     imds.stop ();
     Lwt_unix.sleep 0.1 >>= fun () ->
     (* refresh fails, cached credentials still valid -> used *)
     C.Aws_creds.get eager >>= fun c ->
     Alcotest.(check string) "stale-but-valid fallback" "AKID2" (get_ok c).access_key_id;
     Alcotest.(check int) "IMDS hits" 3 !n;
     let none =
       C.Aws_creds.create
         ~env:(env_of [ ("AWS_EC2_METADATA_DISABLED", "true") ])
         C.Aws_creds.default_chain
     in
     C.Aws_creds.get none >|= fun r ->
     Alcotest.(check (result string string))
       "empty chain"
       (Error
          "no AWS credentials found (env: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY \
           are not set; web identity: AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN are \
           not set; instance: IMDS disabled by AWS_EC2_METADATA_DISABLED)")
       (Result.map (fun (c : S.credentials) -> c.access_key_id) r))

let test_creds_env_static () =
  run
    (let env =
       env_of
         [
           ("AWS_ACCESS_KEY_ID", "AKENV");
           ("AWS_SECRET_ACCESS_KEY", "sk");
           ("AWS_SESSION_TOKEN", "st");
         ]
     in
     C.Aws_creds.get (C.Aws_creds.create ~env C.Aws_creds.default_chain) >>= fun r ->
     let c = get_ok r in
     Alcotest.(check (list string))
       "env creds" [ "AKENV"; "sk"; "st" ]
       [ c.access_key_id; c.secret_access_key; Option.get c.session_token ];
     C.Aws_creds.get
       (C.Aws_creds.create
          (C.Aws_creds.Static
             { S.access_key_id = "AKS"; secret_access_key = "s"; session_token = None }))
     >|= fun r -> Alcotest.(check string) "static" "AKS" (get_ok r).access_key_id)

let test_web_identity () =
  run
    (let token_file = tmp_file "eyJhbGciOiJSUzI1NiJ9.web-identity-token\n" in
     let seen = ref [] in
     let sts =
       Fake_http.start (fun req body ->
           let q = Uri.query_of_encoded body in
           let p k = match List.assoc_opt k q with Some [ v ] -> v | _ -> "" in
           seen :=
             [
               p "Action";
               p "RoleArn";
               p "RoleSessionName";
               p "WebIdentityToken";
               Uri.verbatim_query (Cohttp.Request.uri req) |> Option.value ~default:"";
             ];
           if p "WebIdentityToken" <> "eyJhbGciOiJSUzI1NiJ9.web-identity-token" then
             Fake_http.respond ~status:400
               "<Error><Code>InvalidIdentityToken</Code></Error>"
           else
             Fake_http.respond
               "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAWEB</AccessKeyId><SecretAccessKey>websecret</SecretAccessKey><SessionToken>web&amp;token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>")
     in
     let env =
       env_of
         [
           ("AWS_WEB_IDENTITY_TOKEN_FILE", token_file);
           ("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/haltsql");
           ("AWS_ROLE_SESSION_NAME", "haltsql-test");
           ("AWS_ENDPOINT_URL_STS", Fake_http.url sts "");
         ]
     in
     let p = C.Aws_creds.create ~env C.Aws_creds.Web_identity in
     C.Aws_creds.get p >>= fun r ->
     C.Aws_creds.get p >|= fun _ ->
     sts.stop ();
     let c = get_ok r in
     Alcotest.(check (list string))
       "STS form"
       [
         "AssumeRoleWithWebIdentity";
         "arn:aws:iam::123456789012:role/haltsql";
         "haltsql-test";
         "eyJhbGciOiJSUzI1NiJ9.web-identity-token";
         "";
       ]
       !seen;
     Alcotest.(check (list string))
       "credentials"
       [ "ASIAWEB"; "websecret"; "web&token" ]
       [ c.access_key_id; c.secret_access_key; Option.get c.session_token ];
     Alcotest.(check int) "cached until expiry" 1 (C.Aws_creds.fetch_count p))

(* ================= GCS + metadata server ================= *)

let start_metadata () =
  let n = ref 0 in
  let srv =
    Fake_http.start (fun req _ ->
        if
          Fake_http.path req
          <> "/computeMetadata/v1/instance/service-accounts/default/token"
        then Fake_http.respond ~status:404 ""
        else if Fake_http.header req "metadata-flavor" <> Some "Google" then
          Fake_http.respond ~status:403 ""
        else begin
          incr n;
          Fake_http.respond
            ~headers:[ ("metadata-flavor", "Google") ]
            (Printf.sprintf
               {|{"access_token":"meta-tok-%d","expires_in":3600,"token_type":"Bearer"}|}
               !n)
        end)
  in
  (srv, n)

type fake_gcs = {
  gsrv : Fake_http.t;
  gobjects : (string, string) Hashtbl.t;
  mutable accept : string list;
  mutable bad_md5 : bool;
}

let start_gcs () =
  let rec st =
    lazy
      {
        gsrv =
          Fake_http.start (fun req body ->
              let st = Lazy.force st in
              let auth =
                Option.value ~default:"" (Fake_http.header req "authorization")
              in
              if not (List.exists (fun t -> auth = "Bearer " ^ t) st.accept) then
                Fake_http.respond ~status:401 {|{"error":{"code":401}}|}
              else if
                Fake_http.path req <> "/upload/storage/v1/b/audit-gcs/o"
                || query_param req "uploadType" <> Some "media"
                || query_param req "ifGenerationMatch" <> Some "0"
              then Fake_http.respond ~status:400 "bad request"
              else
                let name = Option.value ~default:"" (query_param req "name") in
                if Hashtbl.mem st.gobjects name then Fake_http.respond ~status:412 ""
                else begin
                  Hashtbl.replace st.gobjects name body;
                  Fake_http.respond
                    (Yojson.Safe.to_string
                       (`Assoc
                          [
                            ("name", `String name);
                            ("bucket", `String "audit-gcs");
                            ( "md5Hash",
                              `String (if st.bad_md5 then md5_b64 "x" else md5_b64 body)
                            );
                          ]))
                end);
        gobjects = Hashtbl.create 8;
        accept = [];
        bad_md5 = false;
      }
  in
  Lazy.force st

let gcs_cfg ?(max_records = 2) creds =
  {
    Config.gcs_bucket = "audit-gcs";
    gcs_prefix = "logs/";
    gcs_batch = { Config.max_records; max_seconds = 1 };
    gcs_credentials = creds;
    gcs_spool_dir = None;
  }

let gcs_lines g =
  Hashtbl.fold (fun k v acc -> (k, v) :: acc) g.gobjects []
  |> List.sort compare
  |> List.concat_map (fun (_, b) ->
      String.split_on_char '\n' b |> List.filter (( <> ) ""))

let test_gcs_metadata () =
  run
    (let md, n = start_metadata () in
     let g = start_gcs () in
     g.accept <- [ "meta-tok-2" ]
     (* the first token is "expired": exercises 401 -> refresh *);
     let env =
       env_of
         [
           ("GCE_METADATA_HOST", Printf.sprintf "127.0.0.1:%d" md.port);
           ("STORAGE_EMULATOR_HOST", Fake_http.url g.gsrv "");
         ]
     in
     let sink =
       get_ok
         (C.Gcs_sink.create ~env ~now:fixed_now ~host:"h1" ~run_id:"r1" ~base_backoff:0.01
            ~on_error:Config.Fail_closed (gcs_cfg Config.Gcs_metadata))
     in
     write_n sink 1 3;
     C.Object_sink.flush sink >>= fun r ->
     get_ok r;
     write_n sink 4 4;
     C.Object_sink.flush sink >|= fun r ->
     get_ok r;
     md.stop ();
     g.gsrv.stop ();
     Alcotest.(check int) "token refreshed once after 401, then cached" 2 !n;
     let names =
       Hashtbl.fold (fun k _ acc -> k :: acc) g.gobjects [] |> List.sort compare
     in
     Alcotest.(check int) "objects" 3 (List.length names);
     Alcotest.(check bool)
       "object name layout" true
       (String.sub (List.hd names) 0 36 = "logs/2023/11/14/22/h1-r1-0000000000-");
     Alcotest.(check (result int (pair int string)))
       "chain" (Ok 4)
       (C.Audit_chain.verify_lines (gcs_lines g)))

let test_gcs_md5_mismatch () =
  run
    (let md, _ = start_metadata () in
     let g = start_gcs () in
     g.accept <- [ "meta-tok-1" ];
     g.bad_md5 <- true;
     let env = env_of [ ("GCE_METADATA_HOST", Printf.sprintf "127.0.0.1:%d" md.port) ] in
     let sink =
       get_ok
         (C.Gcs_sink.create ~env ~endpoint:(Fake_http.url g.gsrv "") ~max_attempts:1
            ~on_error:Config.Fail_closed (gcs_cfg Config.Gcs_metadata))
     in
     write_n sink 1 2;
     C.Object_sink.flush sink >|= fun r ->
     md.stop ();
     g.gsrv.stop ();
     Alcotest.(check (result unit string))
       "integrity check" (Error "GCS md5Hash does not match the uploaded body") r;
     Alcotest.(check bool) "fail closed" false (C.Object_sink.healthy sink))

let b64url_decode s = Base64.decode_exn ~pad:false ~alphabet:Base64.uri_safe_alphabet s

let test_gcs_service_account () =
  run
    (let key = Mirage_crypto_pk.Rsa.generate ~bits:2048 () in
     let pub = Mirage_crypto_pk.Rsa.pub_of_priv key in
     let claims = ref `Null in
     let tok_srv =
       lazy
         (Fake_http.start (fun _ body ->
              let q = Uri.query_of_encoded body in
              let p k = match List.assoc_opt k q with Some [ v ] -> v | _ -> "" in
              if p "grant_type" <> "urn:ietf:params:oauth:grant-type:jwt-bearer" then
                Fake_http.respond ~status:400 {|{"error":"unsupported_grant_type"}|}
              else
                match String.split_on_char '.' (p "assertion") with
                | [ h; c; sg ] ->
                    let ok =
                      Mirage_crypto_pk.Rsa.PKCS1.verify
                        ~hashp:(fun x -> x = `SHA256)
                        ~key:pub ~signature:(b64url_decode sg)
                        (`Message (h ^ "." ^ c))
                    in
                    claims := Yojson.Safe.from_string (b64url_decode c);
                    let hdr = Yojson.Safe.from_string (b64url_decode h) in
                    if
                      ok
                      && C.Cloud_util.json_string_field hdr "alg" = Some "RS256"
                      && C.Cloud_util.json_string_field hdr "kid" = Some "kid-1"
                    then
                      Fake_http.respond
                        {|{"access_token":"sa-tok","expires_in":3600,"token_type":"Bearer"}|}
                    else Fake_http.respond ~status:400 {|{"error":"invalid_grant"}|}
                | _ -> Fake_http.respond ~status:400 {|{"error":"invalid_request"}|}))
     in
     let ts = Lazy.force tok_srv in
     let token_uri = Fake_http.url ts "/token" in
     let sa =
       Yojson.Safe.to_string
         (`Assoc
            [
              ("type", `String "service_account");
              ("client_email", `String "haltsql@proj.iam.gserviceaccount.com");
              ("private_key_id", `String "kid-1");
              ("private_key", `String (X509.Private_key.encode_pem (`RSA key)));
              ("token_uri", `String token_uri);
            ])
     in
     let sa_file = tmp_file sa in
     let g = start_gcs () in
     g.accept <- [ "sa-tok" ];
     let sink =
       get_ok
         (C.Gcs_sink.create ~endpoint:(Fake_http.url g.gsrv "")
            ~on_error:Config.Fail_closed
            (gcs_cfg ~max_records:1 (Config.Gcs_service_account_file sa_file)))
     in
     write_n sink 1 1;
     C.Object_sink.flush sink >|= fun r ->
     ts.stop ();
     g.gsrv.stop ();
     get_ok r;
     Alcotest.(check int) "uploaded with the SA token" 1 (Hashtbl.length g.gobjects);
     let f = C.Cloud_util.json_string_field !claims in
     Alcotest.(check (list (option string)))
       "JWT claims"
       [
         Some "haltsql@proj.iam.gserviceaccount.com";
         Some token_uri;
         Some "https://www.googleapis.com/auth/cloud-platform";
       ]
       [ f "iss"; f "aud"; f "scope" ];
     (match C.Gcp_auth.service_account "{\"type\":\"authorized_user\"}" with
     | Error m ->
         Alcotest.(check string)
           "wrong type" "credentials type \"authorized_user\" is not service_account" m
     | Ok _ -> Alcotest.fail "accepted non-SA credentials");
     match
       C.Gcp_auth.service_account
         (Yojson.Safe.to_string
            (`Assoc
               [
                 ("type", `String "service_account");
                 ("client_email", `String "a@b");
                 ("private_key", `String "x");
                 ("token_uri", `String "http://evil.example/token");
               ]))
     with
     | Error m ->
         Alcotest.(check string)
           "token_uri must be https"
           "service account token_uri: http is only allowed for loopback hosts; use https"
           m
     | Ok _ -> Alcotest.fail "accepted http token_uri")

(* ================= Vault ================= *)

let start_vault () =
  let logins = ref 0 in
  let revoked = ref [] in
  let srv =
    Fake_http.start (fun req body ->
        let h = Fake_http.header req in
        let ns_ok = h "x-vault-namespace" = Some "team-a" in
        match (Cohttp.Request.meth req, Fake_http.path req) with
        | _ when not ns_ok ->
            Fake_http.respond ~status:400 {|{"errors":["missing namespace"]}|}
        | `POST, "/v1/auth/kubernetes/login" -> (
            let j = Yojson.Safe.from_string body in
            match
              ( C.Cloud_util.json_string_field j "role",
                C.Cloud_util.json_string_field j "jwt" )
            with
            | Some "haltsql", Some "k8s-sa-jwt" ->
                incr logins;
                Fake_http.respond
                  {|{"auth":{"client_token":"k8s-token","lease_duration":3600,"renewable":true}}|}
            | _ -> Fake_http.respond ~status:400 {|{"errors":["invalid role or jwt"]}|})
        | `POST, "/v1/auth/approle/login" -> (
            let j = Yojson.Safe.from_string body in
            match
              ( C.Cloud_util.json_string_field j "role_id",
                C.Cloud_util.json_string_field j "secret_id" )
            with
            | Some "rid", Some "sid" ->
                incr logins;
                Fake_http.respond
                  (Printf.sprintf
                     {|{"auth":{"client_token":"approle-token-%d","lease_duration":3600}}|}
                     !logins)
            | _ ->
                Fake_http.respond ~status:400
                  {|{"errors":["invalid role_id or secret_id"]}|})
        | `GET, "/v1/secret/data/haltsql/otel" -> (
            match h "x-vault-token" with
            | Some t
              when List.mem t [ "root-token"; "k8s-token"; "approle-token-2" ]
                   && not (List.mem t !revoked) ->
                Fake_http.respond
                  {|{"data":{"data":{"token":"otel-secret","port":4317,"nested":{"a":1}},"metadata":{"version":3}}}|}
            | Some "approle-token-1" ->
                revoked := "approle-token-1" :: !revoked;
                Fake_http.respond ~status:403 {|{"errors":["permission denied"]}|}
            | _ -> Fake_http.respond ~status:403 {|{"errors":["permission denied"]}|})
        | `GET, _ -> Fake_http.respond ~status:404 {|{"errors":[]}|}
        | _ -> Fake_http.respond ~status:405 "")
  in
  (srv, logins)

let vault_cfg srv auth =
  {
    Config.vault_address = Fake_http.url srv "";
    vault_namespace = Some "team-a";
    vault_auth = auth;
    vault_ca_file = None;
  }

let test_vault_token () =
  run
    (let srv, _ = start_vault () in
     let v = C.Vault.create (vault_cfg srv (Config.Vault_token "root-token")) in
     C.Vault.read v "secret/haltsql/otel#token" >>= fun a ->
     C.Vault.read v "secret/data/haltsql/otel#port" >>= fun b ->
     C.Vault.read v "secret/haltsql/otel#nope" >>= fun c ->
     C.Vault.read v "secret/haltsql/otel#nested" >>= fun d ->
     C.Vault.read v "secret/missing#x" >>= fun e ->
     C.Vault.read
       (C.Vault.create (vault_cfg srv (Config.Vault_token "bad")))
       "secret/haltsql/otel#token"
     >|= fun f ->
     srv.stop ();
     Alcotest.(check (result string string)) "inserted data/ segment" (Ok "otel-secret") a;
     Alcotest.(check (result string string)) "explicit data path, number" (Ok "4317") b;
     Alcotest.(check (result string string))
       "missing field" (Error "vault: field \"nope\" not found in secret/haltsql/otel") c;
     Alcotest.(check (result string string))
       "non-scalar"
       (Error "vault: field \"nested\" in secret/haltsql/otel is not a scalar") d;
     Alcotest.(check (result string string))
       "404" (Error "vault: secret secret/missing not found") e;
     Alcotest.(check (result string string))
       "403" (Error "vault: read secret/haltsql/otel failed: HTTP 403: permission denied")
       f;
     List.iter
       (fun r ->
         match r with
         | Error m ->
             Alcotest.(check bool) "no secret in errors" false (contains m "otel-secret")
         | Ok _ -> ())
       [ c; d; e; f ];
     Alcotest.(check (result string string))
       "api path" (Ok "/v1/kv/data/a%2Bb%40c/d")
       (C.Vault.api_path "kv/a+b@c/d");
     Alcotest.(check bool)
       "whitespace rejected" true
       (Result.is_error (C.Vault.api_path "kv/a b"));
     Alcotest.(check bool)
       "dot-dot rejected" true
       (Result.is_error (C.Vault.api_path "secret/../sys/x"));
     Alcotest.(check bool)
       "empty segment rejected" true
       (Result.is_error (C.Vault.api_path "secret//x"));
     Alcotest.(check bool)
       "mount alone rejected" true
       (Result.is_error (C.Vault.api_path "secret")))

let test_vault_kubernetes () =
  run
    (let srv, logins = start_vault () in
     let jwt = tmp_file "k8s-sa-jwt\n" in
     let v =
       C.Vault.create
         (vault_cfg srv
            (Config.Vault_kubernetes
               { role = "haltsql"; jwt_path = jwt; mount = "kubernetes" }))
     in
     C.Vault.read v "secret/haltsql/otel#token" >>= fun a ->
     C.Vault.read v "secret/haltsql/otel#port" >|= fun b ->
     srv.stop ();
     Alcotest.(check (result string string)) "read" (Ok "otel-secret") a;
     Alcotest.(check (result string string)) "second read" (Ok "4317") b;
     Alcotest.(check int) "one login, token cached" 1 !logins)

let test_vault_approle_relogin () =
  run
    (let srv, logins = start_vault () in
     let v =
       C.Vault.create
         (vault_cfg srv
            (Config.Vault_approle
               { role_id = "rid"; secret_id = "sid"; mount = "approle" }))
     in
     C.Vault.read v "secret/haltsql/otel#token" >>= fun a ->
     let bad =
       C.Vault.create
         (vault_cfg srv
            (Config.Vault_approle
               { role_id = "rid"; secret_id = "WRONG"; mount = "approle" }))
     in
     C.Vault.read bad "secret/haltsql/otel#token" >|= fun b ->
     srv.stop ();
     Alcotest.(check (result string string)) "403 then re-login" (Ok "otel-secret") a;
     Alcotest.(check int) "two logins" 2 !logins;
     Alcotest.(check (result string string))
       "login failure"
       (Error "vault login (approle) failed: HTTP 400: invalid role_id or secret_id") b)

(* Vault over HTTPS with a private CA (secrets.vault.ca_file). *)
let make_pki dir =
  let ptime f = Option.get (Ptime.of_float_s f) in
  let now = Unix.gettimeofday () in
  let valid_from = ptime (now -. 3600.) and valid_until = ptime (now +. 86400.) in
  let dn cn =
    [ X509.Distinguished_name.(Relative_distinguished_name.singleton (CN cn)) ]
  in
  let ca_key = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:2048 ()) in
  let ca_csr =
    Result.get_ok (X509.Signing_request.create (dn "HaltSQL Test CA") ca_key)
  in
  let ca_ext = X509.Extension.(singleton Basic_constraints (true, (true, None))) in
  let ca =
    Result.get_ok
      (X509.Signing_request.sign ca_csr ~valid_from ~valid_until ~extensions:ca_ext ca_key
         (dn "HaltSQL Test CA"))
  in
  let key = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:2048 ()) in
  let csr = Result.get_ok (X509.Signing_request.create (dn "localhost") key) in
  let ext =
    X509.Extension.(
      singleton Subject_alt_name (false, X509.General_name.(singleton DNS [ "localhost" ])))
  in
  let leaf =
    Result.get_ok
      (X509.Signing_request.sign csr ~valid_from ~valid_until ~extensions:ext ca_key
         (dn "HaltSQL Test CA"))
  in
  let w name s =
    let f = Filename.concat dir name in
    Out_channel.with_open_bin f (fun oc -> output_string oc s);
    f
  in
  ( w "ca.pem" (X509.Certificate.encode_pem ca),
    w "cert.pem" (X509.Certificate.encode_pem leaf),
    w "key.pem" (X509.Private_key.encode_pem key) )

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with Unix.ADDR_INET (_, p) -> p | _ -> 0 in
  Unix.close s;
  p

let test_vault_custom_ca () =
  run
    (let dir = tmp_dir () in
     let ca, cert, key = make_pki dir in
     let port = free_port () in
     let stop, stopper = Lwt.wait () in
     let callback _ req _ =
       if Fake_http.header req "x-vault-token" = Some "root-token" then
         Fake_http.respond {|{"data":{"data":{"token":"tls-secret"}}}|}
       else Fake_http.respond ~status:403 {|{"errors":["permission denied"]}|}
     in
     Lwt.async (fun () ->
         Cohttp_lwt_unix.Server.create ~stop ~on_exn:ignore
           ~mode:
             (`TLS_native
                (`Crt_file_path cert, `Key_file_path key, `No_password, `Port port))
           (Cohttp_lwt_unix.Server.make ~callback ()));
     Lwt_unix.sleep 0.2 >>= fun () ->
     let cfg ca_file =
       {
         Config.vault_address = Printf.sprintf "https://localhost:%d" port;
         vault_namespace = None;
         vault_auth = Config.Vault_token "root-token";
         vault_ca_file = ca_file;
       }
     in
     C.Vault.read (C.Vault.create (cfg (Some ca))) "secret/app#token" >>= fun a ->
     C.Vault.read (C.Vault.create ~timeout:3. (cfg None)) "secret/app#token" >>= fun b ->
     C.Vault.read
       (C.Vault.create (cfg (Some (Filename.concat dir "missing.pem"))))
       "secret/app#token"
     >|= fun c ->
     Lwt.wakeup_later stopper ();
     Alcotest.(check (result string string)) "trusted via ca_file" (Ok "tls-secret") a;
     Alcotest.(check bool)
       "system trust store rejects the private CA" true (Result.is_error b);
     Alcotest.(check bool)
       "missing CA file fails closed" true
       (match c with Error m -> contains m "cannot read CA file" | Ok _ -> false))

(* ================= AWS Secrets Manager ================= *)

let start_sm () =
  Fake_http.start (fun req body ->
      match
        verify_sigv4
          ~secrets:[ ("AKSM", "smsecret") ]
          ~service:"secretsmanager" ~region:"eu-west-1" req body
      with
      | Error e -> Fake_http.respond ~status:400 (Printf.sprintf {|{"__type":"%s"}|} e)
      | Ok _ -> (
          if Fake_http.header req "x-amz-target" <> Some "secretsmanager.GetSecretValue"
          then Fake_http.respond ~status:400 {|{"__type":"UnknownOperationException"}|}
          else
            match
              C.Cloud_util.json_string_field (Yojson.Safe.from_string body) "SecretId"
            with
            | Some "prod/db" ->
                Fake_http.respond
                  {|{"Name":"prod/db","SecretString":"{\"password\":\"hunter2\",\"port\":5432}"}|}
            | Some "plain" ->
                Fake_http.respond {|{"Name":"plain","SecretString":"just-a-string"}|}
            | Some "bin" ->
                Fake_http.respond
                  (Printf.sprintf {|{"Name":"bin","SecretBinary":"%s"}|}
                     (b64 "binary-value"))
            | _ ->
                Fake_http.respond ~status:400
                  {|{"__type":"com.amazonaws.secretsmanager#ResourceNotFoundException","message":"Secrets Manager can't find the specified secret."}|}
          ))

let test_aws_sm () =
  run
    (let srv = start_sm () in
     let credentials =
       C.Aws_creds.create
         (C.Aws_creds.Static
            {
              S.access_key_id = "AKSM";
              secret_access_key = "smsecret";
              session_token = None;
            })
     in
     let sm =
       C.Aws_sm.create ~credentials
         { Config.aws_region = "eu-west-1"; aws_endpoint = Some (Fake_http.url srv "") }
     in
     C.Aws_sm.get sm "prod/db#password" >>= fun a ->
     C.Aws_sm.get sm "prod/db#port" >>= fun b ->
     C.Aws_sm.get sm "plain" >>= fun c ->
     C.Aws_sm.get sm "bin" >>= fun d ->
     C.Aws_sm.get sm "missing" >>= fun e ->
     C.Aws_sm.get sm "plain#k" >>= fun f ->
     C.Aws_sm.get sm "prod/db#user" >>= fun g ->
     let wrong =
       C.Aws_creds.create
         (C.Aws_creds.Static
            { S.access_key_id = "AKSM"; secret_access_key = "nope"; session_token = None })
     in
     C.Aws_sm.get
       (C.Aws_sm.create ~credentials:wrong
          { Config.aws_region = "eu-west-1"; aws_endpoint = Some (Fake_http.url srv "") })
       "plain"
     >|= fun h ->
     srv.stop ();
     Alcotest.(check (result string string)) "json key" (Ok "hunter2") a;
     Alcotest.(check (result string string)) "json number" (Ok "5432") b;
     Alcotest.(check (result string string)) "string" (Ok "just-a-string") c;
     Alcotest.(check (result string string)) "binary" (Ok "binary-value") d;
     Alcotest.(check (result string string))
       "not found"
       (Error "aws-sm: GetSecretValue missing failed: HTTP 400 ResourceNotFoundException")
       e;
     Alcotest.(check (result string string))
       "not json"
       (Error "aws-sm secret plain is not a JSON object, cannot select key \"k\"") f;
     Alcotest.(check (result string string))
       "missing key" (Error "key \"user\" not found in aws-sm secret prod/db") g;
     Alcotest.(check (result string string))
       "signature verified server-side"
       (Error "aws-sm: GetSecretValue plain failed: HTTP 400 SignatureDoesNotMatch") h;
     List.iter
       (function
         | Error m ->
             Alcotest.(check bool)
               "no value leak" false
               (contains m "hunter2" || contains m "just-a-string")
         | Ok _ -> ())
       [ e; f; g; h ])

(* ================= GCP Secret Manager ================= *)

let start_gsm () =
  Fake_http.start (fun req _ ->
      let auth = Option.value ~default:"" (Fake_http.header req "authorization") in
      if not (String.length auth > 16 && String.sub auth 0 16 = "Bearer meta-tok-") then
        Fake_http.respond ~status:401
          {|{"error":{"code":401,"status":"UNAUTHENTICATED"}}|}
      else
        let payload ?(crc = true) v =
          let c = Int64.logand (Int64.of_int32 (C.Cloud_util.crc32c v)) 0xFFFFFFFFL in
          Fake_http.respond
            (Yojson.Safe.to_string
               (`Assoc
                  [
                    ("name", `String "projects/p1/secrets/x/versions/1");
                    ( "payload",
                      `Assoc
                        ([ ("data", `String (b64 v)) ]
                        @
                        if crc then [ ("dataCrc32c", `String (Int64.to_string c)) ]
                        else [ ("dataCrc32c", `String "1") ]) );
                  ]))
        in
        match Fake_http.path req with
        | "/v1/projects/p1/secrets/db/versions/latest:access" ->
            payload {|{"user":"app","pw":"s3cr3t"}|}
        | "/v1/projects/p2/secrets/api/versions/7:access" -> payload "api-key-7"
        | "/v1/projects/p1/secrets/corrupt/versions/latest:access" ->
            payload ~crc:false "tampered"
        | _ ->
            Fake_http.respond ~status:404 {|{"error":{"code":404,"status":"NOT_FOUND"}}|})

let test_gcp_sm () =
  run
    (let md, n = start_metadata () in
     let srv = start_gsm () in
     let env = env_of [ ("GCE_METADATA_HOST", Printf.sprintf "127.0.0.1:%d" md.port) ] in
     let g =
       C.Gcp_sm.create ~env
         { Config.gcp_project = Some "p1"; gcp_endpoint = Some (Fake_http.url srv "") }
     in
     C.Gcp_sm.get g "db#user" >>= fun a ->
     C.Gcp_sm.get g "projects/p2/secrets/api/versions/7" >>= fun b ->
     C.Gcp_sm.get g "corrupt" >>= fun c ->
     C.Gcp_sm.get g "nope" >>= fun d ->
     C.Gcp_sm.get g "bad/name" >|= fun e ->
     md.stop ();
     srv.stop ();
     Alcotest.(check (result string string)) "short name + key" (Ok "app") a;
     Alcotest.(check (result string string)) "full name" (Ok "api-key-7") b;
     Alcotest.(check (result string string))
       "crc32c checked"
       (Error "gcp-sm: CRC32C mismatch for projects/p1/secrets/corrupt/versions/latest")
       c;
     Alcotest.(check (result string string))
       "404"
       (Error
          "gcp-sm: access projects/p1/secrets/nope/versions/latest failed: HTTP 404 \
           NOT_FOUND")
       d;
     Alcotest.(check (result string string))
       "name syntax" (Error "gcp-sm: invalid Secret Manager name \"bad/name\"") e;
     Alcotest.(check int) "one token for all reads" 1 !n;
     Alcotest.(check (result string string))
       "no project"
       (Error "gcp-sm \"db\" is a short name but secrets.gcp.project is not set")
       (C.Gcp_sm.resource_name ~project:None "db");
     Alcotest.(check (result string string))
       "secret without version" (Ok "projects/a/secrets/b/versions/latest")
       (C.Gcp_sm.resource_name ~project:None "projects/a/secrets/b"))

(* ================= Secrets: Config ?resolve integration ================= *)

let test_scan () =
  Alcotest.(check (list (pair string string)))
    "scan"
    [ ("vault", "secret/a#b"); ("aws-sm", "id#k"); ("gcp-sm", "s") ]
    (C.Secrets.scan_placeholders
       "x: ${vault:secret/a#b} y: $${vault:esc#aped} ${env:HOME} ${aws-sm:id#k} \
        ${vault:secret/a#b} ${gcp-sm:s} ${unterminated")

let config_doc ~vault_url =
  Printf.sprintf
    {|apiVersion: haltsql.dev/v1
kind: Config
policies:
  - inline: {metadata: {name: p1}}
telemetry:
  otlp:
    endpoint: http://127.0.0.1:4318
    headers:
      authorization: "Bearer ${vault:secret/haltsql/otel#token}"
      x-again: "${vault:secret/haltsql/otel#token}"
      x-db: "${aws-sm:prod/db#password}"
      x-gcp: "${gcp-sm:db#user}"
secrets:
  vault:
    address: %s
    namespace: team-a
    auth: {method: token, token: "${env:VAULT_TOKEN}"}
  aws:
    region: eu-west-1
    endpoint: %s
  gcp:
    project: p1
    endpoint: %s
|}
    vault_url

let test_load_config () =
  let vsrv, _ = start_vault () in
  let sm = start_sm () in
  let md, _ = start_metadata () in
  let gsm = start_gsm () in
  let file =
    tmp_file ~ext:".yaml"
      (config_doc ~vault_url:(Fake_http.url vsrv "") (Fake_http.url sm "")
         (Fake_http.url gsm ""))
  in
  let env =
    env_of
      [
        ("VAULT_TOKEN", "root-token");
        ("AWS_ACCESS_KEY_ID", "AKSM");
        ("AWS_SECRET_ACCESS_KEY", "smsecret");
        ("GCE_METADATA_HOST", Printf.sprintf "127.0.0.1:%d" md.port);
      ]
  in
  (* async path (server) *)
  (match run (C.Secrets.load_config ~env file) with
  | Ok cfg ->
      let o = Option.get cfg.otlp in
      Alcotest.(check (list (pair string string)))
        "resolved headers"
        [
          ("authorization", "Bearer otel-secret");
          ("x-again", "otel-secret");
          ("x-db", "hunter2");
          ("x-gcp", "app");
        ]
        (List.sort compare o.otlp_headers)
  | Error errs ->
      Alcotest.failf "load failed: %s"
        (String.concat "; "
           (List.map (fun (e : Haltsql_core.Load_error.t) -> e.message) errs)));
  (* blocking path (CLI) *)
  (match C.Secrets.load_config_blocking ~env file with
  | Ok cfg ->
      Alcotest.(check int)
        "blocking load" 4
        (List.length (Option.get cfg.otlp).otlp_headers)
  | Error errs ->
      Alcotest.failf "blocking load failed: %s"
        (String.concat "; "
           (List.map (fun (e : Haltsql_core.Load_error.t) -> e.message) errs)));
  (* per-load cache: one fetch per distinct reference *)
  let t =
    C.Secrets.create ~env
      (get_ok (Result.map_error (fun _ -> "secrets") (Config.secrets_of_file ~env file)))
  in
  run
    (C.Secrets.prefetch t
       (C.Secrets.scan_placeholders (In_channel.with_open_bin file In_channel.input_all)));
  Alcotest.(check int)
    "3 distinct references fetched once each" 3 (C.Secrets.fetch_count t);
  Alcotest.(check (result string string))
    "blocking resolver serves cache" (Ok "otel-secret")
    (C.Secrets.blocking_resolver t ~scheme:"vault" ~reference:"secret/haltsql/otel#token");
  Alcotest.(check int) "no refetch" 3 (C.Secrets.fetch_count t);
  Alcotest.(check (result string string))
    "blocking resolver fetches a miss" (Ok "4317")
    (C.Secrets.blocking_resolver t ~scheme:"vault" ~reference:"secret/haltsql/otel#port");
  Alcotest.(check (result string string))
    "cached resolver miss"
    (Error "secret was not prefetched (placeholder not found verbatim in the config file)")
    (C.Secrets.cached_resolver t ~scheme:"vault" ~reference:"secret/other#x");
  (* a failing secret is a located load error without the value *)
  let bad =
    tmp_file ~ext:".yaml"
      (Str_compat.replace
         (config_doc ~vault_url:(Fake_http.url vsrv "") (Fake_http.url sm "")
            (Fake_http.url gsm ""))
         "otel#token}\"\n      x-again" "otel#missing}\"\n      x-again")
  in
  (match C.Secrets.load_config_blocking ~env bad with
  | Error errs ->
      let msgs = List.map (fun (e : Haltsql_core.Load_error.t) -> e.message) errs in
      Alcotest.(check bool)
        "names the reference and the cause" true
        (List.exists
           (fun m ->
             contains m "${vault:secret/haltsql/otel#missing}"
             && contains m "field \"missing\" not found")
           msgs);
      Alcotest.(check bool)
        "no secret values in errors" false
        (List.exists (fun m -> contains m "otel-secret" || contains m "hunter2") msgs)
  | Ok _ -> Alcotest.fail "missing field accepted");
  (* provider not configured *)
  let t2 = C.Secrets.create Config.no_secrets in
  Alcotest.(check (result string string))
    "unconfigured provider" (Error "secrets.vault is not configured")
    (run (C.Secrets.resolve t2 ~scheme:"vault" ~reference:"a/b#c"));
  vsrv.stop ();
  sm.stop ();
  md.stop ();
  gsm.stop ()

(* ================= misc ================= *)

let test_util () =
  Alcotest.(check int32) "crc32c(123456789)" 0xE3069283l (C.Cloud_util.crc32c "123456789");
  Alcotest.(check (option string))
    "xml entity" (Some "a&b<c")
    (C.Cloud_util.xml_tag "<r><Code>a&amp;b&lt;c</Code></r>" "Code");
  Alcotest.(check (option (float 0.1)))
    "rfc3339" (Some 1700000000.)
    (C.Cloud_util.parse_rfc3339 "2023-11-14T22:13:20Z");
  Alcotest.(check string)
    "rfc3339 out" "2023-11-14T22:13:20Z"
    (C.Cloud_util.rfc3339 1700000000.);
  let ok s = Result.is_ok (C.Http.check_endpoint ~what:"x" s) in
  Alcotest.(check (list bool))
    "endpoint policy"
    [ true; true; true; false; false; false; false ]
    (List.map ok
       [
         "https://vault.corp:8200";
         "http://127.0.0.1:8200";
         "http://localhost:1";
         "http://vault.corp";
         "https://u:p@h";
         "https://h/?q=1";
         "ftp://h";
       ]);
  Alcotest.(check string)
    "object key"
    "p/2023/11/14/22/h-r1-0000000042-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.jsonl"
    (C.Object_sink.object_key ~prefix:"p/" ~host:"h" ~run:"r1" ~seq:42 ~time:1700000000.
       "")

let test_audit_chain () =
  let l1, h1 = C.Audit_chain.seal ~prev:C.Audit_chain.genesis [ ("a", `Int 1) ] in
  let l2, _ = C.Audit_chain.seal ~prev:h1 [ ("a", `Int 2) ] in
  Alcotest.(check string)
    "server-compatible line"
    (Printf.sprintf {|{"a":1,"prev_hash":"%s","hash":"%s"}|} C.Audit_chain.genesis
       (sha256_hex
          (C.Audit_chain.genesis
          ^ Printf.sprintf {|{"a":1,"prev_hash":"%s"}|} C.Audit_chain.genesis)))
    l1;
  Alcotest.(check (result int (pair int string)))
    "verifies" (Ok 2)
    (C.Audit_chain.verify_lines [ l1; l2 ]);
  Alcotest.(check (result int (pair int string)))
    "tamper detected"
    (Error (2, "hash mismatch (record was modified)"))
    (C.Audit_chain.verify_lines [ l1; Str_compat.replace l2 "\"a\":2" "\"a\":3" ]);
  Alcotest.(check (result int (pair int string)))
    "reorder detected"
    (Error (1, "prev_hash does not match the previous record's hash"))
    (C.Audit_chain.verify_lines [ l2; l1 ])

let () =
  Alcotest.run "cloud"
    [
      ( "sigv4",
        [
          Alcotest.test_case "get-vanilla" `Quick test_sigv4_get_vanilla;
          Alcotest.test_case "query order" `Quick test_sigv4_query_order;
          Alcotest.test_case "post-vanilla" `Quick test_sigv4_post_vanilla;
          Alcotest.test_case "IAM ListUsers" `Quick test_sigv4_iam;
          Alcotest.test_case "S3 examples" `Quick test_sigv4_s3_examples;
          Alcotest.test_case "helpers" `Quick test_sigv4_helpers;
        ] );
      ( "credentials",
        [
          Alcotest.test_case "env + static" `Quick test_creds_env_static;
          Alcotest.test_case "web identity" `Quick test_web_identity;
          Alcotest.test_case "refresh margin" `Quick test_creds_refresh_margin;
        ] );
      ( "s3",
        [
          Alcotest.test_case "upload + chain + object lock" `Quick
            test_s3_upload_and_chain;
          Alcotest.test_case "412 and no lock" `Quick test_s3_no_lock_412;
          Alcotest.test_case "prefix with = + : @ , ; and space" `Quick
            test_s3_special_char_prefix;
          Alcotest.test_case "permanent error" `Quick test_s3_permanent;
          Alcotest.test_case "bad signature" `Quick test_s3_bad_signature_rejected;
          Alcotest.test_case "fail_closed" `Quick test_s3_fail_closed;
          Alcotest.test_case "buffer" `Quick test_s3_buffer_mode;
          Alcotest.test_case "spool recovery" `Quick test_s3_spool_recovery;
          Alcotest.test_case "restart without spool: distinct run ids" `Quick
            test_restart_without_spool_no_collision;
          Alcotest.test_case "restart with spool: chain + seq continue" `Quick
            test_restart_with_spool_continues_chain;
          Alcotest.test_case "crash after upload: no duplicate object" `Quick
            test_spool_crash_after_upload_no_duplicate;
          Alcotest.test_case "corrupt spool state fails closed" `Quick
            test_spool_corrupt_head_fails_closed;
          Alcotest.test_case "expired credentials" `Quick
            test_s3_expired_credentials_refresh;
        ] );
      ( "gcs",
        [
          Alcotest.test_case "metadata token + 401 refresh" `Quick test_gcs_metadata;
          Alcotest.test_case "md5 mismatch" `Quick test_gcs_md5_mismatch;
          Alcotest.test_case "service account JWT" `Quick test_gcs_service_account;
        ] );
      ( "secrets",
        [
          Alcotest.test_case "vault token" `Quick test_vault_token;
          Alcotest.test_case "vault kubernetes" `Quick test_vault_kubernetes;
          Alcotest.test_case "vault approle re-login" `Quick test_vault_approle_relogin;
          Alcotest.test_case "vault custom CA (https)" `Quick test_vault_custom_ca;
          Alcotest.test_case "aws secrets manager" `Quick test_aws_sm;
          Alcotest.test_case "gcp secret manager" `Quick test_gcp_sm;
          Alcotest.test_case "scan placeholders" `Quick test_scan;
          Alcotest.test_case "load config" `Quick test_load_config;
        ] );
      ( "misc",
        [
          Alcotest.test_case "util" `Quick test_util;
          Alcotest.test_case "audit chain" `Quick test_audit_chain;
        ] );
    ]
