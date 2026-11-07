(* Tests for haltsql-server.

   In-process: servers are started with Haltsql_server.Server.serve on
   ephemeral ports; Lwt promises started by one Lwt_main.run keep running in
   later ones, so each test case drives the shared event loop.

   Subprocess: the real binary, for signals and startup checks. *)

open Lwt.Syntax
open Haltsql_server
module Client = Cohttp_lwt_unix.Client

let fx name = Filename.concat "fixtures" name

let tmpdir =
  let d =
    Filename.concat
      (Filename.get_temp_dir_name ())
      (Printf.sprintf "haltsql-server-test-%d" (Unix.getpid ()))
  in
  (try Unix.mkdir d 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  d

let tmp name = Filename.concat tmpdir name
let read_file f = In_channel.with_open_bin f In_channel.input_all
let write_file f s = Out_channel.with_open_bin f (fun oc -> output_string oc s)
let copy src dst = write_file dst (read_file src)

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  n = 0 || go 0

let member k = function
  | `Assoc kv -> Option.value (List.assoc_opt k kv) ~default:`Null
  | _ -> `Null

let sha = Auth.sha256_hex
let token_a = "token-for-shop-agent"
let token_b = "token-for-other-agent"

(* Policy files live in tmpdir so tests can modify them. *)
let shop_path = tmp "shop.yaml"
let other_path = tmp "other.json"
let audit_path = tmp "audit.jsonl"
let audit_path_b = tmp "audit-anon.jsonl"

let () =
  copy (fx "shop.yaml") shop_path;
  copy (fx "other.json") other_path;
  (try Sys.remove audit_path with _ -> ());
  try Sys.remove audit_path_b with _ -> ()

let tokens : Haltsql.Config.token list =
  [
    { token_name = "shop-agent"; token_sha256 = sha token_a; token_policy = "shop" };
    {
      token_name = "other-agent";
      token_sha256 = String.uppercase_ascii (sha token_b);
      token_policy = "other";
    };
  ]

let file_sink p =
  {
    Haltsql.Config.sink = Haltsql.Config.Sink_file p;
    on_error = Haltsql.Config.Fail_closed;
  }

let start ~overrides ~policy_files =
  let sources = { State.config_file = None; policy_files; overrides } in
  match State.load sources with
  | Error e -> Alcotest.failf "load failed: %s" (String.concat "; " e)
  | Ok cfg ->
      let st = State.create ~sources cfg in
      let fd, port = Server.bind_listen "127.0.0.1:0" in
      let stop, stopper = Lwt.wait () in
      Lwt.async (fun () -> Server.serve ~watch_interval:0.2 st fd ~stop);
      (st, port, stopper)

(* Server A: tokens required, file audit sink, file watching, 4 KiB body cap. *)
let st_a, port_a, _stop_a =
  Log.setup ~level:"error" ~format:"json";
  start ~policy_files:[ shop_path; other_path ] ~overrides:(fun c ->
      {
        c with
        tokens;
        allow_unauthenticated = false;
        audit_sinks = [ Haltsql.Config.Audit_file audit_path ];
        sinks = [ file_sink audit_path ];
        reload_watch = true;
        max_request_bytes = 4096;
      })

(* Server B: unauthenticated dev mode, default policy shop, raw SQL audit. *)
let st_b, port_b, _stop_b =
  start ~policy_files:[ shop_path; other_path ] ~overrides:(fun c ->
      {
        c with
        tokens;
        allow_unauthenticated = true;
        default_policy = Some "shop";
        audit_sinks = [ Haltsql.Config.Audit_file audit_path_b ];
        sinks = [ file_sink audit_path_b ];
        log_raw_sql = true;
        reload_watch = false;
      })

let uri port path = Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" port path)

type resp = { status : int; body : string; headers : Cohttp.Header.t }

let request ?(meth = `GET) ?token ?(headers = []) ?body port path =
  let headers =
    Cohttp.Header.of_list
      ((match token with Some t -> [ ("authorization", "Bearer " ^ t) ] | None -> [])
      @ (if body <> None then [ ("content-type", "application/json") ] else [])
      @ headers)
  in
  let body = Option.map Cohttp_lwt.Body.of_string body in
  let* r, b = Client.call ~headers ?body meth (uri port path) in
  let* s = Cohttp_lwt.Body.to_string b in
  Lwt.return
    {
      status = Cohttp.Code.code_of_status (Cohttp.Response.status r);
      body = s;
      headers = Cohttp.Response.headers r;
    }

let run p = Lwt_main.run p

let json r =
  try Yojson.Safe.from_string r.body
  with _ -> Alcotest.failf "not JSON (%d): %s" r.status r.body

let check_status msg expected r =
  if r.status <> expected then
    Alcotest.failf "%s: expected %d, got %d: %s" msg expected r.status r.body

let error_code r = member "code" (member "error" (json r))

let verify_body ?policy ?(context = {|{"tenant_id":"acme"}|}) sql =
  Printf.sprintf {|{"sql":%s,"context":%s%s}|}
    (Yojson.Safe.to_string (`String sql))
    context
    (match policy with Some p -> Printf.sprintf {|,"policy":"%s"|} p | None -> "")

let good_sql = "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10"

(* ------------------------------------------------------------------ *)

let health () =
  run
    (let* r = request port_a "/healthz" in
     check_status "healthz" 200 r;
     let* r = request port_a "/readyz" in
     check_status "readyz" 200 r;
     Alcotest.(check bool)
       "x-request-id" true
       (Cohttp.Header.get r.headers "x-request-id" <> None);
     Lwt.return_unit)

let request_id_echo () =
  run
    (let* r = request ~headers:[ ("x-request-id", "abc-123") ] port_a "/healthz" in
     Alcotest.(check (option string))
       "echoed" (Some "abc-123")
       (Cohttp.Header.get r.headers "x-request-id");
     let* r =
       request ~headers:[ ("x-request-id", "bad id with spaces") ] port_a "/healthz"
     in
     let id = Option.value (Cohttp.Header.get r.headers "x-request-id") ~default:"" in
     Alcotest.(check int) "generated uuid" 36 (String.length id);
     Alcotest.(check char) "v4" '4' id.[14];
     Lwt.return_unit)

let verify_with_token () =
  run
    (let* r =
       request ~meth:`POST ~token:token_a ~body:(verify_body "DROP TABLE x") port_a
         "/v1/verify"
     in
     check_status "verify" 200 r;
     let j = json r in
     Alcotest.(check bool) "denied" true (member "allowed" j = `Bool false);
     Alcotest.(check bool)
       "policy shop" true
       (member "name" (member "policy" j) = `String "shop");
     (* pinned policy explicitly named is fine *)
     let* r =
       request ~meth:`POST ~token:token_a
         ~body:(verify_body ~policy:"shop" "DROP TABLE x")
         port_a "/v1/verify"
     in
     check_status "explicit pinned" 200 r;
     (* upper-case configured hash still matches *)
     let* r =
       request ~meth:`POST ~token:token_b ~body:(verify_body "DROP TABLE x") port_a
         "/v1/verify"
     in
     check_status "token b" 200 r;
     let j = json r in
     Alcotest.(check bool)
       "policy other" true
       (member "name" (member "policy" j) = `String "other");
     (* other is a shadow policy: allowed, with shadow reasons *)
     Alcotest.(check bool) "shadow allowed" true (member "allowed" j = `Bool true);
     Alcotest.(check bool) "shadow reasons" true (member "shadow_reasons" j <> `List []);
     Lwt.return_unit)

let verify_allowed_query () =
  (* [needs analyzer] *)
  run
    (let* r =
       request ~meth:`POST ~token:token_a ~body:(verify_body good_sql) port_a "/v1/verify"
     in
     check_status "verify" 200 r;
     let j = json r in
     Alcotest.(check bool) "allowed" true (member "allowed" j = `Bool true);
     Alcotest.(check bool)
       "bind" true
       (member "bind_params" j
       = `List [ `Assoc [ ("param", `Int 1); ("value", `String "acme") ] ]);
     Lwt.return_unit)

let auth_failures () =
  run
    (let body = verify_body "SELECT 1" in
     let* r = request ~meth:`POST ~body port_a "/v1/verify" in
     check_status "missing" 401 r;
     Alcotest.(check bool) "code" true (error_code r = `String "UNAUTHORIZED");
     Alcotest.(check bool)
       "www-authenticate" true
       (Cohttp.Header.get r.headers "www-authenticate" <> None);
     let* r = request ~meth:`POST ~token:"wrong" ~body port_a "/v1/verify" in
     check_status "invalid" 401 r;
     let* r =
       request ~meth:`POST
         ~headers:[ ("authorization", "Basic Zm9vOmJhcg==") ]
         ~body port_a "/v1/verify"
     in
     check_status "wrong scheme" 401 r;
     let* r =
       request ~meth:`POST ~token:token_a
         ~body:(verify_body ~policy:"other" "SELECT 1")
         port_a "/v1/verify"
     in
     check_status "pinned mismatch" 403 r;
     Alcotest.(check bool) "code" true (error_code r = `String "FORBIDDEN");
     (* invalid token is rejected even in unauthenticated mode *)
     let* r = request ~meth:`POST ~token:"wrong" ~body port_b "/v1/verify" in
     check_status "invalid on B" 401 r;
     Lwt.return_unit)

let unauthenticated_mode () =
  run
    (let* r =
       request ~meth:`POST ~body:(verify_body "DROP TABLE x") port_b "/v1/verify"
     in
     check_status "anon default" 200 r;
     Alcotest.(check bool)
       "default shop" true
       (member "name" (member "policy" (json r)) = `String "shop");
     let* r =
       request ~meth:`POST
         ~body:(verify_body ~policy:"other" "DROP TABLE x")
         port_b "/v1/verify"
     in
     check_status "anon picks" 200 r;
     Alcotest.(check bool)
       "other" true
       (member "name" (member "policy" (json r)) = `String "other");
     let* r =
       request ~meth:`POST
         ~body:(verify_body ~policy:"nope" "DROP TABLE x")
         port_b "/v1/verify"
     in
     check_status "unknown policy" 404 r;
     (* a token still pins on server B *)
     let* r =
       request ~meth:`POST ~token:token_a
         ~body:(verify_body ~policy:"other" "SELECT 1")
         port_b "/v1/verify"
     in
     check_status "pinned on B" 403 r;
     Lwt.return_unit)

let bad_requests () =
  run
    (let post body = request ~meth:`POST ~token:token_a ~body port_a "/v1/verify" in
     let cases =
       [
         "not json";
         "[]";
         {|{}|};
         {|{"sql":1}|};
         {|{"sql":"SELECT 1","context":[1]}|};
         {|{"sql":"SELECT 1","context":{"tenant_id":{"x":1}}}|};
         {|{"sql":"SELECT 1","policy":7}|};
         {|{"sql":"SELECT 1","extra":true}|};
       ]
     in
     let* () =
       Lwt_list.iter_s
         (fun b ->
           let* r = post b in
           check_status ("bad request: " ^ b) 400 r;
           Alcotest.(check bool) "code" true (error_code r = `String "BAD_REQUEST");
           Lwt.return_unit)
         cases
     in
     Lwt.return_unit)

let too_large () =
  run
    (let big = verify_body (String.make 5000 'x') in
     let* r = request ~meth:`POST ~token:token_a ~body:big port_a "/v1/verify" in
     check_status "413" 413 r;
     Alcotest.(check bool) "code" true (error_code r = `String "PAYLOAD_TOO_LARGE");
     Lwt.return_unit)

let routing () =
  run
    (let* r = request port_a "/nope" in
     check_status "404" 404 r;
     let* r = request port_a "/v1/verify" in
     check_status "GET verify" 405 r;
     Alcotest.(check (option string))
       "allow" (Some "POST")
       (Cohttp.Header.get r.headers "allow");
     let* r = request ~meth:`POST ~body:"{}" port_a "/healthz" in
     check_status "POST healthz" 405 r;
     Lwt.return_unit)

let policies () =
  run
    (let* r = request ~token:token_a port_a "/v1/policies" in
     check_status "policies" 200 r;
     let names j =
       match member "policies" j with
       | `List l -> List.map (fun p -> member "name" p) l
       | _ -> []
     in
     Alcotest.(check bool) "filtered to pinned" true (names (json r) = [ `String "shop" ]);
     (match member "policies" (json r) with
     | `List [ p ] ->
         Alcotest.(check bool)
           "version" true
           (match member "version" p with `String v -> String.length v > 7 | _ -> false)
     | _ -> Alcotest.fail "one policy");
     let* r = request port_a "/v1/policies" in
     check_status "no token" 401 r;
     let* r = request port_b "/v1/policies" in
     check_status "anon lists all" 200 r;
     Alcotest.(check int) "two" 2 (List.length (names (json r)));
     Lwt.return_unit)

let metrics () =
  run
    (let* r = request port_a "/metrics" in
     check_status "metrics" 200 r;
     List.iter
       (fun s ->
         if not (contains r.body s) then Alcotest.failf "metrics missing %S:\n%s" s r.body)
       [
         "haltsql_verify_total{policy=\"shop\",result=\"denied\"}";
         "haltsql_verify_total{policy=\"other\",result=\"shadow_denied\"}";
         "haltsql_reasons_total{code=";
         "haltsql_verify_duration_seconds_bucket{le=\"0.001\"}";
         "haltsql_verify_duration_seconds_bucket{le=\"+Inf\"}";
         "haltsql_verify_duration_seconds_count";
         "haltsql_build_info{version=\"" ^ Haltsql.version ^ "\",pg=\"";
         "# TYPE haltsql_verify_duration_seconds histogram";
         "haltsql_policies_loaded 2";
       ];
     Lwt.return_unit)

(* ---- audit ---- *)

let audit_lines path =
  String.split_on_char '\n' (read_file path) |> List.filter (fun l -> String.trim l <> "")

let audit_chain () =
  let lines = audit_lines audit_path in
  if List.length lines < 3 then
    Alcotest.failf "expected audit records, got %d" (List.length lines);
  (match Audit.verify_lines lines with
  | Ok n -> Alcotest.(check int) "records verified" (List.length lines) n
  | Error e -> Alcotest.failf "chain broken at line %d: %s" e.line_no e.problem);
  let first = Yojson.Safe.from_string (List.hd lines) in
  Alcotest.(check bool) "genesis" true (member "prev_hash" first = `String Audit.genesis);
  List.iter
    (fun k ->
      if member k first = `Null && k <> "fingerprint" then
        Alcotest.failf "missing field %s" k)
    [
      "ts";
      "request_id";
      "caller";
      "policy";
      "policy_version";
      "allowed";
      "shadow";
      "codes";
      "sql_sha256";
      "fingerprint";
      "elapsed_us";
      "prev_hash";
      "hash";
    ];
  Alcotest.(check bool) "caller" true (member "caller" first = `String "shop-agent");
  Alcotest.(check bool) "caller_type" true (member "caller_type" first = `String "token");
  Alcotest.(check bool) "subject" true (member "subject" first = `Null);
  Alcotest.(check bool) "no raw sql" true (member "sql" first = `Null);
  (* field order: hash last, prev_hash just before *)
  (match first with
  | `Assoc kv -> (
      match List.rev kv with
      | ("hash", _) :: ("prev_hash", _) :: _ -> ()
      | _ -> Alcotest.fail "hash must be last, prev_hash second to last")
  | _ -> ());
  (* raw SQL on server B; anonymous caller *)
  let b = Yojson.Safe.from_string (List.hd (audit_lines audit_path_b)) in
  Alcotest.(check bool) "raw sql" true (member "sql" b = `String "DROP TABLE x");
  Alcotest.(check bool) "anonymous" true (member "caller" b = `String "anonymous");
  Alcotest.(check bool)
    "anonymous type" true
    (member "caller_type" b = `String "anonymous");
  (match Audit.verify_file audit_path_b with
  | Ok _ -> ()
  | Error e -> Alcotest.failf "B chain: %s" e.problem);
  (* tampering: edit a field in the middle *)
  let arr = Array.of_list lines in
  let mid = Array.length arr / 2 in
  let tampered = Array.copy arr in
  tampered.(mid) <-
    Str.global_replace
      (Str.regexp_string {|"allowed":false|})
      {|"allowed":true|} arr.(mid);
  if tampered.(mid) = arr.(mid) then
    tampered.(mid) <-
      Str.global_replace (Str.regexp_string {|"caller":"|}) {|"caller":"x|} arr.(mid);
  (match Audit.verify_lines (Array.to_list tampered) with
  | Ok _ -> Alcotest.fail "tampered line was not detected"
  | Error e -> Alcotest.(check int) "detected at edited line" (mid + 1) e.line_no);
  (* deleting a line breaks the chain at the following line *)
  let deleted = List.filteri (fun i _ -> i <> mid) lines in
  (match Audit.verify_lines deleted with
  | Ok _ -> Alcotest.fail "deleted line was not detected"
  | Error e -> Alcotest.(check int) "detected after deletion" (mid + 1) e.line_no);
  (* recomputing the edited line's own hash still breaks the next link *)
  let j = Yojson.Safe.from_string tampered.(mid) in
  match j with
  | `Assoc kv -> (
      let body = List.filter (fun (k, _) -> k <> "hash") kv in
      let prev = match member "prev_hash" j with `String p -> p | _ -> "" in
      let h = Audit.sha256_hex (prev ^ Yojson.Safe.to_string (`Assoc body)) in
      let resealed = Array.copy tampered in
      resealed.(mid) <- Yojson.Safe.to_string (`Assoc (body @ [ ("hash", `String h) ]));
      if mid + 1 < Array.length arr then
        match Audit.verify_lines (Array.to_list resealed) with
        | Ok _ -> Alcotest.fail "resealed line was not detected"
        | Error e -> Alcotest.(check int) "detected at next line" (mid + 2) e.line_no)
  | _ -> ()

let audit_resume () =
  (* Re-opening the sink continues the chain from the last record. *)
  let path = tmp "resume.jsonl" in
  (try Sys.remove path with _ -> ());
  let s = Audit.open_file path in
  Audit.append s [ ("n", `Int 1) ];
  Audit.append s [ ("n", `Int 2) ];
  Audit.close s;
  let s = Audit.open_file path in
  Audit.append s [ ("n", `Int 3) ];
  Audit.close s;
  match Audit.verify_file path with
  | Ok n -> Alcotest.(check int) "3 records" 3 n
  | Error e -> Alcotest.failf "resume broke chain at %d: %s" e.line_no e.problem

let audit_buffer_mode () =
  (* on_error: buffer keeps records when the backend fails and writes them,
     chained in order, once it recovers. *)
  let lines = ref [] and fail = ref true in
  let sink =
    Audit.custom ~on_error:Haltsql.Config.Buffer ~name:"mem"
      ~write:(fun l -> if !fail then failwith "down" else lines := l :: !lines)
      ~close:ignore ()
  in
  let d n = Audit.deliver sink [ ("n", `Int n) ] in
  Alcotest.(check bool) "buffered 1" true (d 1 = Audit.Buffered);
  Alcotest.(check bool) "buffered 2" true (d 2 = Audit.Buffered);
  fail := false;
  Alcotest.(check bool) "written 3" true (d 3 = Audit.Written);
  let written = List.rev_map String.trim !lines in
  Alcotest.(check int) "all three written" 3 (List.length written);
  (match Audit.verify_lines written with
  | Ok n -> Alcotest.(check int) "chain" 3 n
  | Error e -> Alcotest.failf "chain: %s" e.problem);
  Alcotest.(check (list string))
    "order" [ "1"; "2"; "3" ]
    (List.map
       (fun l -> Yojson.Safe.to_string (member "n" (Yojson.Safe.from_string l)))
       written);
  (* fail_closed reports failure immediately *)
  let fc = Audit.custom ~name:"fc" ~write:(fun _ -> failwith "down") ~close:ignore () in
  match Audit.deliver fc [ ("n", `Int 1) ] with
  | Audit.Failed e -> Alcotest.(check string) "message" "down" e
  | _ -> Alcotest.fail "expected Failed"

let audit_failure_fails_closed () =
  (* A sink whose fd is closed makes writes fail: the request must get 503. *)
  let path = tmp "closed.jsonl" in
  let sources =
    {
      State.config_file = None;
      policy_files = [ shop_path ];
      overrides =
        (fun c ->
          {
            c with
            allow_unauthenticated = true;
            audit_sinks = [ Haltsql.Config.Audit_file path ];
            sinks = [ file_sink path ];
          });
    }
  in
  let cfg =
    match State.load sources with
    | Ok c -> c
    | Error e -> Alcotest.failf "%s" (String.concat ";" e)
  in
  let st = State.create ~sources cfg in
  List.iter Audit.close st.sinks;
  (* A read-only descriptor: every append fails with EBADF. *)
  let ro = Unix.openfile path [ Unix.O_RDONLY ] 0 in
  let st = { st with sinks = [ Audit.of_fd ~name:path ro ] } in
  let fd, port = Server.bind_listen "127.0.0.1:0" in
  let stop, stopper = Lwt.wait () in
  Lwt.async (fun () -> Server.serve st fd ~stop);
  run
    (let* r = request ~meth:`POST ~body:(verify_body "DROP TABLE x") port "/v1/verify" in
     check_status "fail closed" 503 r;
     Alcotest.(check bool) "code" true (error_code r = `String "AUDIT_UNAVAILABLE");
     Lwt.wakeup_later stopper ();
     Lwt.return_unit)

(* ---- hot reload ---- *)

let policy_version st name =
  match State.find_policy st name with
  | Some (p : Haltsql.Policy.t) -> p.version
  | None -> "<missing>"

let reload_counter result =
  let s = Metrics.render ~version:"" ~pg:"" ~policies_loaded:0 in
  let key = Printf.sprintf "haltsql_policy_reload_total{result=\"%s\"} " result in
  String.split_on_char '\n' s
  |> List.find_map (fun l ->
      if String.length l > String.length key && String.sub l 0 (String.length key) = key
      then
        int_of_string_opt
          (String.sub l (String.length key) (String.length l - String.length key))
      else None)
  |> Option.value ~default:0

let wait_until ?(timeout = 5.0) f =
  let t0 = Unix.gettimeofday () in
  let rec loop () =
    if f () then Lwt.return true
    else if Unix.gettimeofday () -. t0 > timeout then Lwt.return false
    else
      let* () = Lwt_unix.sleep 0.05 in
      loop ()
  in
  loop ()

let hot_reload_watch () =
  let v0 = policy_version st_a "shop" in
  let ok0 = reload_counter "success" and err0 = reload_counter "error" in
  (* valid change: require_limit 100 -> 50 changes the version *)
  let original = read_file shop_path in
  let changed = Str.global_replace (Str.regexp_string "max: 100") "max: 50" original in
  run
    (let* () =
       Lwt_unix.sleep 1.1
       (* distinct mtime on coarse filesystems *)
     in
     write_file shop_path changed;
     let* ok = wait_until (fun () -> policy_version st_a "shop" <> v0) in
     Alcotest.(check bool) "watch reloaded valid change" true ok;
     Alcotest.(check bool) "success metric" true (reload_counter "success" > ok0);
     let v1 = policy_version st_a "shop" in
     (* corrupt file: last good set is kept *)
     let* () = Lwt_unix.sleep 1.1 in
     write_file shop_path
       "apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: { name: shop }\ntabels: {}\n";
     let* ok = wait_until (fun () -> reload_counter "error" > err0) in
     Alcotest.(check bool) "failed reload counted" true ok;
     Alcotest.(check string) "last good kept" v1 (policy_version st_a "shop");
     Alcotest.(check int) "both policies kept" 2 (List.length st_a.snap.policies);
     let* r =
       request ~meth:`POST ~token:token_a ~body:(verify_body "DROP TABLE x") port_a
         "/v1/verify"
     in
     check_status "still serving" 200 r;
     Alcotest.(check bool)
       "with last good" true
       (member "version" (member "policy" (json r)) = `String v1);
     let* r = request port_a "/readyz" in
     check_status "still ready" 200 r;
     (* restore *)
     let* () = Lwt_unix.sleep 1.1 in
     write_file shop_path original;
     let* ok = wait_until (fun () -> policy_version st_a "shop" = v0) in
     Alcotest.(check bool) "restored" true ok;
     Lwt.return_unit)

let manual_reload () =
  (* State.reload is what SIGHUP triggers. *)
  let err0 = reload_counter "error" in
  let original = read_file other_path in
  write_file other_path "{ not json";
  (match State.reload st_b with
  | Ok () -> Alcotest.fail "reload should fail"
  | Error _ -> ());
  Alcotest.(check int) "error metric" (err0 + 1) (reload_counter "error");
  Alcotest.(check int) "kept" 2 (List.length st_b.snap.policies);
  write_file other_path original;
  match State.reload st_b with
  | Ok () -> ()
  | Error e -> Alcotest.failf "reload: %s" (String.concat ";" e)

(* Regression: server.auth.allow_unauthenticated from the config file must be
   applied on reload. Previously Http.static_caller read the startup value, so
   switching anonymous access off with SIGHUP silently had no effect. *)
let reload_disables_anonymous () =
  let cfg_path = tmp "anon-reload.yaml" in
  let audit = tmp "anon-reload.jsonl" in
  let write_cfg allow =
    write_file cfg_path
      (Printf.sprintf
         "apiVersion: haltsql.dev/v1\n\
          kind: Config\n\
          server:\n\
         \  auth:\n\
         \    tokens:\n\
         \      - {name: shop-agent, token_sha256: %s, policy: shop}\n\
         \    allow_unauthenticated: %b\n\
          policies:\n\
         \  - path: %s\n\
          default_policy: shop\n"
         (sha token_a) allow shop_path)
  in
  write_cfg true;
  let sources =
    {
      State.config_file = Some cfg_path;
      policy_files = [];
      overrides =
        (fun c ->
          {
            c with
            audit_sinks = [ Haltsql.Config.Audit_file audit ];
            sinks = [ file_sink audit ];
            reload_watch = false;
          });
    }
  in
  let cfg =
    match State.load sources with
    | Ok c -> c
    | Error e -> Alcotest.failf "load: %s" (String.concat ";" e)
  in
  Alcotest.(check bool) "starts open" true cfg.allow_unauthenticated;
  let st = State.create ~sources cfg in
  let fd, port = Server.bind_listen "127.0.0.1:0" in
  let stop, stopper = Lwt.wait () in
  Lwt.async (fun () -> Server.serve st fd ~stop);
  run
    (let* r = request ~meth:`POST ~body:(verify_body "DROP TABLE x") port "/v1/verify" in
     check_status "anonymous accepted before reload" 200 r;
     write_cfg false;
     (match State.reload st with
     | Ok () -> ()
     | Error e -> Alcotest.failf "reload: %s" (String.concat ";" e));
     Alcotest.(check bool) "snapshot updated" false st.snap.allow_unauthenticated;
     let* r = request ~meth:`POST ~body:(verify_body "DROP TABLE x") port "/v1/verify" in
     check_status "anonymous rejected after reload" 401 r;
     let* r =
       request ~meth:`POST ~token:token_a ~body:(verify_body "DROP TABLE x") port
         "/v1/verify"
     in
     check_status "token still accepted" 200 r;
     (* and back on again *)
     write_cfg true;
     (match State.reload st with
     | Ok () -> ()
     | Error e -> Alcotest.failf "reload: %s" (String.concat ";" e));
     let* r = request ~meth:`POST ~body:(verify_body "DROP TABLE x") port "/v1/verify" in
     check_status "anonymous accepted after re-enable" 200 r;
     Lwt.wakeup_later stopper ();
     Lwt.return_unit)

(* ---- subprocess: the real binary ---- *)

let server_bin =
  let b =
    Option.value
      (Sys.getenv_opt "HALTSQL_SERVER_BIN")
      ~default:"../../bin/server/main.exe"
  in
  if Filename.is_relative b then Filename.concat (Sys.getcwd ()) b else b

let spawn args =
  let err = tmp (Printf.sprintf "server-%d.stderr" (Random.bits ())) in
  let out = tmp (Printf.sprintf "server-%d.stdout" (Random.bits ())) in
  let fd_err = Unix.openfile err [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o644 in
  let fd_out = Unix.openfile out [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o644 in
  let pid =
    Unix.create_process server_bin
      (Array.of_list (server_bin :: args))
      Unix.stdin fd_out fd_err
  in
  Unix.close fd_err;
  Unix.close fd_out;
  (pid, out, err)

let find_port err_file =
  let rec loop n =
    let s = try read_file err_file with _ -> "" in
    let found =
      String.split_on_char '\n' s
      |> List.find_map (fun l ->
          match Yojson.Safe.from_string l with
          | j when member "msg" j = `String "haltsql-server listening" -> (
              match member "port" j with `Int p -> Some p | _ -> None)
          | _ -> None
          | exception _ -> None)
    in
    match found with
    | Some p -> p
    | None when n > 100 -> Alcotest.failf "server did not start:\n%s" s
    | None ->
        Unix.sleepf 0.05;
        loop (n + 1)
  in
  loop 0

let wait_exit pid =
  let rec loop n =
    match Unix.waitpid [ Unix.WNOHANG ] pid with
    | 0, _ when n > 100 ->
        Unix.kill pid Sys.sigkill;
        Alcotest.fail "server did not exit"
    | 0, _ ->
        Unix.sleepf 0.05;
        loop (n + 1)
    | _, Unix.WEXITED c -> c
    | _, _ -> -1
  in
  loop 0

let subprocess_signals () =
  let pol = tmp "proc-shop.yaml" in
  copy (fx "shop.yaml") pol;
  let pid, out, err =
    spawn
      [
        "--policy";
        pol;
        "--listen";
        "127.0.0.1:0";
        "--allow-unauthenticated";
        "--no-watch";
        "--log-level";
        "info";
      ]
  in
  let port = find_port err in
  run
    (let* r = request ~meth:`POST ~body:(verify_body "DROP TABLE x") port "/v1/verify" in
     check_status "verify" 200 r;
     let v0 = member "version" (member "policy" (json r)) in
     write_file pol
       (Str.global_replace (Str.regexp_string "max: 100") "max: 10" (read_file pol));
     Unix.kill pid Sys.sighup;
     let* () = Lwt_unix.sleep 0.5 in
     let* r = request port "/metrics" in
     if not (contains r.body "haltsql_policy_reload_total{result=\"success\"} 1") then
       Alcotest.failf "SIGHUP reload not counted:\n%s" r.body;
     let* r = request ~meth:`POST ~body:(verify_body "DROP TABLE x") port "/v1/verify" in
     Alcotest.(check bool)
       "new version after SIGHUP" true
       (member "version" (member "policy" (json r)) <> v0);
     Lwt.return_unit);
  (* audit went to stdout (default sink) *)
  Unix.kill pid Sys.sigterm;
  Alcotest.(check int) "graceful exit 0" 0 (wait_exit pid);
  (match Audit.verify_file out with
  | Ok n -> Alcotest.(check int) "stdout audit records" 2 n
  | Error e -> Alcotest.failf "stdout audit chain: %s" e.problem);
  if not (contains (read_file err) "shutting down") then Alcotest.fail "no shutdown log"

(* TLS is built in now; unreadable certificate material must still refuse to
   start (exit 2) with an error naming the setting. *)
let subprocess_tls_bad_material () =
  let pid, _, err = spawn [ "--config"; fx "tls.yaml" ] in
  Alcotest.(check int) "exit 2" 2 (wait_exit pid);
  let s = read_file err in
  if not (contains s "server.tls.cert") then Alcotest.failf "unclear TLS error:\n%s" s

let subprocess_bad_config () =
  let pid, _, _ = spawn [ "--policy"; fx "missing.yaml" ] in
  Alcotest.(check int) "missing policy file -> 2" 2 (wait_exit pid);
  let bad = tmp "bad.yaml" in
  write_file bad "kind: Policy\n";
  let pid, _, _ = spawn [ "--policy"; bad; "--listen"; "127.0.0.1:0" ] in
  Alcotest.(check int) "invalid policy -> 2" 2 (wait_exit pid);
  let pid, _, _ = spawn [] in
  Alcotest.(check int) "no policy -> 2" 2 (wait_exit pid)

let unit_auth () =
  Alcotest.(check bool) "ct_equal eq" true (Auth.ct_equal "abc" "abc");
  Alcotest.(check bool) "ct_equal ne" false (Auth.ct_equal "abc" "abd");
  Alcotest.(check bool) "ct_equal len" false (Auth.ct_equal "abc" "abcd");
  Alcotest.(check bool) "ct_equal empty" false (Auth.ct_equal "abc" "");
  (match Auth.authenticate tokens (Some ("bearer " ^ token_a)) with
  | Auth.Token t ->
      Alcotest.(check string) "case-insensitive scheme" "shop-agent" t.token_name
  | _ -> Alcotest.fail "token");
  Alcotest.(check bool)
    "empty token" true
    (Auth.authenticate tokens (Some "Bearer ") = Auth.Invalid);
  Alcotest.(check bool) "missing" true (Auth.authenticate tokens None = Auth.Missing)

let unit_listen () =
  Alcotest.(check bool)
    "v4" true
    (Server.parse_listen "127.0.0.1:8080" = Ok ("127.0.0.1", 8080));
  Alcotest.(check bool) "v6" true (Server.parse_listen "[::1]:9" = Ok ("::1", 9));
  Alcotest.(check bool) "any" true (Server.parse_listen ":80" = Ok ("0.0.0.0", 80));
  Alcotest.(check bool) "bad" true (Result.is_error (Server.parse_listen "nope"));
  Alcotest.(check bool) "bad port" true (Result.is_error (Server.parse_listen "h:99999"))

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run ~and_exit:true "haltsql-server"
    [
      ( "unit",
        [ tc "auth" unit_auth; tc "listen" unit_listen; tc "audit resume" audit_resume ]
      );
      ( "http",
        [
          tc "health + readiness" health;
          tc "request id" request_id_echo;
          tc "verify with token" verify_with_token;
          tc "auth failures" auth_failures;
          tc "unauthenticated mode" unauthenticated_mode;
          tc "bad requests" bad_requests;
          tc "413" too_large;
          tc "routing" routing;
          tc "policies" policies;
          tc "metrics" metrics;
          tc "[needs analyzer] allowed + bind params" verify_allowed_query;
        ] );
      ( "audit",
        [
          tc "hash chain + tamper detection" audit_chain;
          tc "fail closed" audit_failure_fails_closed;
          tc "buffer mode" audit_buffer_mode;
        ] );
      ( "reload",
        [
          tc "file watch: success and failure" hot_reload_watch;
          tc "manual (SIGHUP path)" manual_reload;
          tc "allow_unauthenticated off on reload" reload_disables_anonymous;
        ] );
      ( "process",
        [
          tc "SIGHUP reload, SIGTERM shutdown" subprocess_signals;
          tc "TLS with unreadable cert exits 2" subprocess_tls_bad_material;
          tc "bad config exits 2" subprocess_bad_config;
        ] );
    ]
