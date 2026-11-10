(* Console_server tests: body limits, CSRF and media type, allowed origins and the dev-mode
   Host check, auth before routing, path parameter validation, timeouts and the
   in-flight cap, background loop supervision, /readyz, static frontend, dev-mode listen
   validation, connection idle timeout and cap, and graceful shutdown. *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console

(* ---- harness ---- *)

let handler_ran = ref false

let test_routes =
  let open C.Router in
  [
    post "/api/v1/t/echo" (fun _ _ r ->
        handler_ran := true;
        let* j = json_body r in
        C.Api.json j);
    get "/api/v1/t/items/:id" (fun _ _ r -> C.Api.json (`String (param r "id")));
    get "/api/v1/t/slow" (fun _ _ _ ->
        let* () = Lwt_unix.sleep 0.5 in
        C.Api.json (`String "slow"));
  ]

(** Starts a console through [Console_server.serve] with the test routes and no background
    loops unless given; returns the running handle and the serving promise. *)
let start_server ?(routes = test_routes) ?(background = []) ?max_body_bytes
    ?request_timeout ?max_in_flight ?max_connections ?idle_timeout ?initial_backoff cfg =
  let cfg = { cfg with C.Console_config.listen = "127.0.0.1:0" } in
  let store = C.Store.create cfg.state_dir in
  let index = C.Index.create () in
  let ctx = C.Ctx.create ~config:cfg ~store ~index in
  let stop_p, stop = Lwt.wait () in
  let* port, serving =
    C.Console_server.serve ~stop:stop_p ~routes ~background ?max_body_bytes
      ?request_timeout ?max_in_flight ?max_connections ?idle_timeout ?initial_backoff ctx
  in
  Lwt.return ({ ctx; port; stop }, serving)

let with_server ?routes ?background ?max_body_bytes ?request_timeout ?max_in_flight
    ?max_connections ?idle_timeout ?initial_backoff ?(cfg = config ()) f =
  Lwt_main.run
    (let* r, serving =
       start_server ?routes ?background ?max_body_bytes ?request_timeout ?max_in_flight
         ?max_connections ?idle_timeout ?initial_backoff cfg
     in
     Lwt.finalize
       (fun () -> f r)
       (fun () ->
         Helpers.stop r;
         Lwt.pick [ serving; Lwt_unix.sleep 5. ]))

let call ?(headers = []) ?body meth r path =
  let body = Option.value body ~default:`Empty in
  let* resp, b =
    Cohttp_lwt_unix.Client.call
      ~headers:(Cohttp.Header.of_list headers)
      ~body meth (uri r path)
  in
  let* j = body_json b in
  Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status resp), j)

let error_code j =
  match member "error.code" j with `String s -> s | j -> Yojson.Safe.to_string j

let check_error msg status code (got, body) =
  check_status msg status (got, body);
  Alcotest.(check string) (msg ^ " code") code (error_code body)

let json_ct = [ ("content-type", "application/json") ]
let str j = Yojson.Safe.to_string j

let contains s sub =
  let n = String.length sub in
  let rec go i = i + n <= String.length s && (String.sub s i n = sub || go (i + 1)) in
  go 0

(* ---- body limits ---- *)

let body_tests =
  [
    ( "chunked body over the limit is 413",
      `Quick,
      fun () ->
        with_server ~max_body_bytes:1024 (fun r ->
            (* 64 chunks of 4 KiB with no Content-Length: sent chunked. *)
            let n = ref 0 in
            let stream =
              Lwt_stream.from_direct (fun () ->
                  incr n;
                  if !n = 1 then Some "{\"x\":\""
                  else if !n <= 64 then Some (String.make 4096 'a')
                  else if !n = 65 then Some "\"}"
                  else None)
            in
            handler_ran := false;
            let* res =
              call ~headers:json_ct
                ~body:(Cohttp_lwt.Body.of_stream stream)
                `POST r "/api/v1/t/echo"
            in
            check_error "chunked" 413 "TOO_LARGE" res;
            Alcotest.(check bool) "handler started reading" true !handler_ran;
            let* ok =
              call ~headers:json_ct
                ~body:(Cohttp_lwt.Body.of_string "{\"x\":1}")
                `POST r "/api/v1/t/echo"
            in
            check_status "small body" 200 ok;
            Lwt.return_unit) );
    ( "Content-Length over the limit is refused before the handler",
      `Quick,
      fun () ->
        with_server ~max_body_bytes:1024 (fun r ->
            handler_ran := false;
            let body = "{\"x\":\"" ^ String.make 4096 'a' ^ "\"}" in
            let* res =
              call ~headers:json_ct
                ~body:(Cohttp_lwt.Body.of_string body)
                `POST r "/api/v1/t/echo"
            in
            check_error "content-length" 413 "TOO_LARGE" res;
            Alcotest.(check bool) "handler not run" false !handler_ran;
            Lwt.return_unit) );
    ( "Api.read_body stops reading at the limit",
      `Quick,
      fun () ->
        let pulled = ref 0 in
        let stream =
          Lwt_stream.from_direct (fun () ->
              incr pulled;
              if !pulled <= 100 then Some (String.make 100 'a') else None)
        in
        match
          Lwt_main.run (C.Api.read_body ~max:250 (Cohttp_lwt.Body.of_stream stream))
        with
        | _ -> Alcotest.fail "expected TOO_LARGE"
        | exception C.Api.Error (_, code, _) ->
            Alcotest.(check string) "code" "TOO_LARGE" code;
            Alcotest.(check bool) "stopped early" true (!pulled <= 4) );
  ]

(* ---- CSRF and media type ---- *)

let csrf_tests =
  [
    ( "POST text/plain is 415",
      `Quick,
      fun () ->
        with_server (fun r ->
            let* res =
              call
                ~headers:[ ("content-type", "text/plain") ]
                ~body:(Cohttp_lwt.Body.of_string "{\"x\":1}")
                `POST r "/api/v1/t/echo"
            in
            check_error "text/plain" 415 "UNSUPPORTED_MEDIA_TYPE" res;
            let* res =
              call ~body:(Cohttp_lwt.Body.of_string "{\"x\":1}") `POST r "/api/v1/t/echo"
            in
            check_error "no content-type" 415 "UNSUPPORTED_MEDIA_TYPE" res;
            let* ok =
              call
                ~headers:[ ("content-type", "application/json; charset=utf-8") ]
                ~body:(Cohttp_lwt.Body.of_string "{\"x\":1}")
                `POST r "/api/v1/t/echo"
            in
            check_status "json with charset" 200 ok;
            let* empty = call `POST r "/api/v1/t/echo" in
            check_status "empty body needs no content-type" 200 empty;
            Lwt.return_unit) );
    ( "cross-site requests are 403",
      `Quick,
      fun () ->
        with_server (fun r ->
            let post headers =
              call ~headers:(headers @ json_ct)
                ~body:(Cohttp_lwt.Body.of_string "{}")
                `POST r "/api/v1/t/echo"
            in
            let* res = post [ ("origin", "https://evil.example") ] in
            check_error "foreign origin" 403 "CSRF" res;
            let* res = post [ ("origin", "http://127.0.0.1:1") ] in
            check_error "other port" 403 "CSRF" res;
            let* res = post [ ("origin", "null") ] in
            check_error "null origin" 403 "CSRF" res;
            let* res = post [ ("sec-fetch-site", "cross-site") ] in
            check_error "sec-fetch-site" 403 "CSRF" res;
            let* ok =
              post
                [
                  ("origin", Printf.sprintf "http://127.0.0.1:%d" r.port);
                  ("sec-fetch-site", "same-origin");
                ]
            in
            check_status "same origin" 200 ok;
            let* ok = post [] in
            check_status "no origin (non-browser client)" 200 ok;
            let* ok =
              call
                ~headers:[ ("origin", "https://evil.example") ]
                `GET r "/api/v1/t/items/a"
            in
            check_status "GET is not checked" 200 ok;
            Lwt.return_unit) );
  ]

(* A config whose only auth method is a service token ("tok", role audit). *)
let token_config () =
  C.Console_config.of_json
    (`Assoc
       [
         ("listen", `String "127.0.0.1:0");
         ("state_dir", `String (temp_dir "st"));
         ( "auth",
           `Assoc
             [
               ( "tokens",
                 `List
                   [
                     `Assoc
                       [
                         ("name", `String "ci");
                         ("sha256", `String (Haltsql.sha256_hex "tok"));
                         ("role", `String "audit");
                       ];
                   ] );
             ] );
       ])

let origin_tests =
  let post r headers =
    call ~headers:(headers @ json_ct)
      ~body:(Cohttp_lwt.Body.of_string "{}")
      `POST r "/api/v1/t/echo"
  in
  [
    ( "public_url and allowed_origins replace the Host comparison",
      `Quick,
      fun () ->
        let cfg =
          config
            ~extra:
              [
                ("public_url", `String "https://Console.Example.com/");
                ("allowed_origins", `List [ `String "http://localhost:5173" ]);
              ]
            ()
        in
        Alcotest.(check int) "two origins" 2 (List.length cfg.allowed_origins);
        with_server ~cfg (fun r ->
            let* ok = post r [ ("origin", "https://console.example.com") ] in
            check_status "public_url origin" 200 ok;
            let* ok = post r [ ("origin", "https://console.example.com:443") ] in
            check_status "explicit default port" 200 ok;
            let* ok = post r [ ("origin", "http://localhost:5173") ] in
            check_status "allowed_origins entry" 200 ok;
            let* res =
              post r [ ("origin", Printf.sprintf "http://127.0.0.1:%d" r.port) ]
            in
            check_error "Host is not used" 403 "CSRF" res;
            let* res = post r [ ("origin", "http://console.example.com") ] in
            check_error "other scheme" 403 "CSRF" res;
            let* res = post r [ ("origin", "https://console.example.com:8443") ] in
            check_error "other port" 403 "CSRF" res;
            let* res = post r [ ("origin", "null") ] in
            check_error "null" 403 "CSRF" res;
            let* ok = post r [] in
            check_status "no Origin" 200 ok;
            let* res =
              post r
                [
                  ("origin", "https://console.example.com");
                  ("sec-fetch-site", "cross-site");
                ]
            in
            check_error "sec-fetch-site still checked" 403 "CSRF" res;
            Lwt.return_unit) );
    ( "public_url and allowed_origins are validated",
      `Quick,
      fun () ->
        let bad extra =
          match config ~extra () with
          | _ -> Alcotest.failf "accepted %s" (str (`Assoc extra))
          | exception C.Console_config.Invalid _ -> ()
        in
        bad [ ("public_url", `String "https://console.example.com/app") ];
        bad [ ("public_url", `String "console.example.com") ];
        bad [ ("public_url", `String "ftp://console.example.com") ];
        bad [ ("allowed_origins", `List [ `String "https://a.test?x=1" ]) ];
        bad [ ("allowed_origins", `String "https://a.test") ] );
    ( "dev mode refuses non-loopback Host headers (DNS rebinding)",
      `Quick,
      fun () ->
        with_server (fun r ->
            let get host = call ~headers:[ ("host", host) ] `GET r "/api/v1/t/items/a" in
            let* res = get "evil.example" in
            check_error "evil host GET" 403 "HOST_NOT_ALLOWED" res;
            let* res = get (Printf.sprintf "evil.example:%d" r.port) in
            check_error "evil host with port" 403 "HOST_NOT_ALLOWED" res;
            let* res = get "127.0.0.1.evil.example" in
            check_error "loopback-looking name" 403 "HOST_NOT_ALLOWED" res;
            let* res = get "10.0.0.1:8090" in
            check_error "private ip" 403 "HOST_NOT_ALLOWED" res;
            let* res =
              call
                ~headers:(("host", "evil.example") :: json_ct)
                ~body:(Cohttp_lwt.Body.of_string "{}")
                `POST r "/api/v1/t/echo"
            in
            check_error "evil host POST" 403 "HOST_NOT_ALLOWED" res;
            let* ok = get "localhost:1234" in
            check_status "localhost" 200 ok;
            let* ok = get "LOCALHOST" in
            check_status "localhost, no port" 200 ok;
            let* ok = get "127.9.9.9:80" in
            check_status "127/8" 200 ok;
            let* ok = get "[::1]:8090" in
            check_status "[::1]" 200 ok;
            let* h = call ~headers:[ ("host", "evil.example") ] `GET r "/healthz" in
            check_status "probes are not /api" 200 h;
            Lwt.return_unit) );
    ( "the Host check is dev mode only",
      `Quick,
      fun () ->
        with_server ~cfg:(token_config ()) (fun r ->
            let* res =
              call
                ~headers:
                  [ ("host", "console.example.com"); ("authorization", "Bearer tok") ]
                `GET r "/api/v1/t/items/a"
            in
            check_status "any Host" 200 res;
            Lwt.return_unit) );
  ]

(* ---- auth before routing, params ---- *)

let routing_tests =
  [
    ( "unauthenticated callers get 401 for unknown endpoints",
      `Quick,
      fun () ->
        with_server ~cfg:(token_config ()) (fun r ->
            let* res = call `GET r "/api/v1/does-not-exist" in
            check_error "unknown" 401 "UNAUTHENTICATED" res;
            let* res = call `DELETE r "/api/v1/t/items/a" in
            check_error "wrong method" 401 "UNAUTHENTICATED" res;
            let* res = call `GET r "/api/v1/t/items/a" in
            check_error "known" 401 "UNAUTHENTICATED" res;
            let auth = [ ("authorization", "Bearer tok") ] in
            let* res = call ~headers:auth `GET r "/api/v1/does-not-exist" in
            check_error "authenticated unknown" 404 "NOT_FOUND" res;
            let* res = call ~headers:auth `DELETE r "/api/v1/t/items/a" in
            check_error "authenticated wrong method" 405 "METHOD_NOT_ALLOWED" res;
            let* h = call `GET r "/healthz" in
            check_status "healthz needs no auth" 200 h;
            let* rd = call `GET r "/readyz" in
            check_status "readyz needs no auth" 200 rd;
            Lwt.return_unit) );
    ( "encoded separators in params are 400",
      `Quick,
      fun () ->
        with_server (fun r ->
            let* ok = call `GET r "/api/v1/t/items/CASE-1" in
            check_status "plain" 200 ok;
            Alcotest.(check string) "value" "\"CASE-1\"" (str (snd ok));
            let* res = call `GET r "/api/v1/t/items/a%2Fb" in
            check_error "%2F" 400 "BAD_REQUEST" res;
            let* res = call `GET r "/api/v1/t/items/a%5Cb" in
            check_error "%5C" 400 "BAD_REQUEST" res;
            let* res = call `GET r "/api/v1/t/items/a%00b" in
            check_error "%00" 400 "BAD_REQUEST" res;
            (* %2E%2E is unreserved, so the URI layer turns it into ".." and removes the
               dot segment before routing (404); either way no handler sees "..". *)
            let* code, _ = call `GET r "/api/v1/t/items/%2E%2E" in
            Alcotest.(check bool) "dot-dot refused" true (code = 400 || code = 404);
            Lwt.return_unit) );
  ]

(* ---- timeouts and in-flight cap ---- *)

let limit_tests =
  [
    ( "slow handler times out",
      `Quick,
      fun () ->
        with_server ~request_timeout:0.1 (fun r ->
            let* res = call `GET r "/api/v1/t/slow" in
            check_error "timeout" 503 "TIMEOUT" res;
            Lwt.return_unit) );
    ( "requests over the in-flight cap are 503",
      `Quick,
      fun () ->
        with_server ~max_in_flight:1 (fun r ->
            let slow = call `GET r "/api/v1/t/slow" in
            let* () = Lwt_unix.sleep 0.1 in
            let* res = call `GET r "/api/v1/t/items/a" in
            check_error "overloaded" 503 "OVERLOADED" res;
            let* rd = call `GET r "/readyz" in
            check_status "probes are exempt" 200 rd;
            let* s = slow in
            check_status "slow finished" 200 s;
            let* ok = call `GET r "/api/v1/t/items/a" in
            check_status "after" 200 ok;
            Lwt.return_unit) );
  ]

(* ---- background supervision and readiness ---- *)

let loop_field name field j =
  match member "loops" j with
  | `List l -> (
      match List.find_opt (fun x -> member "name" x = `String name) l with
      | Some x -> member field x
      | None -> `Null)
  | _ -> `Null

let background_tests =
  [
    ( "a crashing loop is restarted and /readyz goes not_ready",
      `Quick,
      fun () ->
        let runs = ref 0 in
        let flaky _ =
          incr runs;
          if !runs <= 2 then failwith "boom" else fst (Lwt.wait ())
        in
        let stub _ = Lwt.return_unit in
        with_server ~initial_backoff:0.2
          ~background:[ ("flaky", flaky); ("stub", stub) ]
          (fun r ->
            let* code, j = call `GET r "/readyz" in
            Alcotest.(check int) "not ready while crashed" 503 code;
            Alcotest.(check string) "status" "\"not_ready\"" (str (member "status" j));
            Alcotest.(check string)
              "flaky crashed" "\"crashed\""
              (str (loop_field "flaky" "state" j));
            Alcotest.(check bool)
              "error recorded" true
              (match loop_field "flaky" "last_error" j with
              | `String s -> contains s "boom"
              | _ -> false);
            Alcotest.(check string)
              "stub done, not crashed" "\"done\""
              (str (loop_field "stub" "state" j));
            let* () = Lwt_unix.sleep 1.2 in
            let* code, j = call `GET r "/readyz" in
            Alcotest.(check int) "ready after restart" 200 code;
            Alcotest.(check string)
              "flaky running" "\"running\""
              (str (loop_field "flaky" "state" j));
            Alcotest.(check string) "restarts" "2" (str (loop_field "flaky" "restarts" j));
            Alcotest.(check int) "runs" 3 !runs;
            Alcotest.(check string)
              "state_dir writable" "true"
              (str (member "state_dir_writable" j));
            Lwt.return_unit) );
    ( "shutdown cancels loops and drains in-flight requests",
      `Quick,
      fun () ->
        Lwt_main.run
          (let cancelled = ref false in
           let forever _ =
             Lwt.catch
               (fun () -> fst (Lwt.task ()))
               (function
                 | Lwt.Canceled ->
                     cancelled := true;
                     Lwt.return_unit
                 | e -> Lwt.fail e)
           in
           let* r, serving =
             start_server ~background:[ ("forever", forever) ] (config ())
           in
           let slow = call `GET r "/api/v1/t/slow" in
           let* () = Lwt_unix.sleep 0.1 in
           Helpers.stop r;
           let t0 = Unix.gettimeofday () in
           let* () = serving in
           let waited = Unix.gettimeofday () -. t0 in
           Alcotest.(check bool) "loop cancelled" true !cancelled;
           Alcotest.(check bool) "waited for the request" true (waited >= 0.2);
           let* s = slow in
           check_status "in-flight request completed" 200 s;
           Lwt.return_unit) );
  ]

(* ---- static frontend ---- *)

let write_file path s = Out_channel.with_open_bin path (fun oc -> output_string oc s)

let static_tests =
  [
    ( "missing assets 404, SPA paths get index.html, no escaping symlinks",
      `Quick,
      fun () ->
        let dir = temp_dir "frontend" in
        write_file (Filename.concat dir "index.html") "<html>spa</html>";
        write_file (Filename.concat dir "app.js") "console.log(1)";
        let outside = temp_dir "outside" in
        write_file (Filename.concat outside "secret.txt") "secret";
        Unix.symlink
          (Filename.concat outside "secret.txt")
          (Filename.concat dir "leak.txt");
        Unix.symlink outside (Filename.concat dir "out");
        Unix.symlink (Filename.concat dir "app.js") (Filename.concat dir "alias.js");
        let cfg = config ~extra:[ ("frontend_dir", `String dir) ] () in
        with_server ~cfg (fun r ->
            let* res = call `GET r "/x.js" in
            check_status "missing asset" 404 res;
            let* res = call `GET r "/assets/missing.css" in
            check_status "missing nested asset" 404 res;
            let* code, body = call `GET r "/some/page" in
            Alcotest.(check int) "spa path" 200 code;
            Alcotest.(check string) "index.html" "\"<html>spa</html>\"" (str body);
            let* code, body = call `GET r "/" in
            Alcotest.(check int) "root" 200 code;
            Alcotest.(check string) "root index" "\"<html>spa</html>\"" (str body);
            let* code, body = call `GET r "/app.js" in
            Alcotest.(check int) "asset" 200 code;
            Alcotest.(check string) "asset body" "\"console.log(1)\"" (str body);
            let* res = call `GET r "/alias.js" in
            check_status "symlink inside" 200 res;
            let* res = call `GET r "/leak.txt" in
            check_status "symlink outside" 404 res;
            let* res = call `GET r "/out/secret.txt" in
            check_status "symlinked dir outside" 404 res;
            Lwt.return_unit) );
    ( "dotfiles and dot-directories are not served",
      `Quick,
      fun () ->
        let dir = temp_dir "frontend" in
        write_file (Filename.concat dir "index.html") "<html>spa</html>";
        write_file (Filename.concat dir ".env") "SECRET=1";
        Unix.mkdir (Filename.concat dir ".git") 0o700;
        write_file (Filename.concat dir ".git/config") "[core]";
        Unix.mkdir (Filename.concat dir "assets") 0o700;
        write_file (Filename.concat dir "assets/.hidden.js") "x";
        write_file (Filename.concat dir "assets/app.js") "app";
        let cfg = config ~extra:[ ("frontend_dir", `String dir) ] () in
        with_server ~cfg (fun r ->
            let* res = call `GET r "/.env" in
            check_status "dotfile" 404 res;
            let* res = call `GET r "/.git/config" in
            check_status "dot-directory" 404 res;
            let* res = call `GET r "/.git" in
            check_status "dot-directory, extensionless" 404 res;
            let* res = call `GET r "/assets/.hidden.js" in
            check_status "nested dotfile" 404 res;
            let* code, body = call `GET r "/assets/app.js" in
            Alcotest.(check int) "nested asset" 200 code;
            Alcotest.(check string) "nested body" "\"app\"" (str body);
            Lwt.return_unit) );
    ( "the file set is built once; unknown paths cache nothing",
      `Quick,
      fun () ->
        let dir = temp_dir "frontend" in
        write_file (Filename.concat dir "index.html") "<html>spa</html>";
        write_file (Filename.concat dir "app.js") "1";
        Unix.mkdir (Filename.concat dir "loop") 0o700;
        (* a symlink back to the root must not loop forever *)
        Unix.symlink dir (Filename.concat dir "loop/up");
        let fe = C.Console_server.frontend_of_dir dir in
        let files () = Hashtbl.length fe.files in
        let before = files () in
        Alcotest.(check bool) "index and app.js listed" true (before >= 2);
        Lwt_main.run
          (let rec go i =
             if i = 0 then Lwt.return_unit
             else
               let* _ = C.Console_server.static fe (Printf.sprintf "/nope/%d.js" i) in
               let* _ = C.Console_server.static fe (Printf.sprintf "/page/%d" i) in
               go (i - 1)
           in
           go 500);
        Alcotest.(check int) "no entries added" before (files ());
        write_file (Filename.concat dir "late.js") "late";
        let code =
          Lwt_main.run
            (let* resp, body = C.Console_server.static fe "/late.js" in
             let* _ = Cohttp_lwt.Body.drain_body body in
             Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status resp)))
        in
        Alcotest.(check int) "files added later are not served" 404 code );
    ( "no frontend directory",
      `Quick,
      fun () ->
        let fe = C.Console_server.frontend_of_dir "/nonexistent/haltsql-frontend" in
        Alcotest.(check int) "empty" 0 (Hashtbl.length fe.files) );
  ]

(* ---- dev-mode listen validation ---- *)

let dev_listen_tests =
  [
    ( "--listen alone cannot move dev mode off loopback",
      `Quick,
      fun () ->
        let cfg = config () in
        (match C.Console_server.apply_overrides ~listen:"0.0.0.0:8090" cfg with
        | Ok _ -> Alcotest.fail "--listen 0.0.0.0 accepted with auth.dev"
        | Error m ->
            Alcotest.(check bool) "mentions --listen" true (contains m "--listen"));
        (match C.Console_server.apply_overrides ~listen:"[::]:8090" cfg with
        | Ok _ -> Alcotest.fail "--listen [::] accepted with auth.dev"
        | Error _ -> ());
        (match C.Console_server.apply_overrides ~listen:"127.0.0.1:9000" cfg with
        | Ok c -> Alcotest.(check string) "loopback ok" "127.0.0.1:9000" c.listen
        | Error m -> Alcotest.failf "loopback refused: %s" m);
        (match
           C.Console_server.apply_overrides ~listen:"0.0.0.0:8090" (token_config ())
         with
        | Ok _ -> ()
        | Error m -> Alcotest.failf "non-dev config refused: %s" m);
        match
          C.Console_server.apply_overrides ~listen:"0.0.0.0:8090" ~dev:C.Rbac.Admin
            (token_config ())
        with
        | Ok _ -> Alcotest.fail "--dev with 0.0.0.0 accepted"
        | Error _ -> () );
    ( "serve refuses a dev config on a non-loopback address",
      `Quick,
      fun () ->
        let cfg = { (config ()) with C.Console_config.listen = "0.0.0.0:0" } in
        let store = C.Store.create cfg.state_dir in
        let ctx = C.Ctx.create ~config:cfg ~store ~index:(C.Index.create ()) in
        match Lwt_main.run (C.Console_server.serve ~background:[] ctx) with
        | _ -> Alcotest.fail "served a dev config on 0.0.0.0"
        | exception Failure m ->
            Alcotest.(check bool) "refusing" true (contains m "refusing to serve") );
  ]

(* ---- connection limits ---- *)

let connect_raw port =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let* () = Lwt_unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, port)) in
  Lwt.return fd

(* Reads until EOF (or a reset); [Some seconds] it took, or [None] after [within]. *)
let closed_within fd within =
  let buf = Bytes.create 4096 in
  let t0 = Unix.gettimeofday () in
  let rec drain () =
    let* n =
      Lwt.catch
        (fun () -> Lwt_unix.read fd buf 0 4096)
        (function Unix.Unix_error _ -> Lwt.return 0 | e -> Lwt.fail e)
    in
    if n = 0 then Lwt.return_some (Unix.gettimeofday () -. t0) else drain ()
  in
  Lwt.pick
    [
      drain ();
      (let* () = Lwt_unix.sleep within in
       Lwt.return_none);
    ]

let send_raw fd s =
  let* _ = Lwt_unix.write_string fd s 0 (String.length s) in
  Lwt.return_unit

let connection_tests =
  [
    ( "idle and slow-header connections are closed",
      `Quick,
      fun () ->
        with_server ~idle_timeout:0.3 (fun r ->
            let* idle = connect_raw r.port in
            let* slow = connect_raw r.port in
            let* () = send_raw slow "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n" in
            let* t_idle = closed_within idle 3. in
            let* t_slow = closed_within slow 3. in
            Alcotest.(check bool) "idle closed" true (Option.is_some t_idle);
            Alcotest.(check bool) "slow headers closed" true (Option.is_some t_slow);
            let* () = Lwt_unix.close idle in
            let* () = Lwt_unix.close slow in
            (* a request slower than the idle timeout is not cut by it *)
            let* res = call `GET r "/api/v1/t/slow" in
            check_status "slow handler" 200 res;
            Lwt.return_unit) );
    ( "keep-alive connections are closed after the idle timeout",
      `Quick,
      fun () ->
        with_server ~idle_timeout:0.3 (fun r ->
            let* fd = connect_raw r.port in
            let* () = send_raw fd "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" in
            let* t = closed_within fd 3. in
            Alcotest.(check bool) "closed after the response" true (Option.is_some t);
            Lwt_unix.close fd) );
    ( "connections over the cap are closed",
      `Quick,
      fun () ->
        with_server ~max_connections:1 ~idle_timeout:5. (fun r ->
            let* first = connect_raw r.port in
            let* () = Lwt_unix.sleep 0.1 in
            let* second = connect_raw r.port in
            let* t = closed_within second 2. in
            Alcotest.(check bool) "second closed" true (Option.is_some t);
            let* () = Lwt_unix.close second in
            let* () = Lwt_unix.close first in
            let* () = Lwt_unix.sleep 0.1 in
            let* ok = call `GET r "/readyz" in
            check_status "after the first closed" 200 ok;
            Lwt.return_unit) );
  ]

let () =
  Alcotest.run "console-server"
    [
      ("body", body_tests);
      ("csrf", csrf_tests);
      ("origins", origin_tests);
      ("routing", routing_tests);
      ("limits", limit_tests);
      ("background", background_tests);
      ("static", static_tests);
      ("dev-listen", dev_listen_tests);
      ("connections", connection_tests);
    ]
