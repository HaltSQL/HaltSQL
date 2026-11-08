(** Upstream connections; see upstream.mli. *)

open Lwt.Syntax
open Proxy_config

exception Upstream_error of string

let fail fmt = Printf.ksprintf (fun s -> Lwt.fail (Upstream_error s)) fmt
let max_upstream_auth_message = 65536

let md5_password ~user ~password ~salt =
  "md5" ^ Sec.md5_hex (Sec.md5_hex (password ^ user) ^ salt)

let tls_config (u : upstream) =
  let authenticator =
    match u.tls_mode with
    | Tls_verify_full ->
        X509.Authenticator.chain_of_trust
          ~time:(fun () -> Some (Ptime_clock.now ()))
          u.tls_ca
    | Tls_require | Tls_disable -> fun ?ip:_ ~host:_ _ -> Ok None
  in
  let peer =
    match Ipaddr.of_string u.host with
    | Ok ip -> Ok (Some ip, None)
    | Error _ -> (
        match Result.bind (Domain_name.of_string u.host) Domain_name.host with
        | Ok h -> Ok (None, Some h)
        | Error _ -> (
            match u.tls_mode with
            | Tls_verify_full ->
                (* without a name or an IP the authenticator checks the chain only:
                   fail closed *)
                Error
                  (Printf.sprintf
                     "upstream host %s cannot be verified (neither an IP address nor a \
                      valid DNS host name); tls.mode verify-full needs one"
                     u.host)
            | Tls_require | Tls_disable -> Ok (None, None)))
  in
  match peer with
  | Error m -> Error m
  | Ok (ip, peer_name) -> (
      match Tls.Config.client ~authenticator ?peer_name ?ip () with
      | Ok c -> Ok (c, peer_name)
      | Error (`Msg m) -> Error m)

let tcp_connect (u : upstream) =
  let* addrs =
    Lwt_unix.getaddrinfo u.host (string_of_int u.port)
      [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
  in
  (* like libpq, try every resolved address in order (e.g. ::1 then 127.0.0.1) *)
  let rec attempt last = function
    | [] -> (
        match last with
        | Some m -> fail "cannot connect to upstream %s:%d: %s" u.host u.port m
        | None -> fail "cannot resolve upstream host %s" u.host)
    | ai :: rest -> (
        let fd = Lwt_unix.socket ai.Unix.ai_family Unix.SOCK_STREAM 0 in
        let* r =
          Lwt.catch
            (fun () ->
              let* () =
                Lwt_unix.with_timeout u.connect_timeout (fun () ->
                    Lwt_unix.connect fd ai.Unix.ai_addr)
              in
              (try Lwt_unix.setsockopt fd Unix.TCP_NODELAY true with _ -> ());
              Lwt.return (Ok fd))
            (fun e ->
              let* () =
                Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
              in
              match e with
              | Lwt_unix.Timeout -> Lwt.return (Error "timed out")
              | Unix.Unix_error (err, _, _) -> Lwt.return (Error (Unix.error_message err))
              | e -> Lwt.fail e)
        in
        match r with Ok fd -> Lwt.return fd | Error m -> attempt (Some m) rest)
  in
  attempt None addrs

(* Negotiate TLS per the configured mode; returns the transport. *)
let negotiate (u : upstream) fd =
  match u.tls_mode with
  | Tls_disable -> Lwt.return (Io.of_fd fd)
  | Tls_require | Tls_verify_full -> (
      let plain = Io.of_fd fd in
      let* () = Io.write plain Wire.encode_ssl_request in
      let* answer = Io.read_byte plain in
      match answer with
      | 'S' -> (
          if Io.buffered plain > 0 then
            fail "upstream sent unencrypted data after accepting TLS (possible MITM)"
          else
            match tls_config u with
            | Error m -> fail "upstream TLS configuration: %s" m
            | Ok (cfg, host) ->
                Lwt.catch
                  (fun () ->
                    let* t = Tls_lwt.Unix.client_of_fd cfg ?host fd in
                    Lwt.return (Io.of_tls fd t))
                  (fun e ->
                    fail "upstream TLS handshake failed: %s"
                      (match e with
                      | Tls_lwt.Tls_failure f -> Tls.Engine.string_of_failure f
                      | Tls_lwt.Tls_alert a -> Tls.Packet.alert_type_to_string a
                      | e -> Printexc.to_string e)))
      | 'N' ->
          fail "upstream server does not support TLS but upstream.tls.mode requires it"
      | _ -> fail "unexpected response to SSLRequest from upstream")

let error_message payload =
  match Wire.decode_fields payload with
  | fields ->
      let get k = Option.value ~default:"" (List.assoc_opt k fields) in
      Printf.sprintf "%s %s: %s" (get 'S') (get 'C') (get 'M')
  | exception Wire.Malformed _ -> "malformed error response"

let authenticate (u : upstream) io =
  let password () =
    match u.password with
    | Some p -> Lwt.return p
    | None -> fail "upstream requested a password but upstream.password is not configured"
  in
  let read () = Io.read_message io ~max:max_upstream_auth_message in
  let rec loop ~scram =
    let* tag, payload = read () in
    match tag with
    | 'E' -> fail "upstream rejected the connection: %s" (error_message payload)
    | 'R' -> (
        match (Wire.decode_auth payload, scram) with
        | Wire.Auth_ok, None -> Lwt.return_unit
        | Wire.Auth_ok, Some _ -> fail "upstream skipped SCRAM server verification"
        | Wire.Auth_cleartext, None ->
            if Io.tls io = None then
              fail
                "upstream requested a cleartext password over an unencrypted connection"
            else
              let* p = password () in
              let* () = Io.write io (Wire.password_message p) in
              loop ~scram:None
        | Wire.Auth_md5 salt, None ->
            let* p = password () in
            let* () =
              Io.write io
                (Wire.password_message (md5_password ~user:u.user ~password:p ~salt))
            in
            loop ~scram:None
        | Wire.Auth_sasl mechs, None ->
            if not (List.mem Scram.mechanism mechs) then
              fail "upstream offers no supported SASL mechanism (%s)"
                (String.concat ", " mechs)
            else
              let* p = password () in
              let st, first =
                Scram.Client.first ~nonce:(Sec.b64_encode (Sec.random 18)) ()
              in
              let* () =
                Io.write io (Wire.sasl_initial_response ~mechanism:Scram.mechanism first)
              in
              loop ~scram:(Some (`First (st, p)))
        | Wire.Auth_sasl_continue data, Some (`First (st, p)) -> (
            match Scram.Client.final st ~password:p data with
            | Error m -> fail "%s" m
            | Ok (st, final) ->
                let* () = Io.write io (Wire.sasl_response final) in
                loop ~scram:(Some (`Final st)))
        | Wire.Auth_sasl_final data, Some (`Final st) -> (
            match Scram.Client.verify_server st data with
            | Error m -> fail "%s" m
            | Ok () -> loop ~scram:None)
        | Wire.Auth_other n, _ -> fail "unsupported upstream authentication method %d" n
        | _ -> fail "unexpected authentication message from upstream")
    | 'v' -> fail "upstream requested protocol negotiation"
    | c -> fail "unexpected message %C from upstream during authentication" c
  in
  loop ~scram:None

let wrap_errors f =
  Lwt.catch f (function
    | Upstream_error _ as e -> Lwt.fail e
    | Io.Closed -> fail "upstream closed the connection"
    | Io.Too_large _ -> fail "upstream sent an oversized message during startup"
    | Wire.Malformed m -> fail "malformed message from upstream: %s" m
    | Unix.Unix_error (e, _, _) -> fail "upstream I/O error: %s" (Unix.error_message e)
    | Lwt_unix.Timeout -> fail "upstream timed out"
    | e -> fail "upstream error: %s" (Printexc.to_string e))

let connect (u : upstream) ~application_name =
  wrap_errors (fun () ->
      let* fd = tcp_connect u in
      (* The SSLRequest answer and the TLS handshake are bounded too: a peer that
         accepts the TCP connection and then stalls must not pin the session. *)
      let* io =
        Lwt.catch
          (fun () -> Lwt_unix.with_timeout u.connect_timeout (fun () -> negotiate u fd))
          (fun e ->
            let* () =
              Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
            in
            Lwt.fail e)
      in
      Lwt.catch
        (fun () ->
          let params =
            [ ("user", u.user); ("database", u.database); ("client_encoding", "UTF8") ]
            @
            match application_name with
            | Some a -> [ ("application_name", a) ]
            | None -> []
          in
          let* () = Io.write io (Wire.encode_startup params) in
          let* () =
            Lwt_unix.with_timeout (u.connect_timeout *. 3.) (fun () -> authenticate u io)
          in
          Lwt.return io)
        (fun e ->
          let* () = Io.close io in
          Lwt.fail e))

let send_cancel (u : upstream) ~pid ~key =
  Lwt.catch
    (fun () ->
      let* fd = tcp_connect u in
      let* io =
        Lwt.catch
          (fun () -> Lwt_unix.with_timeout u.connect_timeout (fun () -> negotiate u fd))
          (fun e ->
            let* () =
              Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
            in
            Lwt.fail e)
      in
      Lwt.finalize
        (fun () ->
          let* () =
            Lwt_unix.with_timeout u.connect_timeout (fun () ->
                Io.write io (Wire.encode_cancel ~pid ~key))
          in
          (* the server closes the connection after processing the request *)
          Lwt.catch
            (fun () ->
              Lwt_unix.with_timeout 2. (fun () ->
                  let* _ = Io.read_byte io in
                  Lwt.return_unit))
            (fun _ -> Lwt.return_unit))
        (fun () -> Io.close io))
    (fun e ->
      Plog.log Plog.Warn "cancel request to upstream failed"
        [
          ( "error",
            `String
              (match e with
              | Upstream_error m -> m
              | Lwt_unix.Timeout -> "timed out"
              | Unix.Unix_error (err, _, _) -> Unix.error_message err
              | e -> Printexc.to_string e) );
        ];
      Lwt.return_unit)
