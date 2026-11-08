(** Minimal PostgreSQL v3 protocol client (see pg_wire.mli).

    Message framing: every backend message is [type:char][len:int32 incl. itself][body].
    The startup and SSLRequest packets have no type byte. *)

open Lwt.Syntax

exception Error of string

let err fmt = Printf.ksprintf (fun s -> raise (Error s)) fmt
let fail fmt = Printf.ksprintf (fun s -> Lwt.fail (Error s)) fmt

type conn = {
  ic : Lwt_io.input_channel;
  oc : Lwt_io.output_channel;
  mutable params : (string * string) list;
  is_tls : bool;
  mutable closed : bool;
  close_fn : unit -> unit Lwt.t;
}

type row = string option array

let max_message = 64 * 1024 * 1024
let rng_initialized = lazy (Mirage_crypto_rng_unix.use_default ())
let server_parameter c k = List.assoc_opt k c.params
let tls c = c.is_tls

(* ------------------------------------------------------------ encoding *)

let add_i32 b n = Buffer.add_int32_be b (Int32.of_int n)
let add_i16 b n = Buffer.add_uint16_be b n

let add_cstr b s =
  if String.contains s '\000' then err "NUL byte in a protocol string";
  Buffer.add_string b s;
  Buffer.add_char b '\000'

let frame typ body =
  let b = Buffer.create (5 + String.length body) in
  Buffer.add_char b typ;
  add_i32 b (4 + String.length body);
  Buffer.add_string b body;
  Buffer.contents b

let build f =
  let b = Buffer.create 64 in
  f b;
  Buffer.contents b

(* ------------------------------------------------------------ decoding *)

type cursor = { s : string; mutable pos : int }

let need c n =
  if c.pos + n > String.length c.s then err "protocol error: truncated message"

let get_i32 c =
  need c 4;
  let v = Int32.to_int (String.get_int32_be c.s c.pos) in
  c.pos <- c.pos + 4;
  v

let get_i16 c =
  need c 2;
  let v = String.get_uint16_be c.s c.pos in
  c.pos <- c.pos + 2;
  v

let get_bytes c n =
  if n < 0 then err "protocol error: negative length";
  need c n;
  let v = String.sub c.s c.pos n in
  c.pos <- c.pos + n;
  v

let get_cstr c =
  match String.index_from_opt c.s c.pos '\000' with
  | None -> err "protocol error: unterminated string"
  | Some j ->
      let v = String.sub c.s c.pos (j - c.pos) in
      c.pos <- j + 1;
      v

let rest c = get_bytes c (String.length c.s - c.pos)

(* ErrorResponse / NoticeResponse fields -> "ERROR 42P01: relation ... does not exist". *)
let error_of_body body =
  let c = { s = body; pos = 0 } in
  let rec fields acc =
    if c.pos >= String.length body then acc
    else
      match body.[c.pos] with
      | '\000' -> acc
      | t ->
          c.pos <- c.pos + 1;
          let v = get_cstr c in
          fields ((t, v) :: acc)
  in
  let f = try fields [] with Error _ -> [] in
  let get k = List.assoc_opt k f in
  let sev =
    match (get 'V', get 'S') with Some s, _ | None, Some s -> s | None, None -> "ERROR"
  in
  let code = Option.value (get 'C') ~default:"XX000" in
  let msg = Option.value (get 'M') ~default:"(no message)" in
  Printf.sprintf "%s %s: %s" sev code msg

(* ------------------------------------------------------------ transport *)

let read_msg conn =
  Lwt.catch
    (fun () ->
      let* typ = Lwt_io.read_char conn.ic in
      let hdr = Bytes.create 4 in
      let* () = Lwt_io.read_into_exactly conn.ic hdr 0 4 in
      let len = Int32.to_int (Bytes.get_int32_be hdr 0) in
      if len < 4 || len > max_message then fail "protocol error: invalid message length"
      else
        let body = Bytes.create (len - 4) in
        let* () = Lwt_io.read_into_exactly conn.ic body 0 (len - 4) in
        Lwt.return (typ, Bytes.unsafe_to_string body))
    (function
      | End_of_file -> fail "server closed the connection unexpectedly"
      | Unix.Unix_error (e, _, _) -> fail "connection error: %s" (Unix.error_message e)
      | e -> Lwt.fail e)

let send conn s =
  Lwt.catch
    (fun () ->
      let* () = Lwt_io.write conn.oc s in
      Lwt_io.flush conn.oc)
    (function
      | Unix.Unix_error (e, _, _) -> fail "connection error: %s" (Unix.error_message e)
      | e -> Lwt.fail e)

let rec write_all fd buf off len =
  if len = 0 then Lwt.return_unit
  else
    let* n = Lwt_unix.write_string fd buf off len in
    write_all fd buf (off + n) (len - n)

let resolve (dsn : Pg_dsn.t) =
  if String.length dsn.host > 0 && dsn.host.[0] = '/' then
    Lwt.return
      [
        Unix.ADDR_UNIX (Filename.concat dsn.host (Printf.sprintf ".s.PGSQL.%d" dsn.port));
      ]
  else
    let* infos =
      Lwt_unix.getaddrinfo dsn.host (string_of_int dsn.port)
        [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
    in
    match infos with
    | [] -> fail "could not resolve host %S" dsn.host
    | l -> Lwt.return (List.map (fun (ai : Unix.addr_info) -> ai.ai_addr) l)

let open_socket dsn =
  let* addrs = resolve dsn in
  let rec try_ last = function
    | [] -> fail "could not connect to %s:%d: %s" dsn.Pg_dsn.host dsn.port last
    | addr :: rest ->
        let domain = Unix.domain_of_sockaddr addr in
        let fd = Lwt_unix.socket domain Unix.SOCK_STREAM 0 in
        Lwt.bind
          (Lwt.catch
             (fun () ->
               let* () = Lwt_unix.connect fd addr in
               Lwt.return (Ok fd))
             (fun e ->
               let* () =
                 Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
               in
               match e with
               | Unix.Unix_error (ue, _, _) ->
                   Lwt.return (Result.Error (Unix.error_message ue))
               | e -> Lwt.fail e))
          (function Ok fd -> Lwt.return fd | Result.Error m -> try_ m rest)
  in
  try_ "no addresses" addrs

let authenticator (dsn : Pg_dsn.t) : X509.Authenticator.t =
  match dsn.sslmode with
  | Disable | Prefer | Require -> fun ?ip:_ ~host:_ _ -> Ok None
  | Verify_ca | Verify_full ->
      let base =
        match dsn.sslrootcert with
        | Some file -> (
            let pem =
              try In_channel.with_open_bin file In_channel.input_all
              with Sys_error _ -> err "cannot read sslrootcert file %s" file
            in
            match X509.Certificate.decode_pem_multiple pem with
            | Ok (_ :: _ as cas) ->
                X509.Authenticator.chain_of_trust
                  ~time:(fun () -> Some (Ptime_clock.now ()))
                  cas
            | Ok [] -> err "sslrootcert file %s contains no certificates" file
            | Result.Error (`Msg m) -> err "invalid sslrootcert file %s: %s" file m)
        | None -> (
            match Ca_certs.authenticator () with
            | Ok a -> a
            | Result.Error (`Msg m) -> err "cannot load the system CA certificates: %s" m)
      in
      if dsn.sslmode = Verify_ca then fun ?ip:_ ~host:_ certs -> base ~host:None certs
      else base

let tls_upgrade (dsn : Pg_dsn.t) fd =
  let authenticator = authenticator dsn in
  let ip = Result.to_option (Ipaddr.of_string dsn.host) in
  let peer_name =
    match ip with
    | Some _ -> None
    | None ->
        Result.to_option (Result.bind (Domain_name.of_string dsn.host) Domain_name.host)
  in
  let config =
    match Tls.Config.client ~authenticator ?peer_name ?ip () with
    | Ok c -> c
    | Result.Error (`Msg m) -> err "TLS configuration error: %s" m
  in
  Lwt.catch
    (fun () ->
      let* t = Tls_lwt.Unix.client_of_fd config ?host:peer_name fd in
      let ic, oc = Tls_lwt.of_t t in
      Lwt.return (ic, oc, fun () -> Tls_lwt.Unix.close t))
    (function
      | Error _ as e -> Lwt.fail e
      | e -> fail "TLS handshake with %s failed: %s" dsn.host (Printexc.to_string e))

(* SSLRequest negotiation; returns channels and whether TLS is on. *)
let negotiate (dsn : Pg_dsn.t) fd =
  let plain () =
    let ic = Lwt_io.of_fd ~mode:Lwt_io.input fd in
    let oc = Lwt_io.of_fd ~mode:Lwt_io.output fd in
    Lwt.return (ic, oc, (fun () -> Lwt_unix.close fd), false)
  in
  match dsn.sslmode with
  | Disable -> plain ()
  | mode -> (
      let req =
        build (fun b ->
            add_i32 b 8;
            add_i32 b 80877103)
      in
      let* () = write_all fd req 0 8 in
      let buf = Bytes.create 1 in
      let* n = Lwt_unix.read fd buf 0 1 in
      if n = 0 then fail "server closed the connection during TLS negotiation"
      else
        match Bytes.get buf 0 with
        | 'S' ->
            let* ic, oc, close = tls_upgrade dsn fd in
            Lwt.return (ic, oc, close, true)
        | 'N' when mode = Prefer -> plain ()
        | 'N' ->
            fail "server does not support TLS, but sslmode=%s requires it"
              (Pg_dsn.sslmode_to_string mode)
        | _ -> fail "protocol error during TLS negotiation")

(* ------------------------------------------------------------ authentication *)

let random_nonce () =
  Lazy.force rng_initialized;
  Base64.encode_string (Mirage_crypto_rng.generate 18)

let md5_hex s = Digestif.MD5.(to_hex (digest_string s))
let password_message pw = frame 'p' (build (fun b -> add_cstr b pw))

let authenticate conn (dsn : Pg_dsn.t) =
  let password () =
    match dsn.password with
    | Some p -> p
    | None -> err "the server requires a password; give it in the DSN or in PGPASSWORD"
  in
  (* SCRAM state: the server must prove knowledge of the password (SASLFinal) before
     AuthenticationOk, otherwise a man in the middle could skip it. *)
  let scram = ref `None in
  let rec loop () =
    let* typ, body = read_msg conn in
    let c = { s = body; pos = 0 } in
    match typ with
    | 'R' -> (
        match get_i32 c with
        | 0 -> (
            match !scram with
            | `Started _ | `Sent _ ->
                fail "server ended SCRAM authentication without proving the password"
            | `None | `Verified -> Lwt.return_unit)
        | 3 ->
            if not (conn.is_tls || Pg_dsn.is_loopback dsn.host) then
              fail
                "server requested a cleartext password over an unencrypted connection; \
                 refusing (use sslmode=require or stronger)"
            else
              let* () = send conn (password_message (password ())) in
              loop ()
        | 5 ->
            let salt = get_bytes c 4 in
            let pw = password () in
            let inner = md5_hex (pw ^ dsn.user) in
            let* () = send conn (password_message ("md5" ^ md5_hex (inner ^ salt))) in
            loop ()
        | 10 ->
            let rec mechs acc =
              match get_cstr c with "" -> List.rev acc | m -> mechs (m :: acc)
            in
            let ms = mechs [] in
            if not (List.mem "SCRAM-SHA-256" ms) then
              fail "server offers no supported SASL mechanism (%s)"
                (String.concat ", " ms)
            else begin
              ignore (password ());
              let nonce = random_nonce () in
              let cf = Scram.client_first ~user:"" ~nonce in
              scram := `Started (cf, nonce);
              let body =
                build (fun b ->
                    add_cstr b "SCRAM-SHA-256";
                    add_i32 b (String.length cf.message);
                    Buffer.add_string b cf.message)
              in
              let* () = send conn (frame 'p' body) in
              loop ()
            end
        | 11 -> (
            match !scram with
            | `Started (cf, nonce) -> (
                let server_first = rest c in
                match
                  Scram.client_final ~password:(password ()) ~client_first:cf
                    ~client_nonce:nonce ~server_first
                with
                | Error e -> fail "%s" e
                | Ok fin ->
                    scram := `Sent fin;
                    let* () = send conn (frame 'p' fin.final_message) in
                    loop ())
            | _ -> fail "protocol error: unexpected SASLContinue")
        | 12 -> (
            match !scram with
            | `Sent fin -> (
                match Scram.verify_server_final fin (rest c) with
                | Ok () ->
                    scram := `Verified;
                    loop ()
                | Error e -> fail "%s" e)
            | _ -> fail "protocol error: unexpected SASLFinal")
        | 2 -> fail "Kerberos authentication is not supported"
        | 7 | 8 -> fail "GSSAPI authentication is not supported"
        | 9 -> fail "SSPI authentication is not supported"
        | n -> fail "unsupported authentication request (code %d)" n)
    | 'E' -> fail "%s" (error_of_body body)
    | 'N' -> loop ()
    | _ -> fail "protocol error: unexpected message %C during authentication" typ
  in
  let rec ready () =
    let* typ, body = read_msg conn in
    match typ with
    | 'S' ->
        let c = { s = body; pos = 0 } in
        let k = get_cstr c in
        let v = get_cstr c in
        conn.params <- (k, v) :: List.remove_assoc k conn.params;
        ready ()
    | 'K' | 'N' -> ready ()
    | 'Z' -> Lwt.return_unit
    | 'E' -> fail "%s" (error_of_body body)
    | _ -> fail "protocol error: unexpected message %C after authentication" typ
  in
  let* () = loop () in
  ready ()

let startup_packet ~read_only (dsn : Pg_dsn.t) =
  let body =
    build (fun b ->
        add_i32 b 196608;
        add_cstr b "user";
        add_cstr b dsn.user;
        add_cstr b "database";
        add_cstr b dsn.dbname;
        add_cstr b "application_name";
        add_cstr b (Option.value dsn.application_name ~default:"haltsql");
        add_cstr b "client_encoding";
        add_cstr b "UTF8";
        if read_only then begin
          add_cstr b "default_transaction_read_only";
          add_cstr b "on"
        end;
        Buffer.add_char b '\000')
  in
  build (fun b ->
      add_i32 b (4 + String.length body);
      Buffer.add_string b body)

let close conn =
  if conn.closed then Lwt.return_unit
  else begin
    conn.closed <- true;
    let* () =
      Lwt.catch
        (fun () ->
          let* () = Lwt_io.write conn.oc (frame 'X' "") in
          Lwt_io.flush conn.oc)
        (fun _ -> Lwt.return_unit)
    in
    Lwt.catch conn.close_fn (fun _ -> Lwt.return_unit)
  end

let connect ?timeout ?(read_only = true) (dsn : Pg_dsn.t) =
  Lazy.force rng_initialized;
  let timeout =
    match (timeout, dsn.connect_timeout) with
    | Some t, _ | None, Some t -> t
    | None, None -> 10.
  in
  let fd_ref = ref None in
  let conn_ref = ref None in
  let attempt () =
    let* fd = open_socket dsn in
    fd_ref := Some fd;
    let* ic, oc, close_fn, is_tls = negotiate dsn fd in
    let conn = { ic; oc; params = []; is_tls; closed = false; close_fn } in
    conn_ref := Some conn;
    let* () = send conn (startup_packet ~read_only dsn) in
    let* () = authenticate conn dsn in
    Lwt.return conn
  in
  Lwt.catch
    (fun () -> Lwt_unix.with_timeout timeout attempt)
    (fun e ->
      let* () =
        match (!conn_ref, !fd_ref) with
        | Some c, _ -> close c
        | None, Some fd ->
            Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
        | None, None -> Lwt.return_unit
      in
      match e with
      | Lwt_unix.Timeout ->
          fail "timed out after %gs connecting to %s" timeout (Pg_dsn.redacted dsn)
      | Error _ -> Lwt.fail e
      | Unix.Unix_error (ue, _, _) ->
          fail "connection to %s failed: %s" (Pg_dsn.redacted dsn) (Unix.error_message ue)
      | e ->
          fail "connection to %s failed: %s" (Pg_dsn.redacted dsn) (Printexc.to_string e))

(* ------------------------------------------------------------ queries *)

let parse_row body : row =
  let c = { s = body; pos = 0 } in
  let n = get_i16 c in
  Array.init n (fun _ ->
      let len = get_i32 c in
      if len < 0 then None else Some (get_bytes c len))

(* Reads until ReadyForQuery. Returns the rows of the last row-returning statement. *)
let collect conn =
  let error = ref None in
  let last = ref [] in
  let current = ref None in
  let rec loop () =
    let* typ, body = read_msg conn in
    match typ with
    | 'T' ->
        current := Some [];
        loop ()
    | 'D' ->
        let r = parse_row body in
        current := Some (r :: Option.value !current ~default:[]);
        loop ()
    | 'C' ->
        (match !current with
        | Some rows ->
            last := List.rev rows;
            current := None
        | None -> ());
        loop ()
    | 'E' ->
        if !error = None then error := Some (error_of_body body);
        loop ()
    | 'G' ->
        (* COPY FROM STDIN: refuse. *)
        let* () =
          send conn (frame 'f' (build (fun b -> add_cstr b "COPY is not supported")))
        in
        loop ()
    | 'Z' -> (
        match !error with Some e -> Lwt.fail (Error e) | None -> Lwt.return !last)
    | '1' | '2' | '3' | 'I' | 'n' | 's' | 't' | 'N' | 'A' | 'H' | 'd' | 'c' -> loop ()
    | 'S' ->
        let c = { s = body; pos = 0 } in
        let k = get_cstr c in
        let v = get_cstr c in
        conn.params <- (k, v) :: List.remove_assoc k conn.params;
        loop ()
    | _ -> fail "protocol error: unexpected message %C" typ
  in
  loop ()

let check_open conn = if conn.closed then err "connection is closed"

let simple_query conn sql =
  check_open conn;
  let* () = send conn (frame 'Q' (build (fun b -> add_cstr b sql))) in
  collect conn

let query conn sql ~params =
  check_open conn;
  let nparams = List.length params in
  if nparams > 65535 then err "too many parameters";
  let parse =
    frame 'P'
      (build (fun b ->
           add_cstr b "";
           add_cstr b sql;
           add_i16 b 0))
  in
  let bind =
    frame 'B'
      (build (fun b ->
           add_cstr b "";
           add_cstr b "";
           add_i16 b 0;
           add_i16 b nparams;
           List.iter
             (function
               | None -> add_i32 b (-1)
               | Some v ->
                   add_i32 b (String.length v);
                   Buffer.add_string b v)
             params;
           add_i16 b 0))
  in
  let execute =
    frame 'E'
      (build (fun b ->
           add_cstr b "";
           add_i32 b 0))
  in
  let sync = frame 'S' "" in
  let* () = send conn (String.concat "" [ parse; bind; execute; sync ]) in
  (* Without Describe there is no RowDescription; DataRows are attributed to the portal. *)
  let error = ref None in
  let rows = ref [] in
  let rec loop () =
    let* typ, body = read_msg conn in
    match typ with
    | 'D' ->
        rows := parse_row body :: !rows;
        loop ()
    | 'E' ->
        if !error = None then error := Some (error_of_body body);
        loop ()
    | 'Z' -> (
        match !error with
        | Some e -> Lwt.fail (Error e)
        | None -> Lwt.return (List.rev !rows))
    | '1' | '2' | '3' | 'C' | 'I' | 'n' | 's' | 'N' | 'A' -> loop ()
    | 'S' ->
        let c = { s = body; pos = 0 } in
        let k = get_cstr c in
        let v = get_cstr c in
        conn.params <- (k, v) :: List.remove_assoc k conn.params;
        loop ()
    | _ -> fail "protocol error: unexpected message %C" typ
  in
  loop ()

let with_conn ?timeout ?read_only dsn f =
  let* conn = connect ?timeout ?read_only dsn in
  Lwt.finalize (fun () -> f conn) (fun () -> close conn)
