(** Minimal PostgreSQL wire-protocol client. See pg_wire.mli. *)

type sslmode = Disable | Prefer | Require | Verify_full

type dsn = {
  host : string;
  port : int;
  user : string;
  password : string option;
  database : string;
  sslmode : sslmode;
  connect_timeout : float;
}

exception Pg_error of { code : string; message : string; detail : string option }
exception Protocol_error of string

let fail fmt = Printf.ksprintf (fun s -> raise (Protocol_error s)) fmt

(* ---------------------------------------------------------------------- DSN *)

let pct_decode s =
  let n = String.length s in
  let b = Buffer.create n in
  let hex c =
    match c with
    | '0' .. '9' -> Some (Char.code c - 48)
    | 'a' .. 'f' -> Some (Char.code c - 87)
    | 'A' .. 'F' -> Some (Char.code c - 55)
    | _ -> None
  in
  let rec go i =
    if i >= n then Ok (Buffer.contents b)
    else if s.[i] = '%' then
      if i + 2 >= n then Error "truncated percent-escape"
      else
        match (hex s.[i + 1], hex s.[i + 2]) with
        | Some h, Some l ->
            Buffer.add_char b (Char.chr ((h * 16) + l));
            go (i + 3)
        | _ -> Error "invalid percent-escape"
    else begin
      Buffer.add_char b s.[i];
      go (i + 1)
    end
  in
  go 0

let sslmode_of_string = function
  | "disable" -> Ok Disable
  | "allow" | "prefer" -> Ok Prefer
  | "require" -> Ok Require
  | "verify-ca" | "verify-full" -> Ok Verify_full
  | s -> Error (Printf.sprintf "unsupported sslmode %S" s)

let sslmode_to_string = function
  | Disable -> "disable"
  | Prefer -> "prefer"
  | Require -> "require"
  | Verify_full -> "verify-full"

let ( let* ) = Result.bind

let split_once c s =
  match String.index_opt s c with
  | Some i -> (String.sub s 0 i, Some (String.sub s (i + 1) (String.length s - i - 1)))
  | None -> (s, None)

let rsplit_once c s =
  match String.rindex_opt s c with
  | Some i -> (String.sub s 0 i, Some (String.sub s (i + 1) (String.length s - i - 1)))
  | None -> (s, None)

let parse_dsn ?(env = Sys.getenv_opt) s =
  let err m = Error ("invalid DSN: " ^ m) in
  let rest =
    let strip p =
      if String.length s >= String.length p && String.sub s 0 (String.length p) = p then
        Some (String.sub s (String.length p) (String.length s - String.length p))
      else None
    in
    match strip "postgresql://" with Some r -> Some r | None -> strip "postgres://"
  in
  match rest with
  | None -> err "expected postgres://user:password@host:port/dbname"
  | Some rest -> (
      if String.contains s '\000' then err "NUL byte"
      else
        let main, query = split_once '?' rest in
        let authority, path = split_once '/' main in
        let userinfo, hostport =
          match rsplit_once '@' authority with
          | ui, Some hp -> (Some ui, hp)
          | hp, None -> (None, hp)
        in
        let* user, password =
          match userinfo with
          | None -> Ok (None, None)
          | Some ui -> (
              let u, p = split_once ':' ui in
              let* u = pct_decode u in
              match p with
              | None -> Ok (Some u, None)
              | Some p ->
                  let* p = pct_decode p in
                  Ok (Some u, Some p))
        in
        let* host, port =
          if hostport = "" then Ok (None, None)
          else if hostport.[0] = '[' then
            match String.index_opt hostport ']' with
            | None -> err "unterminated [IPv6] host"
            | Some i ->
                let h = String.sub hostport 1 (i - 1) in
                let after =
                  String.sub hostport (i + 1) (String.length hostport - i - 1)
                in
                if after = "" then Ok (Some h, None)
                else if after.[0] = ':' then
                  Ok (Some h, Some (String.sub after 1 (String.length after - 1)))
                else err "garbage after [IPv6] host"
          else
            let h, p = rsplit_once ':' hostport in
            let* h = pct_decode h in
            Ok ((if h = "" then None else Some h), p)
        in
        let* database =
          match path with
          | None | Some "" -> Ok None
          | Some d ->
              let* d = pct_decode d in
              Ok (Some d)
        in
        let params =
          match query with
          | None | Some "" -> []
          | Some q -> String.split_on_char '&' q |> List.filter (( <> ) "")
        in
        let* params =
          List.fold_left
            (fun acc kv ->
              let* acc = acc in
              let k, v = split_once '=' kv in
              let* v = pct_decode (Option.value v ~default:"") in
              Ok ((k, v) :: acc))
            (Ok []) params
        in
        let known =
          [
            "sslmode";
            "connect_timeout";
            "application_name";
            "host";
            "port";
            "user";
            "password";
            "dbname";
          ]
        in
        match List.find_opt (fun (k, _) -> not (List.mem k known)) params with
        | Some (k, _) -> err (Printf.sprintf "unsupported parameter %S" k)
        | None ->
            let param k = List.assoc_opt k params in
            let pick a b = match a with Some _ -> a | None -> b in
            let host = Option.value (pick (param "host") host) ~default:"localhost" in
            let* port =
              match pick (param "port") port with
              | None | Some "" -> Ok 5432
              | Some p -> (
                  match int_of_string_opt p with
                  | Some n when n > 0 && n < 65536 -> Ok n
                  | _ -> err (Printf.sprintf "invalid port %S" p))
            in
            let user =
              match pick (param "user") user with
              | Some u when u <> "" -> Some u
              | _ -> pick (env "PGUSER") (env "USER")
            in
            let* user =
              match user with Some u -> Ok u | None -> err "no user name given"
            in
            let password =
              match pick (param "password") password with
              | Some _ as p -> p
              | None -> env "PGPASSWORD"
            in
            let database =
              match pick (param "dbname") database with Some d -> d | None -> user
            in
            let* sslmode =
              sslmode_of_string (Option.value (param "sslmode") ~default:"prefer")
            in
            let* connect_timeout =
              match param "connect_timeout" with
              | None -> Ok 10.
              | Some t -> (
                  match int_of_string_opt t with
                  | Some n when n > 0 -> Ok (float_of_int n)
                  | _ -> err "invalid connect_timeout")
            in
            if String.contains user '\000' || String.contains database '\000' then
              err "NUL byte"
            else Ok { host; port; user; password; database; sslmode; connect_timeout })

let dsn_to_string_redacted d =
  let host = if String.contains d.host ':' then "[" ^ d.host ^ "]" else d.host in
  Printf.sprintf "postgres://%s@%s:%d/%s?sslmode=%s" d.user host d.port d.database
    (sslmode_to_string d.sslmode)

(* ---------------------------------------------------------------------- I/O *)

open Lwt.Syntax

type io = {
  read : bytes -> int -> int -> int Lwt.t;
  write : string -> unit Lwt.t;
  shutdown : unit -> unit Lwt.t;
}

type t = {
  mutable io : io;
  mutable tls : bool;
  rbuf : bytes;
  mutable rpos : int;
  mutable rlen : int;
  mutable broken : bool;
}

let max_message = 64 * 1024 * 1024

let plain_io fd =
  let rec write_all s off len =
    if len = 0 then Lwt.return_unit
    else
      let* n = Lwt_unix.write_string fd s off len in
      write_all s (off + n) (len - n)
  in
  {
    read = (fun b off len -> Lwt_unix.read fd b off len);
    write = (fun s -> write_all s 0 (String.length s));
    shutdown =
      (fun () -> Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit));
  }

let tls_io (tls : Tls_lwt.Unix.t) =
  {
    read =
      (fun b off len ->
        let tmp = Bytes.create len in
        let* n = Tls_lwt.Unix.read tls tmp in
        Bytes.blit tmp 0 b off n;
        Lwt.return n);
    write = Tls_lwt.Unix.write tls;
    shutdown =
      (fun () -> Lwt.catch (fun () -> Tls_lwt.Unix.close tls) (fun _ -> Lwt.return_unit));
  }

let fill c =
  if c.rpos > 0 && c.rpos = c.rlen then begin
    c.rpos <- 0;
    c.rlen <- 0
  end;
  let* n =
    Lwt.catch
      (fun () -> c.io.read c.rbuf c.rlen (Bytes.length c.rbuf - c.rlen))
      (fun e ->
        c.broken <- true;
        fail "connection read failed: %s" (Printexc.to_string e))
  in
  if n = 0 then begin
    c.broken <- true;
    fail "server closed the connection"
  end;
  c.rlen <- c.rlen + n;
  Lwt.return_unit

let read_exact c n =
  let out = Bytes.create n in
  let rec go got =
    if got = n then Lwt.return (Bytes.unsafe_to_string out)
    else begin
      let avail = c.rlen - c.rpos in
      if avail = 0 then
        let* () = fill c in
        go got
      else
        let k = min avail (n - got) in
        Bytes.blit c.rbuf c.rpos out got k;
        c.rpos <- c.rpos + k;
        go (got + k)
    end
  in
  go 0

let be32 s off = Int32.to_int (String.get_int32_be s off)
let be16 s off = String.get_int16_be s off

let read_message c =
  let* hdr = read_exact c 5 in
  let typ = hdr.[0] in
  let len = be32 hdr 1 in
  if len < 4 || len - 4 > max_message then begin
    c.broken <- true;
    fail "invalid message length %d" len
  end;
  let* body = read_exact c (len - 4) in
  Lwt.return (typ, body)

let int32_str n =
  let b = Bytes.create 4 in
  Bytes.set_int32_be b 0 (Int32.of_int n);
  Bytes.unsafe_to_string b

let message typ body = String.make 1 typ ^ int32_str (String.length body + 4) ^ body

let send c s =
  Lwt.catch
    (fun () -> c.io.write s)
    (fun e ->
      c.broken <- true;
      fail "connection write failed: %s" (Printexc.to_string e))

let cstring s =
  if String.contains s '\000' then fail "NUL byte in protocol string";
  s ^ "\000"

(* Parse an ErrorResponse / NoticeResponse body. *)
let error_fields body =
  let rec go i acc =
    if i >= String.length body || body.[i] = '\000' then acc
    else
      let k = body.[i] in
      match String.index_from_opt body (i + 1) '\000' with
      | None -> acc
      | Some j -> go (j + 1) ((k, String.sub body (i + 1) (j - i - 1)) :: acc)
  in
  go 0 []

let raise_error body =
  let f = error_fields body in
  raise
    (Pg_error
       {
         code = Option.value (List.assoc_opt 'C' f) ~default:"XX000";
         message = Option.value (List.assoc_opt 'M' f) ~default:"unknown error";
         detail = List.assoc_opt 'D' f;
       })

(* --------------------------------------------------------------- connecting *)

let rng_initialized = ref false

let ensure_rng () =
  if not !rng_initialized then begin
    Mirage_crypto_rng_unix.use_default ();
    rng_initialized := true
  end

let open_socket d =
  let* addrs =
    if String.length d.host > 0 && d.host.[0] = '/' then
      Lwt.return
        [ Unix.ADDR_UNIX (Filename.concat d.host (Printf.sprintf ".s.PGSQL.%d" d.port)) ]
    else
      let* infos =
        Lwt_unix.getaddrinfo d.host (string_of_int d.port)
          [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
      in
      Lwt.return (List.map (fun (ai : Unix.addr_info) -> ai.ai_addr) infos)
  in
  if addrs = [] then fail "cannot resolve host %s" d.host;
  let rec try_addrs last = function
    | [] -> fail "cannot connect to %s:%d: %s" d.host d.port last
    | addr :: rest ->
        let domain = Unix.domain_of_sockaddr addr in
        let fd = Lwt_unix.socket domain Unix.SOCK_STREAM 0 in
        Lwt.catch
          (fun () ->
            let* () = Lwt_unix.connect fd addr in
            Lwt.return fd)
          (fun e ->
            let* () =
              Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
            in
            let msg =
              match e with
              | Unix.Unix_error (err, _, _) -> Unix.error_message err
              | e -> Printexc.to_string e
            in
            try_addrs msg rest)
  in
  try_addrs "no address" addrs

let no_verify : X509.Authenticator.t = fun ?ip:_ ~host:_ _ -> Ok None

let start_tls c fd d =
  (* SSLRequest *)
  let* () = send c (int32_str 8 ^ int32_str 80877103) in
  let* answer = read_exact c 1 in
  match answer with
  | "S" ->
      if c.rlen - c.rpos <> 0 then fail "unexpected data after SSL response";
      ensure_rng ();
      let authenticator, peer_name =
        match d.sslmode with
        | Verify_full -> (
            match Ca_certs.authenticator () with
            | Error (`Msg m) -> fail "cannot load system CA certificates: %s" m
            | Ok a ->
                let peer =
                  match Domain_name.of_string d.host with
                  | Ok n -> (
                      match Domain_name.host n with Ok h -> Some h | Error _ -> None)
                  | Error _ -> None
                in
                (a, peer))
        | _ -> (no_verify, None)
      in
      let ip = match Ipaddr.of_string d.host with Ok ip -> Some ip | Error _ -> None in
      let config =
        match Tls.Config.client ~authenticator ?peer_name ?ip () with
        | Ok c -> c
        | Error (`Msg m) -> fail "TLS configuration error: %s" m
      in
      let* tls =
        Lwt.catch
          (fun () -> Tls_lwt.Unix.client_of_fd config ?host:peer_name fd)
          (fun e -> fail "TLS handshake failed: %s" (Printexc.to_string e))
      in
      c.io <- tls_io tls;
      c.tls <- true;
      Lwt.return_unit
  | "N" ->
      if d.sslmode = Require || d.sslmode = Verify_full then
        fail "server does not support TLS but sslmode=%s" (sslmode_to_string d.sslmode);
      Lwt.return_unit
  | "E" -> fail "server rejected the SSL request"
  | _ -> fail "unexpected answer to SSL request"

let md5_hex s = Digest.to_hex (Digest.string s)

let authenticate c d =
  let need_password () =
    match d.password with
    | Some p -> p
    | None -> fail "server requested a password but none was given (set PGPASSWORD)"
  in
  let scram = ref None in
  let scram_verified = ref false in
  let rec loop () =
    let* typ, body = read_message c in
    match typ with
    | 'R' -> (
        if String.length body < 4 then fail "short authentication message";
        let code = be32 body 0 in
        let data = String.sub body 4 (String.length body - 4) in
        match code with
        | 0 ->
            if !scram <> None && not !scram_verified then
              fail "server skipped SCRAM verification; refusing";
            after_auth ()
        | 3 ->
            if not c.tls then
              fail
                "server requested a cleartext password over an unencrypted connection; \
                 refusing (use sslmode=require)";
            let* () = send c (message 'p' (cstring (need_password ()))) in
            loop ()
        | 5 ->
            if String.length data <> 4 then fail "bad MD5 salt";
            let pw = need_password () in
            let digest = "md5" ^ md5_hex (md5_hex (pw ^ d.user) ^ data) in
            let* () = send c (message 'p' (cstring digest)) in
            loop ()
        | 10 ->
            let mechs = String.split_on_char '\000' data in
            if not (List.mem "SCRAM-SHA-256" mechs) then
              fail "server offers no supported SASL mechanism";
            let pw = need_password () in
            ignore pw;
            ensure_rng ();
            let nonce =
              Haltsql_scram.(
                nonce_of_entropy (Mirage_crypto_rng.generate nonce_entropy_bytes))
            in
            let st, first = Scram.client_first ~user:"" ~nonce in
            scram := Some st;
            let body =
              cstring "SCRAM-SHA-256" ^ int32_str (String.length first) ^ first
            in
            let* () = send c (message 'p' body) in
            loop ()
        | 11 -> (
            match !scram with
            | None -> fail "unexpected SASLContinue"
            | Some st -> (
                match
                  Scram.client_final st ~password:(need_password ()) ~server_first:data
                with
                | Error e -> fail "%s" e
                | Ok (st', final) ->
                    scram := Some st';
                    let* () = send c (message 'p' final) in
                    loop ()))
        | 12 -> (
            match !scram with
            | None -> fail "unexpected SASLFinal"
            | Some st -> (
                match Scram.verify_server_final st data with
                | Error e -> fail "%s" e
                | Ok () ->
                    scram_verified := true;
                    loop ()))
        | n -> fail "unsupported authentication method (code %d)" n)
    | 'E' -> raise_error body
    | 'N' -> loop ()
    | _ -> fail "unexpected message %C during authentication" typ
  and after_auth () =
    let* typ, body = read_message c in
    match typ with
    | 'Z' -> Lwt.return_unit
    | 'S' | 'K' | 'N' -> after_auth ()
    | 'E' -> raise_error body
    | _ -> fail "unexpected message %C after authentication" typ
  in
  loop ()

let connect d =
  let go () =
    let* fd = open_socket d in
    let c =
      {
        io = plain_io fd;
        tls = false;
        rbuf = Bytes.create 65536;
        rpos = 0;
        rlen = 0;
        broken = false;
      }
    in
    Lwt.catch
      (fun () ->
        let is_unix = String.length d.host > 0 && d.host.[0] = '/' in
        let* () =
          if d.sslmode = Disable || is_unix then Lwt.return_unit else start_tls c fd d
        in
        let params =
          cstring "user" ^ cstring d.user ^ cstring "database" ^ cstring d.database
          ^ cstring "application_name" ^ cstring "haltsql" ^ "\000"
        in
        let body = int32_str 196608 ^ params in
        let* () = send c (int32_str (String.length body + 4) ^ body) in
        let* () = authenticate c d in
        Lwt.return c)
      (fun e ->
        let* () = c.io.shutdown () in
        Lwt.reraise e)
  in
  Lwt.catch
    (fun () -> Lwt_unix.with_timeout d.connect_timeout go)
    (function
      | Lwt_unix.Timeout -> fail "connection to %s:%d timed out" d.host d.port
      | e -> Lwt.reraise e)

(* ------------------------------------------------------------------- queries *)

let parse_row body =
  let n = be16 body 0 in
  let pos = ref 2 in
  List.init n (fun _ ->
      let len = be32 body !pos in
      pos := !pos + 4;
      if len < 0 then None
      else begin
        if !pos + len > String.length body then raise (Protocol_error "truncated DataRow");
        let v = String.sub body !pos len in
        pos := !pos + len;
        Some v
      end)

let query c sql =
  if c.broken then fail "connection is broken";
  let* () = send c (message 'Q' (cstring sql)) in
  let rows = ref [] in
  let err = ref None in
  let rec loop () =
    let* typ, body = read_message c in
    match typ with
    | 'T' ->
        rows := [];
        loop ()
    | 'D' ->
        let row =
          try parse_row body
          with Invalid_argument _ ->
            c.broken <- true;
            raise (Protocol_error "malformed DataRow")
        in
        rows := row :: !rows;
        loop ()
    | 'C' | 'I' | 'N' | 'S' -> loop ()
    | 'E' ->
        if !err = None then err := Some body;
        loop ()
    | 'Z' -> (
        match !err with Some b -> raise_error b | None -> Lwt.return (List.rev !rows))
    | 'G' | 'H' | 'W' ->
        c.broken <- true;
        fail "COPY is not supported"
    | _ -> loop ()
  in
  loop ()

let exec c sql =
  let* _ = query c sql in
  Lwt.return_unit

let close c =
  Lwt.catch
    (fun () ->
      let* () =
        if c.broken then Lwt.return_unit
        else Lwt.catch (fun () -> c.io.write (message 'X' "")) (fun _ -> Lwt.return_unit)
      in
      c.broken <- true;
      c.io.shutdown ())
    (fun _ -> Lwt.return_unit)

let with_connection d f =
  let* c = connect d in
  Lwt.finalize (fun () -> f c) (fun () -> close c)
