(* An in-process stand-in for a PostgreSQL backend: enough of protocol 3.0 for the proxy
   to open a session and relay statements, and it records what it was sent. It executes
   nothing: every statement "succeeds" with an empty result, except the proxy's injected
   denial sentinels, which fail like a syntax error would. *)

open Haltsql_pgwire
open Lwt.Syntax

(* How a SCRAM-SHA-256 exchange ends: the way a real server ends it, with a
   server-final message whose signature is wrong (a peer that does not know the
   password), or with AuthenticationOk and no server-final message at all. *)
type scram_end = Honest | Wrong_signature | No_server_final

type auth =
  | Trust
  | Md5 of string
  | Cleartext of string
  | Scram of string * scram_end  (** password *)

type t = {
  sock : Lwt_unix.file_descr;
  port : int;
  mutable auth : auth;
  mutable show_search_path : string option;
      (** answer to [SHOW search_path]; default: the startup parameter (or
          ["$user", public] when the startup packet did not set one) *)
  mutable report_search_path : string option;
      (** PostgreSQL 18+: a [search_path] ParameterStatus sent during startup *)
  mutable statement_delay : float;  (** seconds before a statement completes *)
  mutable startups : (string * string) list list;  (** newest first *)
  mutable received : (char * string) list;  (** frontend messages, newest first *)
  mutable connections : int;
  mutable closed : int;
  mutable passwords : int;  (** password messages received *)
  mutable cancels : (int * int) list;  (** CancelRequest (pid, key), newest first *)
  mutable on_query : string -> string option;
      (** raw bytes to answer a simple query with, instead of completing it *)
}

let startup_params t = match t.startups with p :: _ -> p | [] -> []
let received t = List.rev t.received

let queries t =
  List.filter_map
    (function 'Q', p -> Some (Wire.decode_query p) | _ -> None)
    (received t)

let count_tag t tag = List.length (List.filter (fun (c, _) -> c = tag) t.received)
let sentinel = "haltsql_deny_"

let is_sentinel q =
  String.length q >= String.length sentinel
  && String.sub q 0 (String.length sentinel) = sentinel

let build f =
  let b = Buffer.create 64 in
  f b;
  Buffer.contents b

let text_row name value =
  Wire.frame 'T'
    (build (fun b ->
         Wire.add_int16 b 1;
         Wire.add_cstring b name;
         Wire.add_int32 b 0;
         Wire.add_int16 b 0;
         Wire.add_int32 b 25;
         Wire.add_int16 b 0xffff;
         Wire.add_int32 b 0xffffffff;
         Wire.add_int16 b 0))
  ^ Wire.frame 'D'
      (build (fun b ->
           Wire.add_int16 b 1;
           Wire.add_int32 b (String.length value);
           Buffer.add_string b value))

let complete tag = Wire.frame 'C' (tag ^ "\000")

let syntax_error tok =
  Wire.error_response
    [
      ('S', "ERROR");
      ('V', "ERROR");
      ('C', "42601");
      ('M', Printf.sprintf "syntax error at or near \"%s\"" tok);
    ]

let auth_request code extra =
  Wire.frame 'R'
    (build (fun b ->
         Wire.add_int32 b code;
         Buffer.add_string b extra))

let password_of payload =
  let c = Wire.cursor payload in
  Wire.get_cstring c

let authenticate t io ~user =
  let reject () =
    let* () =
      Io.write io
        (Wire.error_response
           [
             ('S', "FATAL");
             ('V', "FATAL");
             ('C', "28P01");
             ('M', "password authentication failed");
           ])
    in
    Lwt.fail Exit
  in
  match t.auth with
  | Trust -> Io.write io Wire.auth_ok
  | Cleartext pw ->
      let* () = Io.write io (auth_request 3 "") in
      let* _, p = Io.read_message io ~max:65536 in
      t.passwords <- t.passwords + 1;
      if password_of p = pw then Io.write io Wire.auth_ok else reject ()
  | Md5 pw ->
      let salt = "\x01\x02\x03\x04" in
      let* () = Io.write io (auth_request 5 salt) in
      let* _, p = Io.read_message io ~max:65536 in
      t.passwords <- t.passwords + 1;
      if password_of p = Upstream.md5_password ~user ~password:pw ~salt then
        Io.write io Wire.auth_ok
      else reject ()
  | Scram (pw, ending) -> (
      let* () = Io.write io (Wire.auth_sasl [ Scram.mechanism ]) in
      let* _, p = Io.read_message io ~max:65536 in
      t.passwords <- t.passwords + 1;
      let first =
        match Wire.decode_sasl_initial p with _, Some f -> f | _, None -> ""
      in
      match
        Scram.Server.start
          ~verifier:(Some (Scram.make_verifier ~iterations:4096 pw))
          ~mock_secret:"fake" ~user ~server_nonce:(Scram.new_nonce ()) first
      with
      | Error _ -> reject ()
      | Ok (st, server_first) -> (
          let* () = Io.write io (Wire.auth_sasl_continue server_first) in
          let* _, final = Io.read_message io ~max:65536 in
          match (Scram.Server.finish st final, ending) with
          | Error _, _ -> reject ()
          | Ok server_final, Honest ->
              let* () = Io.write io (Wire.auth_sasl_final server_final) in
              Io.write io Wire.auth_ok
          | Ok _, Wrong_signature ->
              let forged = "v=" ^ Sec.b64_encode (String.make 32 'x') in
              let* () = Io.write io (Wire.auth_sasl_final forged) in
              Io.write io Wire.auth_ok
          | Ok _, No_server_final -> Io.write io Wire.auth_ok))

let rec read_start io =
  let* body = Io.read_startup io ~max:10_000 in
  match Wire.decode_startup body with
  | Wire.Ssl_request | Wire.Gssenc_request ->
      let* () = Io.write io "N" in
      read_start io
  | Wire.Startup { params; _ } -> Lwt.return (`Start params)
  | Wire.Cancel_request { pid; key } -> Lwt.return (`Cancel (pid, key))

let serve t fd =
  let io = Io.of_fd fd in
  let tx = ref 'I' and skip = ref false in
  let ready () = Io.write io (Wire.ready_for_query !tx) in
  let delay () =
    if t.statement_delay > 0. then Lwt_unix.sleep t.statement_delay else Lwt.return_unit
  in
  let rec loop search_path =
    let* tag, payload = Io.read_message io ~max:(1 lsl 24) in
    t.received <- (tag, payload) :: t.received;
    let* () =
      match tag with
      | 'Q' -> (
          let q = Wire.decode_query payload in
          match String.uppercase_ascii (String.trim q) with
          | _ when t.on_query q <> None -> Io.write io (Option.get (t.on_query q))
          | "SHOW SEARCH_PATH" ->
              let v = Option.value t.show_search_path ~default:search_path in
              let* () = Io.write io (text_row "search_path" v ^ complete "SHOW") in
              ready ()
          | _ when is_sentinel q ->
              let* () = Io.write io (syntax_error q) in
              if !tx = 'T' then tx := 'E';
              ready ()
          | u ->
              let* () = delay () in
              let word = List.hd (String.split_on_char ' ' u) in
              (match word with
              | "BEGIN" | "START" -> tx := 'T'
              | "COMMIT" | "ROLLBACK" | "END" | "ABORT" -> tx := 'I'
              | _ -> ());
              let* () =
                Io.write io (complete (if word = "SELECT" then "SELECT 0" else word))
              in
              ready ())
      | 'P' ->
          if !skip then Lwt.return_unit
          else
            let p = Wire.decode_parse payload in
            if is_sentinel p.query then (
              skip := true;
              Io.write io (syntax_error p.query))
            else Io.write io (Wire.frame '1' "")
      | 'B' -> if !skip then Lwt.return_unit else Io.write io (Wire.frame '2' "")
      | 'D' -> if !skip then Lwt.return_unit else Io.write io (Wire.frame 'n' "")
      | 'E' ->
          if !skip then Lwt.return_unit
          else
            let* () = delay () in
            Io.write io (complete "SELECT 0")
      | 'C' -> if !skip then Lwt.return_unit else Io.write io (Wire.frame '3' "")
      | 'S' ->
          skip := false;
          ready ()
      | 'X' -> Lwt.fail Exit
      | _ -> Lwt.return_unit
    in
    loop search_path
  in
  Lwt.finalize
    (fun () ->
      Lwt.catch
        (fun () ->
          let* start = read_start io in
          match start with
          | `Cancel c ->
              t.cancels <- c :: t.cancels;
              Lwt.return_unit
          | `Start params ->
              t.startups <- params :: t.startups;
              let user = Option.value ~default:"" (List.assoc_opt "user" params) in
              let* () = authenticate t io ~user in
              let search_path =
                Option.value
                  (List.assoc_opt "search_path" params)
                  ~default:"\"$user\", public"
              in
              let* () =
                Io.write io
                  (Wire.parameter_status "client_encoding" "UTF8"
                  ^ Wire.parameter_status "standard_conforming_strings" "on"
                  ^ Wire.parameter_status "server_version" "17.0"
                  ^ (match t.report_search_path with
                    | Some v -> Wire.parameter_status "search_path" v
                    | None -> "")
                  ^ Wire.backend_key_data ~pid:4242 ~key:99)
              in
              let* () = ready () in
              loop search_path)
        (fun _ -> Lwt.return_unit))
    (fun () ->
      t.closed <- t.closed + 1;
      Io.close io)

let start () =
  let sock = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt sock Unix.SO_REUSEADDR true;
  let* () = Lwt_unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_loopback, 0)) in
  Lwt_unix.listen sock 64;
  let port = match Lwt_unix.getsockname sock with Unix.ADDR_INET (_, p) -> p | _ -> 0 in
  let t =
    {
      sock;
      port;
      auth = Trust;
      show_search_path = None;
      report_search_path = None;
      statement_delay = 0.;
      startups = [];
      received = [];
      connections = 0;
      closed = 0;
      passwords = 0;
      cancels = [];
      on_query = (fun _ -> None);
    }
  in
  let rec accept () =
    let* r =
      Lwt.catch
        (fun () ->
          let* fd, _ = Lwt_unix.accept sock in
          Lwt.return (Some fd))
        (fun _ -> Lwt.return None)
    in
    match r with
    | None -> Lwt.return_unit
    | Some fd ->
        t.connections <- t.connections + 1;
        Lwt.async (fun () -> serve t fd);
        accept ()
  in
  Lwt.async accept;
  Lwt.return t

let stop t = Lwt.catch (fun () -> Lwt_unix.close t.sock) (fun _ -> Lwt.return_unit)
