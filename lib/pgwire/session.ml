(* One client connection; see session.mli and docs/proxy.md for the protocol rules. *)

open Lwt.Syntax
open Proxy_config

type shared = {
  cfg : Proxy_config.t;
  generation : int;
  tls_server : Tls.Config.server option;
  audit : Paudit.t;
  mock_secret : string;
  cancel_table : (int, int * int * int * Proxy_config.upstream) Hashtbl.t;
}

let audit_sqlstate = "58030"
let sentinel_prefix = "haltsql_deny_"
let max_startup_packet = 10_000
let max_sasl_message = 4096
let max_upstream_message = 1 lsl 30

exception Fatal of string * string
(** [Fatal (sqlstate, message)]: send a FATAL ErrorResponse to the client and close. *)

exception Done
(** Orderly end of the session (Terminate, or upstream ended it). *)

type s = {
  sh : shared;
  id : string;
  peer : string;
  fd : Lwt_unix.file_descr;
  mutable client : Io.t;
  mutable user : string;
  mutable binding : binding option;
  mutable upstream : Io.t option;
  st : Stmt_state.t;
  mutable discarding : bool;
      (** after an injected extended-protocol denial, until Sync *)
  changed : unit Lwt_condition.t;
  mutable finished : bool;
  mutable proxy_pid : int option;
}

let fatal code msg = Lwt.fail (Fatal (code, msg))

let send_fatal io code msg =
  Lwt.catch
    (fun () ->
      Io.write io
        (Wire.error_response [ ('S', "FATAL"); ('V', "FATAL"); ('C', code); ('M', msg) ]))
    (fun _ -> Lwt.return_unit)

let log s level msg fields =
  Plog.log level msg
    ([ ("session", `String s.id); ("peer", `String s.peer) ]
    @ (if s.user = "" then [] else [ ("user", `String s.user) ])
    @ fields)

let contains ~sub s =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  m > 0 && go 0

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let binding s =
  match s.binding with
  | Some b -> b
  | None -> raise (Fatal ("XX000", "no session binding"))

let upstream s =
  match s.upstream with Some u -> u | None -> raise (Fatal ("XX000", "no upstream"))

(* ------------------------------------------------------------------ *)
(* Audit                                                                *)

let audit_base s ~event =
  let b = binding s in
  [
    ("event", `String event);
    ("session", `String s.id);
    ("user", `String s.user);
    ("policy", `String b.policy_name);
  ]

(* Fail closed: a statement whose audit record could not be written is refused (in-band,
   SQLSTATE 58030 io_error), whatever its verdict. *)
let audit_refusal () =
  Enforce.local_deny ~sqlstate:audit_sqlstate ~code:"PROXY_AUDIT_UNAVAILABLE"
    ~hint:
      "haltsql-proxy refuses statements while an audit sink with on_error: fail_closed \
       (or a full buffer) cannot be written; retry once the sink has recovered."
    "the audit log could not be written; statement refused"

let audited s r =
  match r with
  | Ok () -> Ok ()
  | Error e ->
      log s Plog.Error "statement refused: audit log unavailable" [ ("error", `String e) ];
      Error (audit_refusal ())

let audit_verdict s ~protocol ?stmt ~sql (v : Haltsql.Verdict.t)
    (r : (unit, Enforce.deny) result) =
  let codes = match r with Ok () -> [] | Error d -> d.codes in
  audited s
  @@ Paudit.record s.sh.audit
       (audit_base s ~event:"statement"
       @ [
           ("policy_version", `String v.policy_version);
           ("protocol", `String protocol);
           ("allowed", `Bool (Result.is_ok r));
           ("reasons", `List (List.map (fun c -> `String c) codes));
           ( "shadow_reasons",
             `List
               (List.map
                  (fun (x : Haltsql.Reason.t) ->
                    `String (Haltsql.Reason.code_to_string x.code))
                  v.shadow_reasons) );
           ("sql_sha256", `String v.sql_sha256);
           ("fingerprint", match v.fingerprint with Some f -> `String f | None -> `Null);
           ("tables", `List (List.map (fun t -> `String t) v.tables));
           ("bind_params", `List (List.map (fun (n, _) -> `Int n) v.bind_params));
         ]
       @ (match stmt with Some n -> [ ("statement", `String n) ] | None -> [])
       @ if s.sh.cfg.log_raw_sql then [ ("sql", `String sql) ] else [])

let audit_local s ~event ?stmt (d : Enforce.deny) =
  audited s
  @@ Paudit.record s.sh.audit
       (audit_base s ~event
       @ [
           ("allowed", `Bool false);
           ("reasons", `List (List.map (fun c -> `String c) d.codes));
           ("message", `String d.message);
         ]
       @ match stmt with Some n -> [ ("statement", `String n) ] | None -> [])

(* A proxy-level denial, replaced by the audit refusal if it cannot be audited. *)
let local_denial s ~event ?stmt d =
  match audit_local s ~event ?stmt d with Ok () -> d | Error refusal -> refusal

(* ------------------------------------------------------------------ *)
(* Startup                                                              *)

type startup = Start of int * (string * string) list | Cancel of int * int

let rec read_startup s ~ssl_done ~gss_done =
  let* body = Io.read_startup s.client ~max:max_startup_packet in
  match Wire.decode_startup body with
  | Wire.Ssl_request -> (
      if ssl_done then fatal "08P01" "duplicate SSLRequest"
      else
        match s.sh.tls_server with
        | None ->
            let* () = Io.write s.client "N" in
            read_startup s ~ssl_done:true ~gss_done
        | Some cfg ->
            if Io.buffered s.client > 0 then
              (* plaintext pipelined after SSLRequest: possible injection (CVE-2021-23214) *)
              Lwt.fail (Wire.Malformed "unencrypted data after SSLRequest")
            else
              let* () = Io.write s.client "S" in
              let* t = Tls_lwt.Unix.server_of_fd cfg s.fd in
              s.client <- Io.of_tls s.fd t;
              read_startup s ~ssl_done:true ~gss_done)
  | Wire.Gssenc_request ->
      if gss_done || ssl_done then fatal "08P01" "unexpected GSSENCRequest"
      else
        let* () = Io.write s.client "N" in
        read_startup s ~ssl_done ~gss_done:true
  | Wire.Cancel_request { pid; key } -> Lwt.return (Cancel (pid, key))
  | Wire.Startup { minor; params; _ } -> Lwt.return (Start (minor, params))

let valid_app_name a =
  String.length a <= 63
  && String.for_all (fun c -> Char.code c >= 0x20 && Char.code c < 0x7f) a

let peer_identity t =
  match Tls_lwt.Unix.epoch t with Error () -> None | Ok e -> e.Tls.Core.peer_certificate

(* X.509 >= 1.2 returns the CN as content octets in their declared ASN.1 string encoding.
   Decode the encodings with an unambiguous Unicode mapping to UTF-8 and treat anything
   else (TeletexString, malformed content, control characters) as no CN, so it never
   matches a [subject_cn] identity. Same rules as Haltsql_auth.Mtls.cn_text. *)
let cn_text (cn : X509.Distinguished_name.Common_name.t) =
  let module E = X509.Distinguished_name.Encoded_string in
  let enc = X509.Distinguished_name.Common_name.encoded cn in
  let raw = E.to_string enc in
  let wide ~width get =
    let len = String.length raw in
    if len mod width <> 0 then None
    else
      let b = Buffer.create len in
      let rec go i =
        if i >= len then Some (Buffer.contents b)
        else
          match get i with
          | Some u ->
              Buffer.add_utf_8_uchar b u;
              go (i + width)
          | None -> None
      in
      go 0
  in
  let text =
    match E.encoding enc with
    | `UTF8 -> if String.is_valid_utf_8 raw then Some raw else None
    | `Printable ->
        if String.for_all (fun c -> Char.code c < 0x80) raw then Some raw else None
    | `BMP ->
        (* UTF-16BE; a surrogate pair spans two units, so decode with the stdlib. *)
        let len = String.length raw in
        let b = Buffer.create len in
        let rec go i =
          if i >= len then Some (Buffer.contents b)
          else
            let d = String.get_utf_16be_uchar raw i in
            if Uchar.utf_decode_is_valid d then (
              Buffer.add_utf_8_uchar b (Uchar.utf_decode_uchar d);
              go (i + Uchar.utf_decode_length d))
            else None
        in
        go 0
    | `Universal ->
        wide ~width:4 (fun i ->
            let cp = Int32.to_int (String.get_int32_be raw i) land 0xFFFF_FFFF in
            if Uchar.is_valid cp then Some (Uchar.of_int cp) else None)
    | `Teletex -> None
  in
  match text with
  | Some t
    when t <> "" && String.for_all (fun c -> Char.code c >= 0x20 && Char.code c <> 0x7f) t
    ->
      Some t
  | _ -> None

let match_identity ids cert =
  let cn =
    Option.bind
      (X509.Distinguished_name.common_name (X509.Certificate.subject cert))
      cn_text
  in
  let uris =
    match
      X509.Extension.find X509.Extension.Subject_alt_name
        (X509.Certificate.extensions cert)
    with
    | Some (_, gn) ->
        Option.value ~default:[] (X509.General_name.find X509.General_name.URI gn)
    | None -> []
  in
  List.find_opt
    (fun id ->
      match id.id_match with
      | Subject_cn c -> cn = Some c
      | Spiffe_id sid -> List.mem sid uris)
    ids

let auth_failed user =
  Printf.sprintf "password authentication failed for user \"%s\"" user

let authenticate s =
  let cfg = s.sh.cfg in
  match cfg.auth with
  | Scram_users users -> (
      let u = List.find_opt (fun u -> u.user_name = s.user) users in
      let* () = Io.write s.client (Wire.auth_sasl [ Scram.mechanism ]) in
      let* tag, payload = Io.read_message s.client ~max:max_sasl_message in
      if tag <> 'p' then fatal "08P01" "expected SASL response"
      else
        let mech, data = Wire.decode_sasl_initial payload in
        if mech <> Scram.mechanism then
          fatal "28000" "client selected an invalid SASL authentication mechanism"
        else
          match data with
          | None -> fatal "08P01" "missing SASL initial response"
          | Some first -> (
              match
                Scram.Server.start
                  ~verifier:(Option.map (fun u -> u.verifier) u)
                  ~mock_secret:s.sh.mock_secret ~user:s.user
                  ~server_nonce:(Sec.b64_encode (Sec.random 18))
                  first
              with
              | Error m ->
                  log s Plog.Warn "authentication failed" [ ("reason", `String m) ];
                  fatal "28P01" (auth_failed s.user)
              | Ok (st, server_first) -> (
                  let* () = Io.write s.client (Wire.auth_sasl_continue server_first) in
                  let* tag, final = Io.read_message s.client ~max:max_sasl_message in
                  if tag <> 'p' then fatal "08P01" "expected SASL response"
                  else
                    match (Scram.Server.finish st final, u) with
                    | Ok server_final, Some u ->
                        let* () = Io.write s.client (Wire.auth_sasl_final server_final) in
                        Lwt.return u.user_binding
                    | Ok _, None | Error _, _ ->
                        log s Plog.Warn "authentication failed"
                          [
                            ( "reason",
                              `String (if u = None then "unknown user" else "bad proof")
                            );
                          ];
                        fatal "28P01" (auth_failed s.user))))
  | Cert_identities ids -> (
      match Io.tls s.client with
      | None -> fatal "28000" "a TLS client certificate is required"
      | Some t -> (
          match peer_identity t with
          | None -> fatal "28000" "a TLS client certificate is required"
          | Some cert -> (
              match match_identity ids cert with
              | Some id -> Lwt.return id.id_binding
              | None ->
                  log s Plog.Warn "certificate identity not authorized" [];
                  fatal "28000" "certificate identity is not authorized")))

let check_parameter s payload =
  let c = Wire.cursor payload in
  let k = Wire.get_cstring c in
  let v = Wire.get_cstring c in
  Wire.expect_end c;
  match k with
  | "client_encoding" when String.uppercase_ascii v <> "UTF8" ->
      log s Plog.Error "upstream client_encoding changed" [ ("value", `String v) ];
      fatal "08P01" "upstream client_encoding is not UTF8; terminating session"
  | "standard_conforming_strings" when v <> "on" ->
      log s Plog.Error "upstream standard_conforming_strings is off" [];
      fatal "08P01" "upstream standard_conforming_strings is not on; terminating session"
  | _ -> Lwt.return_unit

let register_cancel s ~upid ~ukey =
  let tbl = s.sh.cancel_table in
  let rec fresh () =
    let pid = Sec.random_int32 () land 0x3fffffff in
    if pid = 0 || Hashtbl.mem tbl pid then fresh () else pid
  in
  let pid = fresh () in
  let key = Sec.random_int32 () in
  Hashtbl.replace tbl pid (key, upid, ukey, s.sh.cfg.upstream);
  s.proxy_pid <- Some pid;
  (pid, key)

let rec relay_startup s up =
  let* tag, payload = Io.read_message up ~max:max_upstream_message in
  match tag with
  | 'S' ->
      let* () = check_parameter s payload in
      let* () = Io.write s.client (Wire.frame tag payload) in
      relay_startup s up
  | 'K' ->
      let c = Wire.cursor payload in
      let upid = Wire.get_int32 c in
      let ukey = Wire.get_int32 c in
      Wire.expect_end c;
      let pid, key = register_cancel s ~upid ~ukey in
      let* () = Io.write s.client (Wire.backend_key_data ~pid ~key) in
      relay_startup s up
  | 'N' ->
      let* () = Io.write s.client (Wire.frame tag payload) in
      relay_startup s up
  | 'Z' -> Io.write s.client (Wire.frame tag payload)
  | 'E' ->
      log s Plog.Error "upstream rejected the session" [];
      fatal "08006" "haltsql-proxy: the upstream database rejected the session"
  | c ->
      fatal "08P01"
        (Printf.sprintf "unexpected message %C from upstream during startup" c)

(* ------------------------------------------------------------------ *)
(* Enforcing relay                                                      *)

let forward s msg = Io.write (upstream s) msg
let new_token () = sentinel_prefix ^ Sec.random_hex 16

(* Denials are injected in-band: the denied message is replaced by a statement that
   fails to parse upstream, so the server's own error/ignore-until-Sync machinery keeps
   responses in order; the upstream relay swaps that error for ours. *)
let deny_simple s (d : Enforce.deny) =
  let tok = new_token () in
  Stmt_state.set_deny s.st ~token:tok (Enforce.deny_fields d);
  Stmt_state.end_segment s.st;
  forward s (Wire.frame 'Q' (tok ^ "\000"))

let deny_extended s (d : Enforce.deny) =
  let tok = new_token () in
  Stmt_state.set_deny s.st ~token:tok (Enforce.deny_fields d);
  s.discarding <- true;
  forward s (Wire.encode_parse { Wire.stmt = tok; query = tok; param_types = [] })

let rec resolve s name =
  match Stmt_state.lookup s.st name with
  | Stmt_state.Wait ->
      if s.finished then Lwt.fail Done
      else
        let* () = Lwt_condition.wait s.changed in
        resolve s name
  | r -> Lwt.return r

let sqlstate s = s.sh.cfg.deny_sqlstate

let handle_client_message s tag payload =
  match tag with
  | 'Q' -> (
      if s.discarding then Lwt.return_unit
      else
        let sql = Wire.decode_query payload in
        let v, r =
          Enforce.simple ~sqlstate:(sqlstate s)
            ~allow_tx:s.sh.cfg.allow_transaction_control (binding s) sql
        in
        match audit_verdict s ~protocol:"simple" ~sql v r with
        | Error refusal -> deny_simple s refusal
        | Ok () -> (
            match r with
            | Ok () ->
                Stmt_state.drop_unnamed s.st;
                Stmt_state.end_segment s.st;
                forward s (Wire.frame 'Q' payload)
            | Error d ->
                log s Plog.Info "statement denied"
                  [
                    ("protocol", `String "simple");
                    ("reasons", `List (List.map (fun c -> `String c) d.codes));
                  ];
                deny_simple s d))
  | 'P' -> (
      if s.discarding then Lwt.return_unit
      else
        let p = Wire.decode_parse payload in
        let v, r =
          Enforce.parse ~sqlstate:(sqlstate s)
            ~allow_tx:s.sh.cfg.allow_transaction_control (binding s) p.query
        in
        match audit_verdict s ~protocol:"extended" ~stmt:p.stmt ~sql:p.query v r with
        | Error refusal -> deny_extended s refusal
        | Ok () -> (
            match r with
            | Error d ->
                log s Plog.Info "statement denied"
                  [
                    ("protocol", `String "extended");
                    ("reasons", `List (List.map (fun c -> `String c) d.codes));
                  ];
                deny_extended s d
            | Ok () -> (
                let* existing =
                  if p.stmt = "" then Lwt.return Stmt_state.Missing else resolve s p.stmt
                in
                match existing with
                | Stmt_state.Found _ ->
                    let d =
                      Enforce.local_deny ~sqlstate:"42P05" ~code:"PROXY_STATEMENT_EXISTS"
                        (Printf.sprintf "prepared statement \"%s\" already exists" p.stmt)
                    in
                    deny_extended s (local_denial s ~event:"parse" ~stmt:p.stmt d)
                | _ ->
                    Stmt_state.note_parse s.st p.stmt v;
                    (* Never let the client choose how the injected tenant value is
                       decoded: forward tenancy parameters as unspecified. *)
                    let p' = Enforce.reset_tenancy_param_types v p in
                    forward s
                      (if p' == p then Wire.frame 'P' payload else Wire.encode_parse p')))
      )
  | 'B' -> (
      if s.discarding then Lwt.return_unit
      else
        let b = Wire.decode_bind payload in
        let* l = resolve s b.bstmt in
        match l with
        | Stmt_state.Found v -> (
            match Enforce.bind ~sqlstate:(sqlstate s) v b with
            | Ok b' ->
                Stmt_state.touch s.st;
                forward s
                  (if v.bind_params = [] then Wire.frame 'B' payload
                   else Wire.encode_bind b')
            | Error d -> deny_extended s (local_denial s ~event:"bind" ~stmt:b.bstmt d))
        | Stmt_state.Missing | Stmt_state.Wait ->
            let d =
              Enforce.local_deny ~sqlstate:"26000" ~code:"PROXY_STATEMENT_UNKNOWN"
                (Printf.sprintf "prepared statement \"%s\" does not exist" b.bstmt)
            in
            deny_extended s (local_denial s ~event:"bind" ~stmt:b.bstmt d))
  | 'D' ->
      if s.discarding then Lwt.return_unit
      else (
        ignore (Wire.decode_describe_or_close payload);
        Stmt_state.touch s.st;
        forward s (Wire.frame tag payload))
  | 'E' ->
      if s.discarding then Lwt.return_unit
      else (
        ignore (Wire.decode_execute payload);
        Stmt_state.touch s.st;
        forward s (Wire.frame tag payload))
  | 'C' ->
      if s.discarding then Lwt.return_unit
      else (
        (match Wire.decode_describe_or_close payload with
        | 'S', name -> Stmt_state.note_close_statement s.st name
        | _ -> Stmt_state.note_close_portal s.st);
        forward s (Wire.frame tag payload))
  | 'H' ->
      if payload <> "" then Lwt.fail (Wire.Malformed "Flush has a body")
      else if s.discarding then Lwt.return_unit
      else forward s (Wire.frame tag payload)
  | 'S' ->
      if payload <> "" then Lwt.fail (Wire.Malformed "Sync has a body")
      else (
        s.discarding <- false;
        Stmt_state.end_segment s.st;
        forward s (Wire.frame tag payload))
  | 'X' ->
      let* () =
        Lwt.catch (fun () -> forward s (Wire.frame 'X' "")) (fun _ -> Lwt.return_unit)
      in
      Lwt.fail Done
  | 'F' ->
      if s.discarding then Lwt.return_unit
      else
        let d =
          Enforce.local_deny ~sqlstate:(sqlstate s) ~code:"PROXY_FUNCTION_CALL"
            "the fastpath function call protocol is not allowed"
        in
        deny_simple s (local_denial s ~event:"function_call" d)
  | 'd' | 'c' | 'f' ->
      fatal "08P01" "COPY sub-protocol is not allowed through haltsql-proxy"
  | 'p' -> fatal "08P01" "unexpected password message"
  | c -> fatal "08P01" (Printf.sprintf "unsupported frontend message type %C" c)

let read_client s =
  let p = Io.read_message s.client ~max:s.sh.cfg.limits.max_message_bytes in
  let idle = s.sh.cfg.limits.idle_timeout in
  if idle <= 0. then p
  else
    let rec wait () =
      let* r =
        Lwt.pick
          [
            Lwt.map (fun m -> `Msg m) (Lwt.no_cancel p);
            Lwt.map (fun () -> `Timeout) (Lwt_unix.sleep idle);
          ]
      in
      match r with
      | `Msg m -> Lwt.return m
      | `Timeout ->
          if Stmt_state.in_flight s.st > 0 then wait ()
          else fatal "57P05" "terminating connection due to idle timeout (haltsql-proxy)"
    in
    wait ()

let rec client_loop s =
  let* tag, payload = read_client s in
  let* () = handle_client_message s tag payload in
  client_loop s

let rec upstream_loop s up =
  let* tag, payload = Io.read_message up ~max:max_upstream_message in
  let raw () = Io.write s.client (Wire.frame tag payload) in
  let* () =
    match tag with
    | '1' -> (
        match Stmt_state.on_parse_complete s.st with
        | Ok () -> raw ()
        | Error m -> fatal "08P01" ("haltsql-proxy lost protocol sync: " ^ m))
    | '3' -> (
        match Stmt_state.on_close_complete s.st with
        | Ok () -> raw ()
        | Error m -> fatal "08P01" ("haltsql-proxy lost protocol sync: " ^ m))
    | 'E' -> (
        let fields = Wire.decode_fields payload in
        let injected = Stmt_state.on_error s.st in
        let msg = Option.value ~default:"" (List.assoc_opt 'M' fields) in
        let* () =
          match injected with
          | Some (tok, ours) when contains ~sub:tok msg ->
              Io.write s.client (Wire.error_response ours)
          | _ -> raw ()
        in
        match List.assoc_opt 'V' fields with
        | Some ("FATAL" | "PANIC") -> Lwt.fail Done
        | _ -> Lwt.return_unit)
    | 'Z' ->
        Stmt_state.on_ready s.st;
        raw ()
    | 'G' | 'H' | 'W' | 'd' | 'c' ->
        fatal "08P01"
          "upstream entered COPY mode; COPY is not allowed through haltsql-proxy"
    | 'R' | 'K' | 'v' ->
        fatal "08P01" (Printf.sprintf "unexpected message %C from upstream" tag)
    | 'S' ->
        let* () = check_parameter s payload in
        raw ()
    | _ -> raw ()
  in
  Lwt_condition.broadcast s.changed ();
  upstream_loop s up

(* ------------------------------------------------------------------ *)

let run s =
  let cfg = s.sh.cfg in
  let* startup =
    Lwt_unix.with_timeout cfg.limits.auth_timeout (fun () ->
        let* r = read_startup s ~ssl_done:false ~gss_done:false in
        match r with
        | Cancel (pid, key) -> Lwt.return (`Cancel (pid, key))
        | Start (minor, params) ->
            let tls_on = Io.tls s.client <> None in
            let* () =
              match cfg.tls with
              | Some t when t.tls_required && not tls_on ->
                  fatal "28000" "haltsql-proxy requires an SSL/TLS connection"
              | _ -> Lwt.return_unit
            in
            let* () =
              if List.mem_assoc "replication" params then
                fatal "28000"
                  "replication connections are not allowed through haltsql-proxy"
              else Lwt.return_unit
            in
            let pq_opts =
              List.filter_map
                (fun (k, _) -> if starts_with ~prefix:"_pq_." k then Some k else None)
                params
            in
            let* () =
              if minor > 0 || pq_opts <> [] then
                Io.write s.client (Wire.negotiate_protocol_version ~minor:0 pq_opts)
              else Lwt.return_unit
            in
            let* () =
              match List.assoc_opt "user" params with
              | Some u when u <> "" ->
                  s.user <- u;
                  Lwt.return_unit
              | _ -> fatal "28000" "no PostgreSQL user name specified in startup packet"
            in
            let database =
              match List.assoc_opt "database" params with
              | Some d when d <> "" -> d
              | _ -> s.user
            in
            let* () =
              if database <> cfg.upstream.database then
                fatal "3D000" (Printf.sprintf "database \"%s\" does not exist" database)
              else Lwt.return_unit
            in
            let app =
              match List.assoc_opt "application_name" params with
              | Some a when valid_app_name a -> Some a
              | _ -> None
            in
            let* b = authenticate s in
            s.binding <- Some b;
            let* () = Io.write s.client Wire.auth_ok in
            log s Plog.Info "client authenticated"
              [
                ("policy", `String b.policy_name);
                ("tls", `Bool tls_on);
                ("config_generation", `Int s.sh.generation);
              ];
            Lwt.return (`Session app))
  in
  match startup with
  | `Cancel (pid, key) -> (
      match Hashtbl.find_opt s.sh.cancel_table pid with
      | Some (k, upid, ukey, upstream) ->
          let enc x =
            let b = Bytes.create 4 in
            Bytes.set_int32_be b 0 (Int32.of_int x);
            Bytes.to_string b
          in
          if Sec.ct_equal (enc k) (enc key) then (
            log s Plog.Info "forwarding cancel request" [];
            Upstream.send_cancel upstream ~pid:upid ~key:ukey)
          else (
            log s Plog.Warn "cancel request with wrong key" [];
            Lwt.return_unit)
      | None ->
          log s Plog.Warn "cancel request for unknown backend" [];
          Lwt.return_unit)
  | `Session app ->
      let* up =
        Lwt.catch
          (fun () -> Upstream.connect cfg.upstream ~application_name:app)
          (function
            | Upstream.Upstream_error m ->
                log s Plog.Error "upstream connection failed" [ ("error", `String m) ];
                fatal "08006" "haltsql-proxy could not connect to the upstream database"
            | e -> Lwt.fail e)
      in
      s.upstream <- Some up;
      let* () = relay_startup s up in
      Lwt.pick [ client_loop s; upstream_loop s up ]

let handle sh ~id fd =
  let peer =
    match Lwt_unix.getpeername fd with
    | Unix.ADDR_INET (a, p) -> Printf.sprintf "%s:%d" (Unix.string_of_inet_addr a) p
    | Unix.ADDR_UNIX p -> p
    | exception _ -> "unknown"
  in
  let s =
    {
      sh;
      id;
      peer;
      fd;
      client = Io.of_fd fd;
      user = "";
      binding = None;
      upstream = None;
      st = Stmt_state.create ();
      discarding = false;
      changed = Lwt_condition.create ();
      finished = false;
      proxy_pid = None;
    }
  in
  (try Lwt_unix.setsockopt fd Unix.TCP_NODELAY true with _ -> ());
  Lwt.finalize
    (fun () ->
      Lwt.catch
        (fun () -> run s)
        (fun e ->
          match e with
          | Done | Io.Closed -> Lwt.return_unit
          | Fatal (code, msg) ->
              log s Plog.Info "session terminated"
                [ ("sqlstate", `String code); ("reason", `String msg) ];
              send_fatal s.client code msg
          | Io.Too_large n ->
              log s Plog.Warn "message too large" [ ("length", `Int n) ];
              send_fatal s.client "08P01" "message exceeds the haltsql-proxy size limit"
          | Wire.Malformed m ->
              log s Plog.Warn "protocol violation" [ ("reason", `String m) ];
              send_fatal s.client "08P01" ("invalid frontend message: " ^ m)
          | Lwt_unix.Timeout ->
              log s Plog.Warn "authentication timeout" [];
              send_fatal s.client "08006" "authentication timed out"
          | Stmt_state.Overflow ->
              send_fatal s.client "54000" "too many pipelined statements"
          | Tls_lwt.Tls_failure f ->
              log s Plog.Warn "client TLS failure"
                [ ("error", `String (Tls.Engine.string_of_failure f)) ];
              Lwt.return_unit
          | Tls_lwt.Tls_alert a ->
              log s Plog.Warn "client TLS alert"
                [ ("error", `String (Tls.Packet.alert_type_to_string a)) ];
              Lwt.return_unit
          | Unix.Unix_error (err, _, _) ->
              log s Plog.Debug "connection error"
                [ ("error", `String (Unix.error_message err)) ];
              Lwt.return_unit
          | e ->
              log s Plog.Error "internal error"
                [ ("error", `String (Printexc.to_string e)) ];
              send_fatal s.client "XX000" "haltsql-proxy internal error"))
    (fun () ->
      s.finished <- true;
      Lwt_condition.broadcast s.changed ();
      (match s.proxy_pid with Some p -> Hashtbl.remove sh.cancel_table p | None -> ());
      let* () = match s.upstream with Some u -> Io.close u | None -> Lwt.return_unit in
      let* () = Io.close s.client in
      if s.binding <> None then log s Plog.Info "session ended" [];
      Lwt.return_unit)
