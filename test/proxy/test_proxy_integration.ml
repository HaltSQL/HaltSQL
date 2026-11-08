(* End-to-end tests of the haltsql-proxy binary against the lab Postgres 17
   (make -C lab up; localhost:5417). A real driver (psycopg 3 / libpq, from lab/.venv)
   and a raw protocol client exercise the proxy. Skips cleanly when Postgres or the venv
   is unavailable.

   Database: haltsql_proxy_test (created and dropped here). *)

open Haltsql_pgwire

let db = "haltsql_proxy_test"
let pg_port = 5417
let agent_pw = "agent-pass-7f3a"
let agent2_pw = "agent2-pass-91c2"
let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p
let proxy_bin = Option.map absolute (Sys.getenv_opt "HALTSQL_PROXY_BIN")
let gencerts_bin = Option.map absolute (Sys.getenv_opt "HALTSQL_GENCERTS_BIN")

(* ------------------------------------------------------------ helpers *)

let rec find_up dir rel n =
  let p = Filename.concat dir rel in
  if Sys.file_exists p then Some p
  else if n = 0 then None
  else
    let parent = Filename.dirname dir in
    if parent = dir then None else find_up parent rel (n - 1)

let python =
  match Sys.getenv_opt "HALTSQL_LAB_PYTHON" with
  | Some p -> Some p
  | None -> find_up (Sys.getcwd ()) "lab/.venv/bin/python" 8

let tcp_open port =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Fun.protect
    ~finally:(fun () -> try Unix.close fd with _ -> ())
    (fun () ->
      try
        Unix.set_nonblock fd;
        (try Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, port))
         with Unix.Unix_error ((Unix.EINPROGRESS | Unix.EAGAIN), _, _) -> ());
        match Unix.select [] [ fd ] [] 1.0 with
        | _, [ _ ], _ -> (
            match Unix.getsockopt_error fd with None -> true | Some _ -> false)
        | _ -> false
      with _ -> false)

let free_port () =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind fd (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p =
    match Unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> assert false
  in
  Unix.close fd;
  p

let read_file path = In_channel.with_open_bin path In_channel.input_all

let write_file path s =
  Out_channel.with_open_gen [ Open_wronly; Open_creat; Open_trunc ] 0o600 path (fun oc ->
      Out_channel.output_string oc s)

let run_capture ?(env = [||]) argv =
  let env = Array.append (Unix.environment ()) env in
  let ic, oc, ec = Unix.open_process_args_full argv.(0) argv env in
  close_out oc;
  let out = In_channel.input_all ic in
  let err = In_channel.input_all ec in
  let st = Unix.close_process_full (ic, oc, ec) in
  (st, out, err)

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

(* ---------------------------------------------------- environment check *)

let skip_reason =
  match (proxy_bin, gencerts_bin, python) with
  | None, _, _ | _, None, _ ->
      Some "HALTSQL_PROXY_BIN / HALTSQL_GENCERTS_BIN not set (run via dune test)"
  | _, _, None -> Some "lab/.venv/bin/python not found (make -C lab venv)"
  | _, _, Some py -> (
      if not (tcp_open pg_port) then
        Some "lab Postgres not reachable on localhost:5417 (make -C lab up)"
      else
        match run_capture [| py; "-c"; "import psycopg" |] with
        | Unix.WEXITED 0, _, _ -> None
        | _ -> Some "psycopg is not installed in lab/.venv"
        | exception _ -> Some ("cannot run " ^ py))

(* --------------------------------------------------------- raw client *)

module Raw = struct
  type t = { fd : Unix.file_descr; ic : in_channel; oc : out_channel }

  let connect port =
    let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, port));
    Unix.setsockopt_float fd Unix.SO_RCVTIMEO 10.;
    { fd; ic = Unix.in_channel_of_descr fd; oc = Unix.out_channel_of_descr fd }

  let send t s =
    output_string t.oc s;
    flush t.oc

  let read t =
    let tag = input_char t.ic in
    let len = input_binary_int t.ic in
    let payload = really_input_string t.ic (len - 4) in
    (tag, payload)

  let read_opt t = try Some (read t) with _ -> None
  let close t = try Unix.close t.fd with _ -> ()

  let rec until_z t acc =
    match read t with ('Z', _) as m -> List.rev (m :: acc) | m -> until_z t (m :: acc)

  let until_z t = until_z t []

  let login ?(user = "agent") ?(password = agent_pw) t =
    send t (Wire.encode_startup [ ("user", user); ("database", db) ]);
    let rec auth scram =
      let tag, p = read t in
      match tag with
      | 'R' -> (
          match (Wire.decode_auth p, scram) with
          | Wire.Auth_ok, _ -> ()
          | Wire.Auth_sasl _, _ ->
              let st, first =
                Scram.Client.first ~nonce:(Sec.b64_encode (Sec.random 18)) ()
              in
              send t (Wire.sasl_initial_response ~mechanism:Scram.mechanism first);
              auth (Some st)
          | Wire.Auth_sasl_continue d, Some st ->
              let st, fin = Result.get_ok (Scram.Client.final st ~password d) in
              send t (Wire.sasl_response fin);
              auth (Some st)
          | Wire.Auth_sasl_final d, Some st ->
              if Scram.Client.verify_server st d <> Ok () then
                failwith "proxy SCRAM signature";
              auth None
          | _ -> failwith "unexpected auth message")
      | 'E' -> failwith ("login failed: " ^ p)
      | c -> failwith (Printf.sprintf "unexpected %C during login" c)
    in
    auth None;
    let rec ready () =
      match read t with
      | 'Z', _ -> ()
      | 'E', p -> failwith ("login failed: " ^ p)
      | _ -> ready ()
    in
    ready ()

  let fields p = Wire.decode_fields p
  let field c p = Option.value ~default:"" (List.assoc_opt c (fields p))

  (* summary of a response sequence: tags, with E rendered as E:<sqlstate> *)
  let summary msgs =
    String.concat " "
      (List.map
         (fun (tag, p) -> if tag = 'E' then "E:" ^ field 'C' p else String.make 1 tag)
         msgs)
end

let q_orders =
  "SELECT id, tenant_id FROM app.orders WHERE tenant_id = $1 ORDER BY id LIMIT 100"

let parse ?(name = "") ?(types = []) q =
  Wire.encode_parse { Wire.stmt = name; query = q; param_types = types }

let bind ?(stmt = "") ?(formats = []) params =
  Wire.encode_bind
    {
      Wire.portal = "";
      bstmt = stmt;
      param_formats = formats;
      params;
      result_formats = [];
    }

let execute = Wire.frame 'E' "\x00\x00\x00\x00\x00"
let sync = Wire.frame 'S' ""

(* ------------------------------------------------------------ fixture *)

type proxy = { pid : int; port : int; log : string }

type env = {
  tmp : string;
  py : string;
  proxies : (string * proxy) list;
  results : Yojson.Safe.t;  (** psycopg scenarios *)
  raw : (string * string) list;  (** raw-client observations *)
  exits : (string * Unix.process_status) list;
  audit : string;
}

(* Password of the lab / CI Postgres superuser (HALTSQL_PGPASSWORD, default: the
   lab compose value). *)
let upstream_pw = Option.value ~default:"haltlab" (Sys.getenv_opt "HALTSQL_PGPASSWORD")

let start_proxy ~name ~tmp (cfg : Yojson.Safe.t) =
  let bin = Option.get proxy_bin in
  let port = free_port () in
  let path = Filename.concat tmp (name ^ ".json") in
  write_file path (Yojson.Safe.to_string cfg);
  let log = Filename.concat tmp (name ^ ".log") in
  let out = Unix.openfile log [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o600 in
  let devnull = Unix.openfile "/dev/null" [ Unix.O_RDWR ] 0 in
  let env = Array.append (Unix.environment ()) [| "PROXY_UPSTREAM_PW=" ^ upstream_pw |] in
  let pid =
    Unix.create_process_env bin
      [| bin; "run"; "-c"; path; "--listen"; Printf.sprintf "127.0.0.1:%d" port |]
      env devnull out out
  in
  Unix.close out;
  Unix.close devnull;
  let rec wait n =
    if tcp_open port then ()
    else if n = 0 then
      failwith (Printf.sprintf "proxy %s did not start: %s" name (read_file log))
    else (
      Unix.sleepf 0.1;
      wait (n - 1))
  in
  wait 100;
  (name, { pid; port; log })

let stop_proxy (name, p) =
  Unix.kill p.pid Sys.sigterm;
  let deadline = Unix.gettimeofday () +. 20. in
  let rec wait () =
    match Unix.waitpid [ Unix.WNOHANG ] p.pid with
    | 0, _ when Unix.gettimeofday () < deadline ->
        Unix.sleepf 0.1;
        wait ()
    | 0, _ ->
        Unix.kill p.pid Sys.sigkill;
        snd (Unix.waitpid [] p.pid)
    | _, st -> st
  in
  (name, wait ())

let config ~tmp ?(tls = `Null) ?(auth = None) ?(limits = `Null) ?(upstream_extra = [])
    ?(audit = `Null) () : Yojson.Safe.t =
  ignore tmp;
  let user name pw tenant =
    `Assoc
      [
        ("name", `String name);
        ("scram_verifier", `String (Scram.verifier_to_string (Scram.make_verifier pw)));
        ("policy", `String "proxy-test");
        ("context", `Assoc [ ("tenant_id", `String tenant) ]);
      ]
  in
  let default_auth =
    `Assoc
      [
        ("method", `String "scram");
        ("users", `List [ user "agent" agent_pw "acme"; user "agent2" agent2_pw "globex" ]);
      ]
  in
  `Assoc
    ([
       ("apiVersion", `String "haltsql.dev/v1");
       ("kind", `String "ProxyConfig");
       ( "upstream",
         `Assoc
           ([
              ("host", `String "127.0.0.1");
              ("port", `Int pg_port);
              ("database", `String db);
              ("user", `String "postgres");
              ("password", `String "${env:PROXY_UPSTREAM_PW}");
            ]
           @ upstream_extra) );
       ( "policies",
         `List
           [
             `Assoc
               [
                 ("path", `String (Filename.concat (Sys.getcwd ()) "fixtures/policy.yaml"));
               ];
           ] );
       ("auth", Option.value auth ~default:default_auth);
       ("logging", `Assoc [ ("level", `String "debug") ]);
       ("shutdown_grace_seconds", `Int 3);
     ]
    @ (if tls = `Null then [] else [ ("tls", tls) ])
    @ (if limits = `Null then [] else [ ("limits", limits) ])
    @
    if audit = `Null then [ ("audit", `Assoc [ ("type", `String "none") ]) ]
    else [ ("audit", audit) ])

let raw_scenarios ~a ~c ~d =
  let obs = ref [] in
  let record name f =
    let v = try f () with e -> "exception: " ^ Printexc.to_string e in
    obs := (name, v) :: !obs
  in
  (* GSSENCRequest is refused with 'N'; login then proceeds *)
  record "gssenc" (fun () ->
      let t = Raw.connect a in
      Raw.send t (Wire.frame_untagged "\x04\xd2\x16\x30");
      let b = input_char t.ic in
      Raw.login t;
      Raw.close t;
      Printf.sprintf "%c then login ok" b);
  (* fastpath function call: denied in-band, connection stays usable *)
  record "function_call" (fun () ->
      let t = Raw.connect a in
      Raw.login t;
      Raw.send t (Wire.frame 'F' "\x00\x00\x04\xd2\x00\x00\x00\x00\x00\x00");
      let r1 = Raw.until_z t in
      let detail = match r1 with ('E', p) :: _ -> Raw.field 'D' p | _ -> "" in
      Raw.send t
        (Wire.frame 'Q' "SELECT code FROM app.currencies ORDER BY code LIMIT 1\x00");
      let r2 = Raw.until_z t in
      Raw.close t;
      Printf.sprintf "%s [%s] | %s" (Raw.summary r1) detail (Raw.summary r2));
  (* COPY sub-protocol messages are a protocol violation: FATAL and close *)
  record "copy_data" (fun () ->
      let t = Raw.connect a in
      Raw.login t;
      Raw.send t (Wire.frame 'd' "1\t2\n");
      let m = Raw.read t in
      let eof = Raw.read_opt t = None in
      Raw.close t;
      Printf.sprintf "%s %s eof=%b" (Raw.summary [ m ]) (Raw.field 'V' (snd m)) eof);
  (* protocol 2.0 is rejected *)
  record "protocol2" (fun () ->
      let t = Raw.connect a in
      Raw.send t (Wire.frame_untagged "\x00\x02\x00\x00user\x00agent\x00\x00");
      let m = Raw.read t in
      Raw.close t;
      Raw.summary [ m ] ^ " " ^ Raw.field 'V' (snd m));
  (* oversized message: FATAL before reading the body *)
  record "oversized" (fun () ->
      let t = Raw.connect a in
      Raw.login t;
      Raw.send t "Q\x7f\x00\x00\x00";
      let m = Raw.read t in
      Raw.close t;
      Raw.summary [ m ] ^ " " ^ Raw.field 'V' (snd m));
  (* plaintext pipelined right after SSLRequest must not be processed *)
  record "ssl_pipelined" (fun () ->
      let t = Raw.connect a in
      Raw.send t (Wire.encode_ssl_request ^ Wire.encode_startup [ ("user", "agent") ]);
      let b = input_char t.ic in
      Raw.close t;
      String.make 1 b);
  record "no_user" (fun () ->
      let t = Raw.connect a in
      Raw.send t (Wire.encode_startup [ ("database", db) ]);
      let m = Raw.read t in
      Raw.close t;
      Raw.summary [ m ]);
  (* extended protocol edge cases *)
  record "bind_unknown" (fun () ->
      let t = Raw.connect a in
      Raw.login t;
      Raw.send t (bind ~stmt:"nope" [] ^ execute ^ sync);
      let r = Raw.until_z t in
      Raw.close t;
      Raw.summary r);
  record "duplicate_parse" (fun () ->
      let t = Raw.connect a in
      Raw.login t;
      Raw.send t (parse ~name:"s1" q_orders ^ sync);
      let r1 = Raw.until_z t in
      Raw.send t (parse ~name:"s1" q_orders ^ sync);
      let r2 = Raw.until_z t in
      Raw.send t (bind ~stmt:"s1" [ Some "globex" ] ^ execute ^ sync);
      let r3 = Raw.until_z t in
      let tenants =
        List.filter_map
          (fun (tag, p) ->
            if tag = 'D' then (
              let c = Wire.cursor p in
              ignore (Wire.get_int16 c);
              let l1 = Wire.get_int32 c in
              ignore (Wire.get_bytes c l1);
              let l2 = Wire.get_int32 c in
              Some (Wire.get_bytes c l2))
            else None)
          r3
      in
      Raw.close t;
      Printf.sprintf "%s | %s | %s" (Raw.summary r1) (Raw.summary r2)
        (String.concat "," tenants));
  (* a Parse the server ignored (after an error in the same segment) never takes effect *)
  record "ignored_parse" (fun () ->
      let t = Raw.connect a in
      Raw.login t;
      Raw.send t (parse q_orders ^ sync);
      let r1 = Raw.until_z t in
      Raw.send t
        (Wire.frame 'E' "missing_portal\x00\x00\x00\x00\x00"
        ^ parse "SELECT code FROM app.currencies LIMIT 1"
        ^ sync);
      let r2 = Raw.until_z t in
      Raw.send t (bind [ Some "globex" ] ^ execute ^ sync);
      let r3 = Raw.until_z t in
      Raw.close t;
      Printf.sprintf "%s | %s | %s" (Raw.summary r1) (Raw.summary r2) (Raw.summary r3));
  (* Regression: a client-declared Parse type for the tenancy parameter must
     not change how the injected tenant value is decoded ("char" = 18 would
     keep only its first byte, float8 = 701 would round). The proxy resets it
     to unspecified, so PostgreSQL infers text from tenant_id. *)
  List.iter
    (fun (name, ty) ->
      record name (fun () ->
          let t = Raw.connect a in
          Raw.login t;
          Raw.send t
            (parse ~types:[ ty ] q_orders ^ bind [ Some "globex" ] ^ execute ^ sync);
          let r = Raw.until_z t in
          Raw.close t;
          let rows = List.length (List.filter (fun (tag, _) -> tag = 'D') r) in
          Printf.sprintf "%s rows=%d" (Raw.summary r) rows))
    [
      ("declared_type_char", 18); ("declared_type_name", 19); ("declared_type_float8", 701);
    ];
  record "binary_tenant_param" (fun () ->
      let t = Raw.connect a in
      Raw.login t;
      Raw.send t
        (parse q_orders ^ bind ~formats:[ 1 ] [ Some "\x00\x01" ] ^ execute ^ sync);
      let r = Raw.until_z t in
      let detail =
        List.find_map
          (fun (tag, p) -> if tag = 'E' then Some (Raw.field 'D' p) else None)
          r
      in
      Raw.close t;
      Printf.sprintf "%s [%s]" (Raw.summary r) (Option.value ~default:"" detail));
  (* limits: proxy c has max_connections = 1 and idle_timeout = 1s *)
  record "max_connections" (fun () ->
      let t1 = Raw.connect c in
      Unix.sleepf 0.3;
      let t2 = Raw.connect c in
      let m = Raw.read t2 in
      Raw.close t2;
      Raw.close t1;
      Raw.summary [ m ]);
  Unix.sleepf 0.5;
  record "idle_timeout" (fun () ->
      let t = Raw.connect c in
      Raw.login t;
      Unix.sleepf 2.0;
      let m = Raw.read t in
      Raw.close t;
      Raw.summary [ m ] ^ " " ^ Raw.field 'V' (snd m));
  (* proxy d requires upstream TLS, which the lab server does not offer *)
  record "upstream_tls_required" (fun () ->
      let t = Raw.connect d in
      try
        Raw.login t;
        "connected"
      with Failure m ->
        Raw.close t;
        if contains m "08006" then "08006" else m);
  List.rev !obs

let setup () =
  let py = Option.get python in
  let tmp = Filename.temp_dir "haltsql_proxy_test" "" in
  let certs = Filename.concat tmp "certs" in
  Unix.mkdir certs 0o700;
  (match run_capture [| Option.get gencerts_bin; certs |] with
  | Unix.WEXITED 0, _, _ -> ()
  | _, _, e -> failwith ("gencerts failed: " ^ e));
  (match run_capture [| py; "pgclient.py"; "setup"; db |] with
  | Unix.WEXITED 0, _, _ -> ()
  | _, o, e -> failwith ("database setup failed: " ^ o ^ e));
  let cert f = `String (Filename.concat certs f) in
  let audit_path = Filename.concat tmp "audit.jsonl" in
  let a =
    start_proxy ~name:"scram" ~tmp
      (config ~tmp
         ~tls:
           (`Assoc
              [
                ("cert", cert "server.pem");
                ("key", cert "server.key");
                ("required", `Bool false);
              ])
         ~audit:(`Assoc [ ("type", `String "file"); ("path", `String audit_path) ])
         ())
  in
  let b =
    start_proxy ~name:"cert" ~tmp
      (config ~tmp
         ~tls:
           (`Assoc
              [
                ("cert", cert "server.pem");
                ("key", cert "server.key");
                ("client_ca", cert "ca.pem");
                ("client_auth", `String "require");
              ])
         ~auth:
           (Some
              (`Assoc
                 [
                   ("method", `String "cert");
                   ( "identities",
                     `List
                       [
                         `Assoc
                           [
                             ("spiffe_id", `String "spiffe://haltsql.test/agent");
                             ("policy", `String "proxy-test");
                             ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                           ];
                       ] );
                 ]))
         ())
  in
  let c =
    start_proxy ~name:"limits" ~tmp
      (config ~tmp
         ~limits:
           (`Assoc [ ("max_connections", `Int 1); ("idle_timeout_seconds", `Int 1) ])
         ())
  in
  let d =
    start_proxy ~name:"uptls" ~tmp
      (config ~tmp ~upstream_extra:[ ("tls", `Assoc [ ("mode", `String "require") ]) ] ())
  in
  let proxies = [ a; b; c; d ] in
  let env =
    [|
      Printf.sprintf "PROXY_PORT=%d" (snd a).port;
      Printf.sprintf "CERT_PROXY_PORT=%d" (snd b).port;
      "PROXY_DB=" ^ db;
      "CERT_DIR=" ^ certs;
      "AGENT_PASSWORD=" ^ agent_pw;
      "AGENT2_PASSWORD=" ^ agent2_pw;
    |]
  in
  let results =
    match run_capture ~env [| py; "pgclient.py"; "scenarios" |] with
    | Unix.WEXITED 0, out, _ -> Yojson.Safe.from_string out
    | _, o, e -> failwith ("scenarios failed: " ^ o ^ e)
  in
  let raw = raw_scenarios ~a:(snd a).port ~c:(snd c).port ~d:(snd d).port in
  let exits = List.map stop_proxy proxies in
  ignore (run_capture [| py; "pgclient.py"; "teardown"; db |]);
  {
    tmp;
    py;
    proxies;
    results;
    raw;
    exits;
    audit = (try read_file audit_path with _ -> "");
  }

(* ------------------------------------------------------------- checks *)

let env = lazy (setup ())
let get () = Lazy.force env

let path keys =
  List.fold_left
    (fun j k ->
      match j with
      | `Assoc kv -> Option.value ~default:`Null (List.assoc_opt k kv)
      | _ -> `Null)
    (get ()).results keys

let json_eq name expected keys =
  let got = path keys in
  let exp = Yojson.Safe.from_string expected in
  if not (Yojson.Safe.equal exp got) then
    Alcotest.failf "%s: expected %s, got %s" name (Yojson.Safe.to_string exp)
      (Yojson.Safe.to_string got)

let str keys = match path keys with `String s -> s | j -> Yojson.Safe.to_string j
let acme = {|[[1,"acme"],[2,"acme"],[3,"acme"]]|}
let raw name = Option.value ~default:"<missing>" (List.assoc_opt name (get ()).raw)
let check_raw name expected () = Alcotest.(check string) name expected (raw name)

let check_contains name sub s =
  if not (contains s sub) then Alcotest.failf "%s: %S does not contain %S" name s sub

let t_simple () =
  json_eq "allowed rows" {|[["EUR"],["USD"]]|} [ "simple"; "allowed"; "rows" ];
  json_eq "denied sqlstate" {|"42501"|} [ "simple"; "denied"; "sqlstate" ];
  json_eq "denied severity" {|"ERROR"|} [ "simple"; "denied"; "severity" ];
  json_eq "denied detail" {|"HaltSQL reasons: E_COLUMN_DENIED"|}
    [ "simple"; "denied"; "detail" ];
  check_contains "denied message"
    "haltsql: query denied by policy \"proxy-test\": column email"
    (str [ "simple"; "denied"; "primary" ]);
  check_contains "hint" "readable columns of app.users"
    (str [ "simple"; "denied"; "hint" ]);
  json_eq "usable after deny" {|[["EUR"]]|} [ "simple"; "after_deny"; "rows" ];
  json_eq "bound tenancy in simple protocol" {|"HaltSQL reasons: E_PARAM_UNBOUND"|}
    [ "simple"; "bound_in_simple"; "detail" ];
  json_eq "multi statement" {|"HaltSQL reasons: E_MULTI_STATEMENT"|}
    [ "simple"; "multi"; "detail" ];
  json_eq "connection ok" "true" [ "simple"; "connection_ok" ]

let t_extended () =
  json_eq "unnamed, client asks for globex" acme [ "extended"; "unnamed_other_tenant" ];
  json_eq "named statement" acme [ "extended"; "named" ];
  json_eq "named, injection attempt in param" acme [ "extended"; "named_injection" ];
  json_eq "named, NULL tenant" acme [ "extended"; "named_null" ];
  json_eq "second tenant asks for acme" {|[[4,"globex"],[5,"globex"],[6,"globex"]]|}
    [ "extended_tenant2"; "rows" ]

let t_extended_denied () =
  json_eq "error class" {|"InsufficientPrivilege"|}
    [ "extended_denied"; "denied"; "error" ];
  json_eq "sqlstate" {|"42501"|} [ "extended_denied"; "denied"; "sqlstate" ];
  json_eq "detail" {|"HaltSQL reasons: E_COLUMN_DENIED"|}
    [ "extended_denied"; "denied"; "detail" ];
  json_eq "usable after deny" acme [ "extended_denied"; "after" ]

let t_transaction () =
  json_eq "first" acme [ "transaction"; "first" ];
  json_eq "denied" {|"42501"|} [ "transaction"; "denied"; "sqlstate" ];
  json_eq "transaction aborted like Postgres" {|"INERROR"|}
    [ "transaction"; "status_after_deny" ];
  json_eq "after rollback" acme [ "transaction"; "again" ]

let t_pipeline () =
  json_eq "pipelined statements"
    (Printf.sprintf "[%s,%s,%s]" acme acme acme)
    [ "pipeline"; "rows" ];
  json_eq "pipeline deny sqlstate" {|"42501"|}
    [ "pipeline_denied"; "outcome"; "sqlstate" ];
  json_eq "pipeline deny detail" {|"HaltSQL reasons: E_COLUMN_DENIED"|}
    [ "pipeline_denied"; "outcome"; "detail" ];
  json_eq "usable after pipeline deny" acme [ "pipeline_denied"; "after" ]

let t_copy () =
  json_eq "COPY denied" {|"42501"|} [ "copy"; "copy"; "sqlstate" ];
  json_eq "COPY reason" {|"HaltSQL reasons: E_STATEMENT_KIND"|}
    [ "copy"; "copy"; "detail" ];
  json_eq "usable after COPY deny" acme [ "copy"; "after" ]

let t_cancel () =
  json_eq "plain cancel" {|"57014"|} [ "cancel"; "outcome"; "sqlstate" ];
  json_eq "cancel was prompt" "true" [ "cancel"; "elapsed_lt_4s" ];
  json_eq "usable after cancel" acme [ "cancel"; "after" ];
  json_eq "cancel over TLS" {|"57014"|} [ "tls_cancel"; "outcome"; "sqlstate" ]

let t_tls () =
  json_eq "ssl in use" "true" [ "tls"; "ssl_in_use" ];
  json_eq "rows over TLS" acme [ "tls"; "rows" ]

let t_auth_failures () =
  check_contains "bad password"
    "FATAL:  password authentication failed for user \"agent\""
    (str [ "bad_password"; "message" ]);
  check_contains "unknown user (same message)"
    "FATAL:  password authentication failed for user \"mallory\""
    (str [ "unknown_user"; "message" ]);
  check_contains "wrong database" "FATAL:  database \"postgres\" does not exist"
    (str [ "wrong_database"; "message" ]);
  check_contains "replication"
    "replication connections are not allowed through haltsql-proxy"
    (str [ "replication"; "message" ])

let t_cert () =
  json_eq "cert identity -> acme policy" acme [ "cert_ok"; "rows" ];
  json_eq "cert over TLS" "true" [ "cert_ok"; "ssl_in_use" ];
  check_contains "plaintext refused" "haltsql-proxy requires an SSL/TLS connection"
    (str [ "cert_plaintext"; "message" ]);
  check_contains "missing client cert" "alert bad certificate"
    (str [ "cert_missing"; "message" ]);
  check_contains "untrusted client cert" "alert bad certificate"
    (str [ "cert_rogue"; "message" ])

let t_audit () =
  let a = (get ()).audit in
  let lines = List.filter (fun l -> l <> "") (String.split_on_char '\n' a) in
  let records = List.map Yojson.Safe.from_string lines in
  let field k = function `Assoc kv -> List.assoc_opt k kv | _ -> None in
  let denied_email =
    List.exists
      (fun r ->
        field "allowed" r = Some (`Bool false)
        && field "reasons" r = Some (`List [ `String "E_COLUMN_DENIED" ])
        && field "user" r = Some (`String "agent")
        && field "policy" r = Some (`String "proxy-test"))
      records
  in
  Alcotest.(check bool) "denial audited" true denied_email;
  Alcotest.(check bool)
    "no raw SQL by default" false
    (List.exists (fun r -> field "sql" r <> None) records);
  Alcotest.(check bool)
    "every record hashed" true
    (List.for_all
       (fun r ->
         field "event" r <> Some (`String "statement") || field "sql_sha256" r <> None)
       records)

let t_no_secrets_in_logs () =
  List.iter
    (fun (name, p) ->
      let log = read_file p.log in
      List.iter
        (fun secret ->
          if contains log secret then Alcotest.failf "proxy %s log leaks %S" name secret)
        [
          agent_pw;
          agent2_pw;
          upstream_pw;
          "HTSECRET";
          "BEGIN PRIVATE KEY";
          "SCRAM-SHA-256$";
        ])
    (get ()).proxies

let t_shutdown () =
  List.iter
    (fun (name, st) ->
      match st with
      | Unix.WEXITED 0 -> ()
      | Unix.WEXITED n -> Alcotest.failf "proxy %s exited %d" name n
      | _ -> Alcotest.failf "proxy %s killed" name)
    (get ()).exits

let () =
  match skip_reason with
  | Some reason ->
      Printf.printf "SKIP haltsql-proxy integration tests: %s\n%!" reason;
      Alcotest.run "proxy-integration"
        [
          ( "environment",
            [ Alcotest.test_case reason `Quick (fun () -> Alcotest.skip ()) ] );
        ]
  | None ->
      at_exit (fun () ->
          if Lazy.is_val env then
            ignore (run_capture [| (get ()).py; "pgclient.py"; "teardown"; db |]));
      Alcotest.run "proxy-integration"
        [
          ( "psycopg",
            [
              Alcotest.test_case "simple query protocol" `Quick t_simple;
              Alcotest.test_case "extended: tenancy overwrite" `Quick t_extended;
              Alcotest.test_case "extended: deny + reuse" `Quick t_extended_denied;
              Alcotest.test_case "transactions" `Quick t_transaction;
              Alcotest.test_case "pipeline mode" `Quick t_pipeline;
              Alcotest.test_case "COPY denied" `Quick t_copy;
              Alcotest.test_case "cancel request" `Quick t_cancel;
              Alcotest.test_case "TLS" `Quick t_tls;
              Alcotest.test_case "authentication failures" `Quick t_auth_failures;
              Alcotest.test_case "client certificate auth" `Quick t_cert;
            ] );
          ( "raw-protocol",
            [
              Alcotest.test_case "GSSENCRequest refused" `Quick
                (check_raw "gssenc" "N then login ok");
              Alcotest.test_case "function call denied" `Quick
                (check_raw "function_call"
                   "E:42501 Z [HaltSQL reasons: PROXY_FUNCTION_CALL] | T D C Z");
              Alcotest.test_case "COPY data -> FATAL" `Quick
                (check_raw "copy_data" "E:08P01 FATAL eof=true");
              Alcotest.test_case "protocol 2.0 rejected" `Quick
                (check_raw "protocol2" "E:08P01 FATAL");
              Alcotest.test_case "oversized message" `Quick
                (check_raw "oversized" "E:08P01 FATAL");
              Alcotest.test_case "SSLRequest + pipelined plaintext" `Quick
                (check_raw "ssl_pipelined" "E");
              Alcotest.test_case "startup without user" `Quick
                (check_raw "no_user" "E:28000");
              Alcotest.test_case "Bind unknown statement" `Quick
                (check_raw "bind_unknown" "E:26000 Z");
              Alcotest.test_case "duplicate named Parse" `Quick
                (check_raw "duplicate_parse" "1 Z | E:42P05 Z | acme,acme,acme");
              Alcotest.test_case "Parse ignored after error is not trusted" `Quick
                (check_raw "ignored_parse" "1 Z | E:34000 Z | E:26000 Z");
              Alcotest.test_case "binary tenancy param rejected" `Quick
                (check_raw "binary_tenant_param"
                   "1 E:42501 Z [HaltSQL reasons: E_PARAM_UNBOUND]");
              Alcotest.test_case "declared \"char\" type on tenancy param reset" `Quick
                (check_raw "declared_type_char" "1 2 D D D C Z rows=3");
              Alcotest.test_case "declared name type on tenancy param reset" `Quick
                (check_raw "declared_type_name" "1 2 D D D C Z rows=3");
              Alcotest.test_case "declared float8 type on tenancy param reset" `Quick
                (check_raw "declared_type_float8" "1 2 D D D C Z rows=3");
              Alcotest.test_case "max_connections" `Quick
                (check_raw "max_connections" "E:53300");
              Alcotest.test_case "idle timeout" `Quick
                (check_raw "idle_timeout" "E:57P05 FATAL");
              Alcotest.test_case "upstream TLS required but unavailable" `Quick
                (check_raw "upstream_tls_required" "08006");
            ] );
          ( "operations",
            [
              Alcotest.test_case "audit log" `Quick t_audit;
              Alcotest.test_case "no secrets in logs" `Quick t_no_secrets_in_logs;
              Alcotest.test_case "graceful shutdown (SIGTERM -> exit 0)" `Quick t_shutdown;
            ] );
        ]
