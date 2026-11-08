(* haltsql-proxy audit and hot reload, end to end: the real proxy binary in front of the
   lab Postgres 17 (localhost:5417), driven by a raw protocol client.

   - records are hash-chained, also across a restart, and stdout records interleaved
     with logs verify with `haltsql audit verify --mixed`;
   - a file sink that fails (a FIFO whose reader goes away: writes get EPIPE) with
     on_error fail_closed refuses statements with SQLSTATE 58030 until it recovers;
     buffer mode keeps serving, refuses at the bound and drains in order; drop mode
     keeps serving and logs every drop;
   - SIGHUP swaps the policy for new sessions only and keeps the last good config on a
     broken one; reload.watch does the same on file changes;
   - an S3 sink writes to a REAL MinIO container (haltsql-audit-minio-proxy, host port
     16002-16003) and the objects verify (skipped without Docker / a MinIO image).

   Database: haltsql_audit_proxy (created and dropped here). Skips cleanly when
   Postgres or lab/.venv (used to load the fixture schema) is unavailable. *)

open Haltsql_pgwire
module Chain = Haltsql_cloud.Audit_chain

let db = "haltsql_audit_proxy"
let pg_port = 5417
let agent_pw = "agent-pass-audit-1"
let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p
let proxy_bin = Option.map absolute (Sys.getenv_opt "HALTSQL_PROXY_BIN")
let audit_cli = Option.map absolute (Sys.getenv_opt "HALTSQL_AUDIT_CLI")
let upstream_pw = Option.value ~default:"haltlab" (Sys.getenv_opt "HALTSQL_PGPASSWORD")

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

let rec restart_on_eintr f =
  try f () with Unix.Unix_error (Unix.EINTR, _, _) -> restart_on_eintr f

let tcp_open port =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Fun.protect
    ~finally:(fun () -> try Unix.close fd with _ -> ())
    (fun () ->
      try
        Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, port));
        true
      with _ -> false)

let free_port () =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind fd (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p =
    match Unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> assert false
  in
  Unix.close fd;
  p

let read_file path = try In_channel.with_open_bin path In_channel.input_all with _ -> ""

let write_file path s =
  Out_channel.with_open_gen [ Open_wronly; Open_creat; Open_trunc ] 0o600 path (fun oc ->
      Out_channel.output_string oc s)

(* what editors and config management do: the watcher never sees a half-written file *)
let replace_file path s =
  let tmp = path ^ ".tmp" in
  write_file tmp s;
  Unix.rename tmp path

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let count_sub s sub =
  let n = String.length s and m = String.length sub in
  let rec go i acc =
    if i + m > n then acc
    else if String.sub s i m = sub then go (i + m) (acc + 1)
    else go (i + 1) acc
  in
  go 0 0

let run_capture ?(env = [||]) argv =
  let env = Array.append (Unix.environment ()) env in
  let ic, oc, ec = Unix.open_process_args_full argv.(0) argv env in
  close_out oc;
  let out = In_channel.input_all ic in
  let err = In_channel.input_all ec in
  let st = restart_on_eintr (fun () -> Unix.close_process_full (ic, oc, ec)) in
  (st, out, err)

let lines s = List.filter (fun l -> String.trim l <> "") (String.split_on_char '\n' s)

let wait_until ?(timeout = 10.) what f =
  let deadline = Unix.gettimeofday () +. timeout in
  let rec go () =
    if f () then ()
    else if Unix.gettimeofday () > deadline then
      Alcotest.failf "timed out waiting for %s" what
    else (
      Unix.sleepf 0.05;
      go ())
  in
  go ()

(* ---------------------------------------------------- environment check *)

let skip_reason =
  match (proxy_bin, python) with
  | None, _ -> Some "HALTSQL_PROXY_BIN not set (run via dune test)"
  | _, None -> Some "lab/.venv/bin/python not found (make -C lab venv)"
  | _, Some py -> (
      if not (tcp_open pg_port) then
        Some "lab Postgres not reachable on localhost:5417 (make -C lab up)"
      else
        match run_capture [| py; "-c"; "import psycopg" |] with
        | Unix.WEXITED 0, _, _ -> None
        | _ -> Some "psycopg is not installed in lab/.venv"
        | exception _ -> Some "cannot run lab/.venv/bin/python")

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
    (tag, really_input_string t.ic (len - 4))

  let close t = try Unix.close t.fd with _ -> ()

  let rec until_z t acc =
    match read t with ('Z', _) as m -> List.rev (m :: acc) | m -> until_z t (m :: acc)

  let login port =
    let t = connect port in
    send t (Wire.encode_startup [ ("user", "agent"); ("database", db) ]);
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
              let st, fin = Result.get_ok (Scram.Client.final st ~password:agent_pw d) in
              send t (Wire.sasl_response fin);
              auth (Some st)
          | Wire.Auth_sasl_final _, Some _ -> auth None
          | _ -> failwith "unexpected auth message")
      | 'E' -> failwith "login failed"
      | c -> failwith (Printf.sprintf "unexpected %C during login" c)
    in
    auth None;
    ignore (until_z t []);
    t

  let field c p = Option.value ~default:"" (List.assoc_opt c (Wire.decode_fields p))

  (* "ok:<rows>" or "E:<sqlstate>" *)
  let query t sql =
    send t (Wire.frame 'Q' (sql ^ "\000"));
    let msgs = until_z t [] in
    match List.find_opt (fun (tag, _) -> tag = 'E') msgs with
    | Some (_, p) -> "E:" ^ field 'C' p
    | None ->
        Printf.sprintf "ok:%d"
          (List.length (List.filter (fun (tag, _) -> tag = 'D') msgs))

  let query_msg t sql =
    send t (Wire.frame 'Q' (sql ^ "\000"));
    match List.find_opt (fun (tag, _) -> tag = 'E') (until_z t []) with
    | Some (_, p) -> field 'M' p
    | None -> ""
end

let q_currencies = "SELECT code FROM app.currencies ORDER BY code LIMIT 10"
let q_denied = "SELECT email FROM app.users LIMIT 1"

(* ------------------------------------------------------------ proxies *)

type proxy = { pid : int; port : int; log : string; cfg_path : string }

let fixture_policy = absolute "fixtures/policy.yaml"

let policy_without_currencies () =
  let p = read_file fixture_policy in
  let drop = "  app.currencies:\n    columns: \"*\"\n" in
  let i =
    let n = String.length p and m = String.length drop in
    let rec go i =
      if i + m > n then failwith "fixture changed"
      else if String.sub p i m = drop then i
      else go (i + 1)
    in
    go 0
  in
  String.sub p 0 i
  ^ String.sub p (i + String.length drop) (String.length p - i - String.length drop)

let config ~policy ?(audit = `Assoc [ ("type", `String "none") ]) ?(extra = []) () :
    Yojson.Safe.t =
  `Assoc
    ([
       ("apiVersion", `String "haltsql.dev/v1");
       ("kind", `String "ProxyConfig");
       ( "upstream",
         `Assoc
           [
             ("host", `String "127.0.0.1");
             ("port", `Int pg_port);
             ("database", `String db);
             ("user", `String "postgres");
             ("password", `String "${env:PROXY_UPSTREAM_PW}");
           ] );
       ("policies", `List [ `Assoc [ ("path", `String policy) ] ]);
       ( "auth",
         `Assoc
           [
             ("method", `String "scram");
             ( "users",
               `List
                 [
                   `Assoc
                     [
                       ("name", `String "agent");
                       ( "scram_verifier",
                         `String (Scram.verifier_to_string (Scram.make_verifier agent_pw))
                       );
                       ("policy", `String "proxy-test");
                       ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                     ];
                 ] );
           ] );
       ("logging", `Assoc [ ("level", `String "info") ]);
       ("shutdown_grace_seconds", `Int 2);
       ("audit", audit);
     ]
    @ extra)

let start_proxy ?(env = [||]) ~tmp name cfg =
  let bin = Option.get proxy_bin in
  let port = free_port () in
  let cfg_path = Filename.concat tmp (name ^ ".json") in
  write_file cfg_path (Yojson.Safe.to_string cfg);
  let log = Filename.concat tmp (name ^ ".log") in
  let out = Unix.openfile log [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o600 in
  let devnull = Unix.openfile "/dev/null" [ Unix.O_RDWR ] 0 in
  let env =
    Array.concat [ Unix.environment (); [| "PROXY_UPSTREAM_PW=" ^ upstream_pw |]; env ]
  in
  let pid =
    Unix.create_process_env bin
      [| bin; "run"; "-c"; cfg_path; "--listen"; Printf.sprintf "127.0.0.1:%d" port |]
      env devnull out out
  in
  Unix.close out;
  Unix.close devnull;
  let deadline = Unix.gettimeofday () +. 15. in
  let rec wait () =
    if tcp_open port then ()
    else
      match Unix.waitpid [ Unix.WNOHANG ] pid with
      | p, _ when p = pid ->
          failwith (Printf.sprintf "proxy %s exited: %s" name (read_file log))
      | _ ->
          if Unix.gettimeofday () > deadline then
            failwith (Printf.sprintf "proxy %s did not start: %s" name (read_file log))
          else (
            Unix.sleepf 0.05;
            wait ())
  in
  wait ();
  { pid; port; log; cfg_path }

let stop_proxy p =
  (try Unix.kill p.pid Sys.sigterm with Unix.Unix_error _ -> ());
  let deadline = Unix.gettimeofday () +. 20. in
  let rec wait () =
    match restart_on_eintr (fun () -> Unix.waitpid [ Unix.WNOHANG ] p.pid) with
    | 0, _ when Unix.gettimeofday () < deadline ->
        Unix.sleepf 0.05;
        wait ()
    | 0, _ ->
        Unix.kill p.pid Sys.sigkill;
        snd (restart_on_eintr (fun () -> Unix.waitpid [] p.pid))
    | _, st -> st
    | exception Unix.Unix_error (Unix.ECHILD, _, _) -> Unix.WEXITED 0
  in
  wait ()

let with_proxy ?env ~tmp name cfg f =
  let p = start_proxy ?env ~tmp name cfg in
  Fun.protect ~finally:(fun () -> ignore (stop_proxy p)) (fun () -> f p)

let run_cli args =
  match audit_cli with
  | None -> Alcotest.skip ()
  | Some bin ->
      let st, out, _ = run_capture (Array.of_list (bin :: "audit" :: "verify" :: args)) in
      ((match st with Unix.WEXITED c -> c | _ -> -1), out)

let check_chain name ls n =
  match Chain.verify_lines ls with
  | Ok k -> Alcotest.(check int) (name ^ ": records") n k
  | Error (line, m) -> Alcotest.failf "%s: chain broken at line %d: %s" name line m

(* ------------------------------------------------------------- FIFOs *)

(* A FIFO sink: the proxy's writes fail with EPIPE while no reader is open, and work
   again once one is. *)
module Fifo = struct
  let create dir name =
    let p = Filename.concat dir name in
    Unix.mkfifo p 0o600;
    p

  (* CLOEXEC: a proxy started later must not inherit a read end *)
  let open_reader p = Unix.openfile p [ Unix.O_RDONLY; Unix.O_NONBLOCK; Unix.O_CLOEXEC ] 0

  (* everything currently in the pipe *)
  let drain fd =
    let b = Buffer.create 4096 and chunk = Bytes.create 65536 in
    let rec go () =
      match Unix.read fd chunk 0 (Bytes.length chunk) with
      | 0 -> ()
      | n ->
          Buffer.add_subbytes b chunk 0 n;
          go ()
      | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) -> ()
    in
    go ();
    Buffer.contents b

  (* drain until [n] complete lines arrived *)
  let read_lines fd n =
    let acc = Buffer.create 4096 in
    wait_until (Printf.sprintf "%d audit lines" n) (fun () ->
        Buffer.add_string acc (drain fd);
        List.length (lines (Buffer.contents acc)) >= n);
    lines (Buffer.contents acc)
end

(* ------------------------------------------------------------ fixture *)

let tmp = lazy (Filename.temp_dir "haltsql_proxy_audit" "")

let setup =
  lazy
    (Sec.init_rng ();
     let py = Option.get python in
     (match run_capture [| py; "pgclient.py"; "setup"; db |] with
     | Unix.WEXITED 0, _, _ -> ()
     | _, o, e -> failwith ("database setup failed: " ^ o ^ e));
     at_exit (fun () -> ignore (run_capture [| py; "pgclient.py"; "teardown"; db |])))

let get_tmp () =
  Lazy.force setup;
  Lazy.force tmp

(* ------------------------------------------------------------- tests *)

let t_chained_file () =
  let tmp = get_tmp () in
  let path = Filename.concat tmp "chain.jsonl" in
  let cfg =
    config ~policy:fixture_policy
      ~audit:
        (`Assoc
           [
             ( "sinks",
               `List [ `Assoc [ ("type", `String "file"); ("path", `String path) ] ] );
           ])
      ()
  in
  with_proxy ~tmp "chain1" cfg (fun p ->
      let c = Raw.login p.port in
      Alcotest.(check string) "allowed" "ok:2" (Raw.query c q_currencies);
      Alcotest.(check string) "denied" "E:42501" (Raw.query c q_denied);
      Alcotest.(check string) "allowed again" "ok:2" (Raw.query c q_currencies);
      Raw.close c);
  (* a restart continues the file's chain *)
  with_proxy ~tmp "chain2" cfg (fun p ->
      let c = Raw.login p.port in
      Alcotest.(check string) "after restart" "ok:2" (Raw.query c q_currencies);
      Raw.close c);
  let ls = lines (read_file path) in
  check_chain "file sink" ls 4;
  let first = Yojson.Safe.from_string (List.hd ls) in
  Alcotest.(check bool)
    "starts at genesis" true
    (Yojson.Safe.Util.(member "prev_hash" first) = `String Chain.genesis);
  let code, out = run_cli [ path ] in
  Alcotest.(check int) "haltsql audit verify: exit 0" 0 code;
  Alcotest.(check bool) "4 records" true (contains out "OK, 4 records")

let t_stdout_mixed_log () =
  let tmp = get_tmp () in
  let p =
    start_proxy ~tmp "stdout"
      (config ~policy:fixture_policy ~audit:(`Assoc [ ("type", `String "stdout") ]) ())
  in
  let c = Raw.login p.port in
  for _ = 1 to 3 do
    ignore (Raw.query c q_currencies)
  done;
  ignore (Raw.query c q_denied);
  Raw.close c;
  ignore (stop_proxy p);
  (* stdout (audit) and stderr (logs) went to one file, like `kubectl logs` *)
  let code, out = run_cli [ "--mixed"; p.log ] in
  Alcotest.(check int) "--mixed: exit 0" 0 code;
  Alcotest.(check bool) "4 records" true (contains out "OK, 4 records");
  let code, _ = run_cli [ p.log ] in
  Alcotest.(check int) "without --mixed: exit 1" 1 code

let fifo_cfg path on_error extra =
  config ~policy:fixture_policy
    ~audit:
      (`Assoc
         [
           ( "sinks",
             `List
               [
                 `Assoc
                   ([
                      ("type", `String "file");
                      ("path", `String path);
                      ("on_error", `String on_error);
                    ]
                   @ extra);
               ] );
         ])
    ()

let t_fail_closed () =
  let tmp = get_tmp () in
  let fifo = Fifo.create tmp "fail.fifo" in
  let r1 = Fifo.open_reader fifo in
  with_proxy ~tmp "failclosed" (fifo_cfg fifo "fail_closed" []) (fun p ->
      let c = Raw.login p.port in
      Alcotest.(check string) "healthy sink" "ok:2" (Raw.query c q_currencies);
      let got1 = Fifo.read_lines r1 1 in
      Unix.close r1;
      (* the sink fails: statements are refused, the connection stays usable *)
      Alcotest.(check string) "refused" "E:58030" (Raw.query c q_currencies);
      Alcotest.(check bool)
        "message" true
        (contains (Raw.query_msg c q_currencies) "audit log could not be written");
      Alcotest.(check string) "denials too" "E:58030" (Raw.query c q_denied);
      let c2 = Raw.login p.port in
      Alcotest.(check string) "new sessions too" "E:58030" (Raw.query c2 q_currencies);
      (* the sink recovers: statements flow again *)
      let r2 = Fifo.open_reader fifo in
      Alcotest.(check string) "recovered" "ok:2" (Raw.query c q_currencies);
      Alcotest.(check string) "recovered (2)" "ok:2" (Raw.query c2 q_currencies);
      let got2 = Fifo.read_lines r2 2 in
      Raw.close c;
      Raw.close c2;
      check_chain "fail_closed stream" (got1 @ got2) 3;
      Alcotest.(check bool)
        "refusal logged" true
        (contains (read_file p.log) "statement refused: audit log unavailable");
      ignore (stop_proxy p);
      Unix.close r2)

let t_buffer () =
  let tmp = get_tmp () in
  let fifo = Fifo.create tmp "buffer.fifo" in
  let r1 = Fifo.open_reader fifo in
  with_proxy ~tmp "buffer"
    (fifo_cfg fifo "buffer" [ ("max_buffer_records", `Int 2) ])
    (fun p ->
      let c = Raw.login p.port in
      Alcotest.(check string) "healthy" "ok:2" (Raw.query c q_currencies);
      let got1 = Fifo.read_lines r1 1 in
      Unix.close r1;
      Alcotest.(check string) "buffered 1" "ok:2" (Raw.query c q_currencies);
      Alcotest.(check string) "buffered 2" "E:42501" (Raw.query c q_denied);
      (* the buffer is full: fail closed *)
      Alcotest.(check string) "buffer full" "E:58030" (Raw.query c q_currencies);
      let r2 = Fifo.open_reader fifo in
      (* the background retry drains the buffer in order without new traffic *)
      let drained = Fifo.read_lines r2 2 in
      Alcotest.(check string) "recovered" "ok:2" (Raw.query c q_currencies);
      let got2 = drained @ Fifo.read_lines r2 1 in
      Raw.close c;
      check_chain "buffer stream" (got1 @ got2) 4;
      let log = read_file p.log in
      Alcotest.(check bool) "buffering logged" true (contains log "record buffered");
      Alcotest.(check bool) "drain logged" true (contains log "buffer drained");
      ignore (stop_proxy p);
      Unix.close r2)

let t_drop () =
  let tmp = get_tmp () in
  let fifo = Fifo.create tmp "drop.fifo" in
  let r1 = Fifo.open_reader fifo in
  with_proxy ~tmp "drop" (fifo_cfg fifo "drop" []) (fun p ->
      let c = Raw.login p.port in
      Alcotest.(check string) "healthy" "ok:2" (Raw.query c q_currencies);
      let got1 = Fifo.read_lines r1 1 in
      Unix.close r1;
      Alcotest.(check string) "dropped, still served" "ok:2" (Raw.query c q_currencies);
      let r2 = Fifo.open_reader fifo in
      Alcotest.(check string) "after" "ok:2" (Raw.query c q_currencies);
      let got2 = Fifo.read_lines r2 1 in
      Raw.close c;
      (* the dropped record was never sealed: the chain stays intact *)
      check_chain "drop stream" (got1 @ got2) 2;
      Alcotest.(check bool)
        "drop logged" true
        (contains (read_file p.log) "record dropped");
      ignore (stop_proxy p);
      Unix.close r2)

let t_sighup_reload () =
  let tmp = get_tmp () in
  let policy = Filename.concat tmp "hup-policy.yaml" in
  write_file policy (read_file fixture_policy);
  with_proxy ~tmp "sighup" (config ~policy ()) (fun p ->
      let old = Raw.login p.port in
      Alcotest.(check string) "policy A" "ok:2" (Raw.query old q_currencies);
      (* policy B: app.currencies is no longer allowed *)
      replace_file policy (policy_without_currencies ());
      Unix.kill p.pid Sys.sighup;
      wait_until "config reloaded" (fun () ->
          contains (read_file p.log) "\"msg\":\"config reloaded\"");
      let fresh = Raw.login p.port in
      Alcotest.(check string)
        "new session: policy B" "E:42501"
        (Raw.query fresh q_currencies);
      Alcotest.(check string)
        "old session keeps policy A" "ok:2" (Raw.query old q_currencies);
      (* a broken config is rejected; policy B stays in force *)
      replace_file policy "this: is: not: a policy\n";
      Unix.kill p.pid Sys.sighup;
      wait_until "config reload failed" (fun () ->
          contains (read_file p.log) "config reload failed");
      let after = Raw.login p.port in
      Alcotest.(check string)
        "after a bad reload: policy B" "E:42501"
        (Raw.query after q_currencies);
      Alcotest.(check string)
        "old session still policy A" "ok:2" (Raw.query old q_currencies);
      let log = read_file p.log in
      Alcotest.(check bool)
        "counters" true
        (contains log "\"reloads\":1,\"reload_failures\":1");
      Alcotest.(check bool)
        "generation in session log" true
        (contains log "\"config_generation\":2");
      List.iter Raw.close [ old; fresh; after ])

let t_watch_reload () =
  let tmp = get_tmp () in
  let policy = Filename.concat tmp "watch-policy.yaml" in
  write_file policy (read_file fixture_policy);
  let cfg =
    config ~policy
      ~extra:
        [
          ( "reload",
            `Assoc [ ("watch", `Bool true); ("poll_interval_seconds", `Float 0.2) ] );
        ]
      ()
  in
  with_proxy ~tmp "watch" cfg (fun p ->
      let old = Raw.login p.port in
      Alcotest.(check string) "policy A" "ok:2" (Raw.query old q_currencies);
      replace_file policy (policy_without_currencies ());
      wait_until "watch reload" (fun () ->
          contains (read_file p.log) "\"trigger\":\"watch\"");
      let fresh = Raw.login p.port in
      Alcotest.(check string)
        "new session: policy B" "E:42501"
        (Raw.query fresh q_currencies);
      Alcotest.(check string) "old session: policy A" "ok:2" (Raw.query old q_currencies);
      (* an invalid edit is logged once and ignored *)
      replace_file policy "kind: Policy\n";
      wait_until "watch reload failure" (fun () ->
          contains (read_file p.log) "config reload failed");
      Unix.sleepf 0.6;
      Alcotest.(check int)
        "failure logged once" 1
        (count_sub (read_file p.log) "config reload failed");
      let after = Raw.login p.port in
      Alcotest.(check string) "still policy B" "E:42501" (Raw.query after q_currencies);
      (* a fixed edit applies *)
      replace_file policy (read_file fixture_policy);
      wait_until "second watch reload" (fun () ->
          count_sub (read_file p.log) "\"msg\":\"config reloaded\"" >= 2);
      let back = Raw.login p.port in
      Alcotest.(check string) "policy A again" "ok:2" (Raw.query back q_currencies);
      List.iter Raw.close [ old; fresh; after; back ])

let t_reload_keeps_audit_sinks () =
  let tmp = get_tmp () in
  let path = Filename.concat tmp "keep.jsonl" in
  let other = Filename.concat tmp "other.jsonl" in
  let file_audit f = `Assoc [ ("type", `String "file"); ("path", `String f) ] in
  with_proxy ~tmp "keepsinks"
    (config ~policy:fixture_policy ~audit:(file_audit path) ())
    (fun p ->
      replace_file p.cfg_path
        (Yojson.Safe.to_string
           (config ~policy:fixture_policy ~audit:(file_audit other) ()));
      Unix.kill p.pid Sys.sighup;
      wait_until "reload" (fun () ->
          contains (read_file p.log) "\"msg\":\"config reloaded\"");
      Alcotest.(check bool)
        "warned" true
        (contains (read_file p.log) "audit sink changes need a restart");
      let c = Raw.login p.port in
      ignore (Raw.query c q_currencies);
      Raw.close c;
      Alcotest.(check bool)
        "still the original file" true
        (Sys.file_exists path && not (Sys.file_exists other));
      check_chain "kept sink" (lines (read_file path)) 1)

(* ---------------------------------------------------------- MinIO / S3 *)

module Minio = struct
  let container = "haltsql-audit-minio-proxy"
  let port = 16002
  let console = 16003
  let endpoint = Printf.sprintf "http://127.0.0.1:%d" port
  let user = "haltsqlproxy"
  let secret = "haltsql-proxy-minio-test-only"
  let bucket = "proxy-audit"
  let quiet cmd = Unix.system (cmd ^ " >/dev/null 2>&1") = Unix.WEXITED 0

  let image () =
    (match Sys.getenv_opt "HALTSQL_MINIO_IMAGE" with Some i -> [ i ] | None -> [])
    @ [ "minio/minio:latest"; "pgsty/minio:latest" ]
    |> List.find_opt (fun i -> quiet ("docker image inspect " ^ Filename.quote i))

  let creds =
    {
      Haltsql_cloud.Sigv4.access_key_id = user;
      secret_access_key = secret;
      session_token = None;
    }

  let request meth path =
    let uri = Uri.of_string (endpoint ^ path) in
    let headers =
      Haltsql_cloud.Sigv4.sign ~s3:true creds ~service:"s3" ~region:"us-east-1"
        ~time:(Unix.gettimeofday ())
        ~meth:(Cohttp.Code.string_of_method meth)
        ~uri ~headers:[] ~payload:""
    in
    Lwt_main.run (Haltsql_cloud.Http.request ~timeout:5. ~headers meth uri)

  let healthy () =
    match
      Lwt_main.run
        (Haltsql_cloud.Http.request ~timeout:2. `GET
           (Uri.of_string (endpoint ^ "/minio/health/live")))
    with
    | Ok r -> r.status = 200
    | Error _ -> false

  let start =
    lazy
      (if List.mem (Sys.getenv_opt "HALTSQL_SKIP_DOCKER") [ Some "1"; Some "true"; Some "yes" ]
       then Error "HALTSQL_SKIP_DOCKER is set"
       else if not (quiet "docker info") then Error "Docker is not available"
       else
         match image () with
         | None -> Error "no MinIO image present locally (set HALTSQL_MINIO_IMAGE)"
         | Some img ->
             (* Docker may still be releasing the ports of a previous run: retry *)
             let run () =
               ignore (quiet ("docker rm -f " ^ container));
               quiet
                 (Printf.sprintf
                    "docker run -d --name %s -p 127.0.0.1:%d:9000 -p 127.0.0.1:%d:9001 \
                     -e MINIO_ROOT_USER=%s -e MINIO_ROOT_PASSWORD=%s %s server /data \
                     --console-address :9001"
                    container port console user secret (Filename.quote img))
             in
             let rec attempt n =
               run ()
               || n > 0
                  &&
                  (Unix.sleepf 0.5;
                   attempt (n - 1))
             in
             if not (attempt 20) then Error "docker run failed"
             else (
               at_exit (fun () -> ignore (quiet ("docker rm -f " ^ container)));
               let rec wait n =
                 if healthy () then Ok ()
                 else if n = 0 then Error "MinIO did not become healthy"
                 else (
                   Unix.sleepf 0.25;
                   wait (n - 1))
               in
               match wait 120 with
               | Error e -> Error e
               | Ok () -> (
                   match request `PUT ("/" ^ bucket) with
                   | Ok r when r.status = 200 -> Ok ()
                   | Ok r -> Error (Printf.sprintf "create bucket: HTTP %d" r.status)
                   | Error e -> Error e)))
end

let t_s3_sink () =
  match Lazy.force Minio.start with
  | Error reason ->
      prerr_endline ("SKIP s3 sink: " ^ reason);
      Alcotest.skip ()
  | Ok () -> (
      let tmp = get_tmp () in
      let audit =
        `Assoc
          [
            ( "sinks",
              `List
                [
                  `Assoc
                    [
                      ("type", `String "s3");
                      ("bucket", `String Minio.bucket);
                      ("region", `String "us-east-1");
                      ("endpoint", `String Minio.endpoint);
                      ("prefix", `String "proxy/");
                      ( "batch",
                        `Assoc [ ("max_records", `Int 2); ("max_seconds", `Int 1) ] );
                      ( "credentials",
                        `Assoc
                          [
                            ("source", `String "static");
                            ("access_key_id", `String Minio.user);
                            ("secret_access_key", `String "${env:MINIO_SECRET}");
                          ] );
                    ];
                ] );
          ]
      in
      let p =
        start_proxy
          ~env:[| "MINIO_SECRET=" ^ Minio.secret |]
          ~tmp "s3"
          (config ~policy:fixture_policy ~audit ())
      in
      let c = Raw.login p.port in
      for _ = 1 to 4 do
        ignore (Raw.query c q_currencies)
      done;
      ignore (Raw.query c q_denied);
      Raw.close c;
      (match stop_proxy p with
      | Unix.WEXITED 0 -> ()
      | _ -> Alcotest.failf "proxy did not exit cleanly: %s" (read_file p.log));
      Alcotest.(check bool)
        "secret not logged" false
        (contains (read_file p.log) Minio.secret);
      match audit_cli with
      | None -> Alcotest.skip ()
      | Some bin ->
          let st, out, err =
            run_capture
              ~env:
                [|
                  "AWS_ACCESS_KEY_ID=" ^ Minio.user;
                  "AWS_SECRET_ACCESS_KEY=" ^ Minio.secret;
                  "AWS_EC2_METADATA_DISABLED=true";
                |]
              [|
                bin;
                "audit";
                "verify";
                "--endpoint";
                Minio.endpoint;
                "s3://" ^ Minio.bucket ^ "/proxy/";
              |]
          in
          if st <> Unix.WEXITED 0 then Alcotest.failf "verify failed: %s %s" out err;
          Alcotest.(check bool)
            "5 records in 3 objects" true
            (contains out "OK, 5 records in 3 objects"))

let () =
  let tests =
    match skip_reason with
    | Some r ->
        [ ("skipped", [ Alcotest.test_case r `Quick (fun () -> Alcotest.skip ()) ]) ]
    | None ->
        [
          ( "audit",
            [
              Alcotest.test_case "file sink records are chained (and across a restart)"
                `Quick t_chained_file;
              Alcotest.test_case "stdout records in a mixed log verify" `Quick
                t_stdout_mixed_log;
              Alcotest.test_case "failing sink + fail_closed refuses statements (58030)"
                `Quick t_fail_closed;
              Alcotest.test_case "buffer mode recovers in order" `Quick t_buffer;
              Alcotest.test_case "drop mode keeps serving, logs drops" `Quick t_drop;
              Alcotest.test_case "S3 sink to MinIO verifies" `Quick t_s3_sink;
            ] );
          ( "reload",
            [
              Alcotest.test_case "SIGHUP: new sessions only; bad config kept out" `Quick
                t_sighup_reload;
              Alcotest.test_case "reload.watch" `Quick t_watch_reload;
              Alcotest.test_case "audit sinks are kept across reloads" `Quick
                t_reload_keeps_audit_sinks;
            ] );
        ]
  in
  Alcotest.run "proxy-audit" tests
