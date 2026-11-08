(* Shared helpers for the haltsql-server.siem integration tests: running the real
   products in Docker (skipped cleanly when Docker is unavailable), a throwaway
   test PKI, and chain checks. Never use outside tests. *)

open Lwt.Infix
module Config = Haltsql_load.Config

(* ---- processes ---- *)

let read_all ic =
  let b = Buffer.create 4096 in
  (try
     while true do
       Buffer.add_channel b ic 1
     done
   with End_of_file -> ());
  Buffer.contents b

(* Runs argv (no shell), returns (exit code, stdout+stderr). *)
let run_cmd argv =
  let out_r, out_w = Unix.pipe ~cloexec:true () in
  let devnull = Unix.openfile "/dev/null" [ Unix.O_RDONLY ] 0 in
  let pid = Unix.create_process argv.(0) argv devnull out_w out_w in
  Unix.close out_w;
  Unix.close devnull;
  let ic = Unix.in_channel_of_descr out_r in
  let out = read_all ic in
  close_in ic;
  let rec wait () =
    match Unix.waitpid [] pid with
    | _, Unix.WEXITED c -> c
    | _, (Unix.WSIGNALED _ | Unix.WSTOPPED _) -> 255
    | exception Unix.Unix_error (Unix.EINTR, _, _) -> wait ()
  in
  (wait (), out)

let docker args = run_cmd (Array.of_list ("docker" :: args))

let docker_ok args =
  match docker args with
  | 0, out -> out
  | c, out ->
      failwith
        (Printf.sprintf "docker %s failed (%d): %s" (String.concat " " args) c
           (String.trim out))

let docker_available =
  lazy
    (match
       (Sys.getenv_opt "HALTSQL_SIEM_SKIP_DOCKER", Sys.getenv_opt "HALTSQL_SKIP_DOCKER")
     with
    | Some ("1" | "true"), _ | _, Some ("1" | "true" | "yes") ->
        Error "HALTSQL_SIEM_SKIP_DOCKER / HALTSQL_SKIP_DOCKER is set"
    | _ -> (
        match docker [ "info"; "--format"; "{{.ServerVersion}}" ] with
        | 0, _ -> Ok ()
        | _, out -> Error ("docker is not available: " ^ String.trim out)
        | exception Unix.Unix_error (e, _, _) ->
            Error ("docker is not available: " ^ Unix.error_message e)))

let image_present image =
  match docker [ "image"; "inspect"; "--format"; "{{.Id}}"; image ] with
  | 0, _ -> true
  | _ -> ( match docker [ "pull"; image ] with 0, _ -> true | _ -> false)

let started : string list ref = ref []
let remove_container name = ignore (docker [ "rm"; "-f"; "-v"; name ])
let temp_dirs : string list ref = ref []

let rec rm_rf path =
  match Sys.is_directory path with
  | true ->
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Sys.rmdir path
  | false -> Sys.remove path
  | exception Sys_error _ -> ()

let () =
  at_exit (fun () ->
      if Sys.getenv_opt "HALTSQL_SIEM_KEEP_CONTAINERS" = None then begin
        List.iter remove_container !started;
        List.iter (fun d -> try rm_rf d with Sys_error _ -> ()) !temp_dirs
      end)

(* Starts a container (removing a leftover of ours with the same name first). *)
let run_container ~name args image cmd =
  remove_container name;
  ignore (docker_ok ([ "run"; "-d"; "--name"; name ] @ args @ [ image ] @ cmd));
  started := name :: !started

let logs name = snd (docker [ "logs"; "--tail"; "60"; name ])

let rec wait_until ?(interval = 1.0) ~deadline what f =
  f () >>= function
  | true -> Lwt.return_unit
  | false ->
      if Unix.gettimeofday () > deadline then
        Lwt.fail_with (Printf.sprintf "timed out waiting for %s" what)
      else Lwt_unix.sleep interval >>= fun () -> wait_until ~interval ~deadline what f

(* ---- test PKI ---- *)

let ok = function Ok x -> x | Error (`Msg m) -> failwith m

let write_file ?(perm = 0o644) path s =
  let oc = open_out_gen [ Open_wronly; Open_creat; Open_trunc; Open_binary ] perm path in
  output_string oc s;
  close_out oc

let dn cn =
  [
    X509.Distinguished_name.(
      Relative_distinguished_name.singleton (CN (Common_name.v cn)));
  ]

let shift days =
  match Ptime.add_span (Ptime_clock.now ()) (Ptime.Span.of_int_s (days * 86400)) with
  | Some t -> t
  | None -> failwith "time"

let make_ca cn =
  let key = X509.Private_key.generate ~bits:2048 `RSA in
  let csr = ok (X509.Signing_request.create (dn cn) key) in
  let ext =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (true, None))
      |> add Key_usage (true, [ `Key_cert_sign; `CRL_sign; `Digital_signature ]))
  in
  match
    X509.Signing_request.sign csr ~valid_from:(shift (-1)) ~valid_until:(shift 30)
      ~extensions:ext key (dn cn)
  with
  | Ok c -> (key, c)
  | Error _ -> failwith "sign ca"

let make_server ~ca_key ~ca_cert cn =
  let key = X509.Private_key.generate ~bits:2048 `RSA in
  let csr = ok (X509.Signing_request.create (dn cn) key) in
  let san =
    X509.General_name.(
      singleton DNS [ "localhost" ] |> add IP [ Ipaddr.V4.to_octets Ipaddr.V4.localhost ])
  in
  let ext =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (false, None))
      |> add Key_usage (true, [ `Digital_signature; `Key_encipherment ])
      |> add Ext_key_usage (false, [ `Server_auth ])
      |> add Subject_alt_name (false, san))
  in
  match
    X509.Signing_request.sign csr ~valid_from:(shift (-1)) ~valid_until:(shift 30)
      ~extensions:ext ca_key
      (X509.Certificate.subject ca_cert)
  with
  | Ok c -> (key, c)
  | Error _ -> failwith "sign server"

let make_client ~ca_key ~ca_cert cn =
  let key = X509.Private_key.generate ~bits:2048 `RSA in
  let csr = ok (X509.Signing_request.create (dn cn) key) in
  let ext =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (false, None))
      |> add Key_usage (true, [ `Digital_signature; `Key_encipherment ])
      |> add Ext_key_usage (false, [ `Client_auth ]))
  in
  match
    X509.Signing_request.sign csr ~valid_from:(shift (-1)) ~valid_until:(shift 30)
      ~extensions:ext ca_key
      (X509.Certificate.subject ca_cert)
  with
  | Ok c -> (key, c)
  | Error _ -> failwith "sign client"

type pki = {
  dir : string;
  ca_pem : string;
  ca_file : string;
  rogue_ca_pem : string;
  client_cert_file : string;  (** client certificate signed by the test CA *)
  client_key_file : string;
  rogue_client_cert_file : string;  (** client certificate signed by another CA *)
  rogue_client_key_file : string;
}

(* Writes ca.pem, server.crt, server.key and server-bundle.pem (key + chain, the
   PEM keystore layout Kafka reads) into a fresh directory. Docker Desktop shares
   the system temp directory with containers. *)
let make_pki () =
  Mirage_crypto_rng_unix.use_default ();
  let dir = Filename.temp_dir "haltsql-siem-pki" "" in
  temp_dirs := dir :: !temp_dirs;
  Unix.chmod dir 0o755;
  let ca_key, ca_cert = make_ca "haltsql siem test CA" in
  let key, cert = make_server ~ca_key ~ca_cert "localhost" in
  let rogue_key, rogue = make_ca "unrelated CA" in
  let ckey, ccert = make_client ~ca_key ~ca_cert "haltsql-client" in
  let rkey, rcert = make_client ~ca_key:rogue_key ~ca_cert:rogue "haltsql-client" in
  let p f = Filename.concat dir f in
  let ca_pem = X509.Certificate.encode_pem ca_cert in
  let key_pem = X509.Private_key.encode_pem key in
  let cert_pem = X509.Certificate.encode_pem cert in
  write_file (p "ca.pem") ca_pem;
  write_file (p "server.crt") cert_pem;
  write_file (p "server.key") key_pem;
  write_file (p "server-bundle.pem") (key_pem ^ cert_pem);
  write_file (p "client.crt") (X509.Certificate.encode_pem ccert);
  write_file ~perm:0o600 (p "client.key") (X509.Private_key.encode_pem ckey);
  write_file (p "rogue-client.crt") (X509.Certificate.encode_pem rcert);
  write_file ~perm:0o600 (p "rogue-client.key") (X509.Private_key.encode_pem rkey);
  {
    dir;
    ca_pem;
    ca_file = p "ca.pem";
    rogue_ca_pem = X509.Certificate.encode_pem rogue;
    client_cert_file = p "client.crt";
    client_key_file = p "client.key";
    rogue_client_cert_file = p "rogue-client.crt";
    rogue_client_key_file = p "rogue-client.key";
  }

(* ---- records and chains ---- *)

let record i extra =
  [
    ("ts", `String (Printf.sprintf "2026-11-07T12:%02d:%02dZ" (i / 60 mod 60) (i mod 60)));
    ("request_id", `String (Printf.sprintf "req-%04d" i));
    ("caller", `String "siem-test");
    ("allowed", `Bool (i mod 2 = 0));
    ("codes", `List [ `String "E_TABLE_DENIED" ]);
    ("elapsed_us", `Int (100 + i));
  ]
  @ extra

let hash_of line =
  match Yojson.Safe.from_string line with
  | `Assoc kv -> (
      match List.assoc_opt "hash" kv with
      | Some (`String h) -> h
      | _ -> failwith "no hash")
  | _ -> failwith "not an object"

let prev_of line =
  match Yojson.Safe.from_string line with
  | `Assoc kv -> (
      match List.assoc_opt "prev_hash" kv with
      | Some (`String h) -> h
      | _ -> failwith "no prev_hash")
  | _ -> failwith "not an object"

(* Drops a record whose hash equals the previous one (an at-least-once retry). *)
let dedupe lines =
  List.rev
    (List.fold_left
       (fun acc l ->
         match acc with p :: _ when hash_of p = hash_of l -> acc | _ -> l :: acc)
       [] lines)

let verify_chain lines =
  match Haltsql_cloud.Audit_chain.verify_lines lines with
  | Ok n -> n
  | Error (n, m) -> Alcotest.failf "chain broken at record %d: %s" n m

(* Orders documents of one chain by following prev_hash links from genesis. *)
let link_chain lines =
  let by_prev = Hashtbl.create 64 in
  List.iter (fun l -> Hashtbl.replace by_prev (prev_of l) l) lines;
  let rec walk prev acc =
    match Hashtbl.find_opt by_prev prev with
    | None -> List.rev acc
    | Some l -> walk (hash_of l) (l :: acc)
  in
  walk Haltsql_cloud.Audit_chain.genesis []

let batch ?(max_records = 10) ?(flush_ms = 50) () =
  {
    Config.batch_max_records = max_records;
    batch_max_bytes = 5 * 1024 * 1024;
    flush_interval_ms = flush_ms;
  }

let events = ref []
let on_event m = events := m :: !events

let check_no_secret ~secret =
  List.iter
    (fun e ->
      let n = String.length secret in
      let found = ref false in
      for i = 0 to String.length e - n do
        if String.sub e i n = secret then found := true
      done;
      if !found then Alcotest.failf "an event leaked a secret: %s" e)
    !events

let write_n sink ?(extra = fun _ -> []) ~from n =
  for i = from to from + n - 1 do
    match Haltsql_siem.Stream_sink.write sink (record i (extra i)) with
    | Ok () -> ()
    | Error e -> Alcotest.failf "write %d refused: %s" i e
  done

let python3 =
  lazy (match run_cmd [| "python3"; "--version" |] with 0, _ -> true | _ -> false)

let run_python script args = run_cmd (Array.of_list ("python3" :: "-I" :: script :: args))

(* The verifier's last line is "OK: <n> records in <k> chain(s)". *)
let python_ok out =
  match
    List.rev (List.filter (fun l -> String.trim l <> "") (String.split_on_char '\n' out))
  with
  | last :: _ -> String.length last >= 3 && String.sub last 0 3 = "OK:"
  | [] -> false

let skip_unless_docker () =
  match Lazy.force docker_available with
  | Ok () -> ()
  | Error m ->
      Printf.printf "SKIP: %s\n%!" m;
      Alcotest.skip ()

module Str_lite = struct
  let replace_first ~sub ~by s =
    let n = String.length sub in
    let rec find i =
      if i + n > String.length s then None
      else if String.sub s i n = sub then Some i
      else find (i + 1)
    in
    match find 0 with
    | None -> s
    | Some i -> String.sub s 0 i ^ by ^ String.sub s (i + n) (String.length s - i - n)
end
