(* haltsql-server POST /v1/verify latency under concurrency.

   The load generator is closed-loop: C persistent HTTP/1.1 keep-alive connections,
   each sending the next request as soon as the previous response is fully read,
   cycling through the complexity-tier queries. Connections are spread over up to 4
   forked worker processes (each an Lwt event loop) so the client is not the
   bottleneck; latencies are merged in the parent. A response counts as an error
   unless it is 200 with "allowed":true. *)

open Lwt.Syntax

let ( // ) = Filename.concat

let request_bytes ~port sql =
  let body =
    Yojson.Safe.to_string
      (`Assoc
         [ ("sql", `String sql); ("context", `Assoc [ ("tenant_id", `String "acme") ]) ])
  in
  Printf.sprintf
    "POST /v1/verify HTTP/1.1\r\n\
     Host: 127.0.0.1:%d\r\n\
     Content-Type: application/json\r\n\
     Content-Length: %d\r\n\
     \r\n\
     %s"
    port (String.length body) body

let contains s needle =
  let ln = String.length needle and ls = String.length s in
  let rec go i = i + ln <= ls && (String.sub s i ln = needle || go (i + 1)) in
  go 0

(* Reads one response; returns (status, body). Only Content-Length framing is
   supported, which is what haltsql-server sends. *)
let read_response ic =
  let* status_line = Lwt_io.read_line ic in
  let status =
    match String.split_on_char ' ' status_line with
    | _ :: code :: _ -> int_of_string_opt code |> Option.value ~default:0
    | _ -> 0
  in
  let rec headers len =
    let* l = Lwt_io.read_line ic in
    let l = String.trim l in
    if l = "" then Lwt.return len
    else
      match String.index_opt l ':' with
      | Some i when String.lowercase_ascii (String.sub l 0 i) = "content-length" ->
          headers
            (int_of_string_opt
               (String.trim (String.sub l (i + 1) (String.length l - i - 1))))
      | _ -> headers len
  in
  let* len = headers None in
  match len with
  | None -> Lwt.fail_with "response without Content-Length"
  | Some n ->
      let buf = Bytes.create n in
      let* () = Lwt_io.read_into_exactly ic buf 0 n in
      Lwt.return (status, Bytes.unsafe_to_string buf)

type worker_out = { lats : float array; errs : int; first_error : string option }

let worker ~port ~conns ~warmup ~duration ~requests ~offset =
  let main () =
    let lat = ref [] and errs = ref 0 and first_error = ref None in
    let t_begin = Unix.gettimeofday () in
    let t_measure = t_begin +. warmup and t_end = t_begin +. warmup +. duration in
    let conn k =
      let fd = Lwt_unix.socket PF_INET SOCK_STREAM 0 in
      Lwt_unix.setsockopt fd TCP_NODELAY true;
      let* () = Lwt_unix.connect fd (ADDR_INET (Unix.inet_addr_loopback, port)) in
      let ic = Lwt_io.of_fd ~mode:Lwt_io.input fd
      and oc = Lwt_io.of_fd ~mode:Lwt_io.output fd in
      let nreq = Array.length requests in
      let rec loop i =
        let t0 = Unix.gettimeofday () in
        if t0 >= t_end then Lwt.return_unit
        else
          let* () = Lwt_io.write oc requests.((offset + k + i) mod nreq) in
          let* () = Lwt_io.flush oc in
          let* status, body = read_response ic in
          let t1 = Unix.gettimeofday () in
          if t0 >= t_measure then (
            lat := ((t1 -. t0) *. 1e6) :: !lat;
            if status <> 200 || not (contains body "\"allowed\":true") then (
              incr errs;
              if !first_error = None then
                first_error :=
                  Some
                    (Printf.sprintf "HTTP %d: %s" status
                       (String.sub body 0 (min 200 (String.length body))))));
          loop (i + 1)
      in
      Lwt.finalize (fun () -> loop 0) (fun () -> Lwt_unix.close fd)
    in
    let* () = Lwt.join (List.init conns conn) in
    Lwt.return { lats = Array.of_list !lat; errs = !errs; first_error = !first_error }
  in
  Lwt_main.run (main ())

(* Runs [conns] connections over [workers] forked processes. *)
let load ~port ~conns ~warmup ~duration ~requests =
  let workers = max 1 (min conns 4) in
  let per =
    Array.init workers (fun w ->
        (conns / workers) + if w < conns mod workers then 1 else 0)
  in
  let children =
    Array.to_list
      (Array.mapi
         (fun w n ->
           let r, wr = Unix.pipe ~cloexec:true () in
           match Lwt_unix.fork () with
           | 0 ->
               Unix.close r;
               let out =
                 try worker ~port ~conns:n ~warmup ~duration ~requests ~offset:(w * 7)
                 with e ->
                   { lats = [||]; errs = 1; first_error = Some (Printexc.to_string e) }
               in
               let oc = Unix.out_channel_of_descr wr in
               Marshal.to_channel oc out [];
               close_out oc;
               Unix._exit 0
           | pid ->
               Unix.close wr;
               (pid, r))
         per)
  in
  let outs =
    List.map
      (fun (pid, r) ->
        let ic = Unix.in_channel_of_descr r in
        let (o : worker_out) = Marshal.from_channel ic in
        close_in ic;
        ignore (Procs.waitpid_eintr pid);
        o)
      children
  in
  let lats = Array.concat (List.map (fun o -> o.lats) outs) in
  let errs = List.fold_left (fun a o -> a + o.errs) 0 outs in
  let first_error = List.find_map (fun o -> o.first_error) outs in
  (lats, errs, first_error)

let start_server ~server ~policy ~dir ~audit =
  let port = Procs.free_port () in
  let log = dir // Printf.sprintf "server-%s.log" audit in
  let audit_arg =
    match audit with "file" -> "file:" ^ (dir // "audit.jsonl") | a -> a
  in
  let pid =
    Procs.spawn ~log server
      [
        "--policy";
        policy;
        "--listen";
        Printf.sprintf "127.0.0.1:%d" port;
        "--allow-unauthenticated";
        "--no-watch";
        "--audit";
        audit_arg;
      ]
  in
  if not (Procs.wait_port ~timeout:15.0 port) then (
    Procs.stop pid;
    failwith ("haltsql-server did not start, see " ^ log));
  (pid, port)

let run ~root ~server ~small =
  let dir = Procs.temp_dir "haltsql-bench-http" in
  Fun.protect
    ~finally:(fun () -> Procs.rm_rf dir)
    (fun () ->
      let policy = Workloads.saas_policy_path root in
      let sqls = Workloads.mix_sqls root in
      let duration = if small then 3.0 else 10.0
      and warmup = if small then 1.0 else 2.0 in
      let scenarios =
        if small then [ ("file", 1); ("file", 8) ]
        else [ ("file", 1); ("file", 8); ("file", 32); ("file", 128); ("none", 32) ]
      in
      List.map
        (fun (audit, conns) ->
          let pid, port = start_server ~server ~policy ~dir ~audit in
          Fun.protect
            ~finally:(fun () -> Procs.stop pid)
            (fun () ->
              let requests = Array.of_list (List.map (request_bytes ~port) sqls) in
              let lats, errs, first_error =
                load ~port ~conns ~warmup ~duration ~requests
              in
              (match first_error with
              | Some e ->
                  Printf.eprintf "http c=%d audit=%s: %d errors, first: %s\n%!" conns
                    audit errs e
              | None -> ());
              Stats.summarize ~errors:errs
                ~gate:(audit = "file" && conns = 1)
                ~suite:"http"
                ~name:(Printf.sprintf "verify_c%d_audit_%s" conns audit)
                ~unit_:"us" ~wall:duration
                ~extra:
                  [
                    ("concurrency", `Int conns);
                    ("audit", `String audit);
                    ("duration_s", `Float duration);
                  ]
                lats))
        scenarios)
