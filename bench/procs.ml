(* Child processes, temp dirs and free ports for the CLI, HTTP and proxy suites. *)

let ( // ) = Filename.concat

let temp_dir prefix =
  let base = Filename.get_temp_dir_name () in
  let rec go i =
    let d =
      base // Printf.sprintf "%s-%d-%d" prefix (Unix.getpid ()) (Random.bits () + i)
    in
    match Unix.mkdir d 0o700 with
    | () -> d
    | exception Unix.Unix_error (Unix.EEXIST, _, _) -> go (i + 1)
  in
  go 0

let rec rm_rf p =
  match (Unix.lstat p).st_kind with
  | S_DIR ->
      Array.iter (fun f -> rm_rf (p // f)) (Sys.readdir p);
      Unix.rmdir p
  | _ -> Unix.unlink p
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> ()

let write_file path s =
  let oc = open_out_bin path in
  output_string oc s;
  close_out oc

let read_file path =
  let ic = open_in_bin path in
  let s = really_input_string ic (in_channel_length ic) in
  close_in ic;
  s

(* A port the kernel considers free right now on 127.0.0.1. *)
let free_port () =
  let s = Unix.socket PF_INET SOCK_STREAM 0 in
  Unix.setsockopt s SO_REUSEADDR true;
  Unix.bind s (ADDR_INET (Unix.inet_addr_loopback, 0));
  let port =
    match Unix.getsockname s with ADDR_INET (_, p) -> p | ADDR_UNIX _ -> assert false
  in
  Unix.close s;
  port

let rec waitpid_eintr pid =
  try snd (Unix.waitpid [] pid)
  with Unix.Unix_error (Unix.EINTR, _, _) -> waitpid_eintr pid

(* Runs [prog args] with stdin/stdout/stderr redirected to files (or /dev/null) and
   returns (exit status, wall seconds). *)
let run_timed ?(env = Unix.environment ()) ?stdin ?stdout ?stderr prog args =
  let open_or_null mode f =
    match f with
    | Some p -> Unix.openfile p mode 0o600
    | None -> Unix.openfile "/dev/null" [ O_RDWR ] 0
  in
  let i = open_or_null [ O_RDONLY ] stdin in
  let o = open_or_null [ O_WRONLY; O_CREAT; O_TRUNC ] stdout in
  let e = open_or_null [ O_WRONLY; O_CREAT; O_TRUNC ] stderr in
  let t0 = Stats.now () in
  let pid = Unix.create_process_env prog (Array.of_list (prog :: args)) env i o e in
  let st = waitpid_eintr pid in
  let wall = Stats.now () -. t0 in
  List.iter Unix.close [ i; o; e ];
  (st, wall)

(* A long-running child (haltsql-server, haltsql-proxy) with output to [log]. *)
let spawn ?(env = Unix.environment ()) ~log prog args =
  let o = Unix.openfile log [ O_WRONLY; O_CREAT; O_TRUNC ] 0o600 in
  let i = Unix.openfile "/dev/null" [ O_RDONLY ] 0 in
  let pid = Unix.create_process_env prog (Array.of_list (prog :: args)) env i o o in
  Unix.close o;
  Unix.close i;
  pid

let stop pid =
  (try Unix.kill pid Sys.sigterm with Unix.Unix_error _ -> ());
  ignore (waitpid_eintr pid)

(* Polls a TCP port until it accepts a connection. *)
let wait_port ~timeout port =
  let deadline = Stats.now () +. timeout in
  let rec go () =
    let s = Unix.socket PF_INET SOCK_STREAM 0 in
    match Unix.connect s (ADDR_INET (Unix.inet_addr_loopback, port)) with
    | () ->
        Unix.close s;
        true
    | exception Unix.Unix_error _ ->
        Unix.close s;
        if Stats.now () > deadline then false
        else (
          Unix.sleepf 0.05;
          go ())
  in
  go ()

let exited_ok = function Unix.WEXITED 0 -> true | _ -> false

let status_string = function
  | Unix.WEXITED n -> Printf.sprintf "exit %d" n
  | Unix.WSIGNALED n -> Printf.sprintf "signal %d" n
  | Unix.WSTOPPED n -> Printf.sprintf "stopped %d" n
