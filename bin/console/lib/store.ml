(* File-backed implementation of the console store; see store.mli for the contract.

   Per collection: an in-memory table id -> (insertion seq, doc), an ordered map
   seq -> id for insertion-order iteration, an append-only operation log and a snapshot.
   Writes take the collection's own lock, append one fsynced line to the log and only
   then change memory, so a failed write leaves memory and disk unchanged: a write or
   fsync error truncates the log back to its last good size before the promise is
   rejected, and if even that fails the collection is poisoned (every later write fails)
   until restart. The append + fsync + apply runs under [Lwt.no_cancel], so a request
   timeout cannot leave the log and memory disagreeing. *)

open Lwt.Syntax
module IntMap = Map.Make (Int)

type coll = {
  name : string;
  lock : Lwt_mutex.t;
  docs : (string, int * Yojson.Safe.t) Hashtbl.t;  (** id -> (seq, doc) *)
  mutable order : string IntMap.t;  (** seq -> id, insertion order *)
  mutable next_seq : int;
  mutable log_ops : int;  (** operations in the log since the last compaction *)
  mutable log_fd : Lwt_unix.file_descr option;  (** opened on first write *)
  mutable log_size : int;  (** bytes of complete, fsynced ops in the log *)
  mutable poisoned : string option;  (** why writes are refused until restart *)
}

type t = { dir : string; compact_min_ops : int; colls : (string, coll) Hashtbl.t }

let valid_name s =
  s <> ""
  && String.for_all
       (function 'a' .. 'z' | '0' .. '9' | '_' | '-' -> true | _ -> false)
       s

let rec mkdir_p d =
  if not (Sys.file_exists d) then (
    mkdir_p (Filename.dirname d);
    try Unix.mkdir d 0o750 with Unix.Unix_error (Unix.EEXIST, _, _) -> ())

let dir t = t.dir
let snapshot_path t c = Filename.concat t.dir (c ^ ".json")
let log_path t c = Filename.concat t.dir (c ^ ".log")

let log_stderr ~level msg =
  Printf.eprintf "{\"ts\":%S,\"level\":%S,\"msg\":%s}\n%!"
    (Api.iso8601 (Unix.gettimeofday ()))
    level
    (Yojson.Safe.to_string (`String msg))

let describe_exn = function
  | Unix.Unix_error (e, fn, arg) ->
      Printf.sprintf "%s%s: %s" fn
        (if arg = "" then "" else " " ^ arg)
        (Unix.error_message e)
  | e -> Printexc.to_string e

(* ---- off-event-loop I/O helpers ---- *)

type io_hooks = {
  mutable write : Lwt_unix.file_descr -> Bytes.t -> int -> int -> int Lwt.t;
  mutable fsync : Lwt_unix.file_descr -> unit Lwt.t;
  mutable rename : string -> string -> unit Lwt.t;
}

(* Lwt_unix runs writes and fsync on regular files as jobs in its thread pool. *)
let io = { write = Lwt_unix.write; fsync = Lwt_unix.fsync; rename = Lwt_unix.rename }

let reset_io () =
  io.write <- Lwt_unix.write;
  io.fsync <- Lwt_unix.fsync;
  io.rename <- Lwt_unix.rename

let fsync fd = io.fsync fd

let write_all fd s =
  let b = Bytes.unsafe_of_string s in
  let len = Bytes.length b in
  let rec go off =
    if off >= len then Lwt.return_unit
    else
      let* n = io.write fd b off (len - off) in
      go (off + n)
  in
  go 0

let append_line fd ~good_size line =
  Lwt.catch
    (fun () ->
      let* () = write_all fd line in
      let* () = fsync fd in
      Lwt.return `Ok)
    (fun e ->
      (* drop whatever part of the line reached the file, so the next append starts on
         a clean line and a rejected write cannot reappear after a restart *)
      Lwt.catch
        (fun () ->
          let* () = Lwt_unix.ftruncate fd good_size in
          let* () = fsync fd in
          Lwt.return (`Rolled_back e))
        (fun e' -> Lwt.return (`Lost (e, e'))))

let fsync_dir d =
  let* fd = Lwt_unix.openfile d [ Unix.O_RDONLY; O_CLOEXEC ] 0 in
  Lwt.finalize
    (fun () ->
      Lwt.catch
        (fun () -> fsync fd)
        (function
          (* some filesystems refuse to fsync a directory; nothing more to do *)
          | Unix.Unix_error ((EINVAL | EOPNOTSUPP | EBADF), _, _) -> Lwt.return_unit
          | e -> Lwt.fail e))
    (fun () -> Lwt_unix.close fd)

let read_lines_from path f =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () ->
      let chunk = Bytes.create 65536 in
      let buf = Buffer.create 4096 in
      let lineno = ref 0 and pos = ref 0 and line_start = ref 0 in
      let pending = ref None in
      (* a line is emitted once the next non-blank line is known, so [last] is exact *)
      let push start s =
        incr lineno;
        if String.trim s <> "" then (
          (match !pending with
          | Some (n, o, l) -> f ~lineno:n ~offset:o ~last:false l
          | None -> ());
          pending := Some (!lineno, start, s))
      in
      let rec loop () =
        let n = input ic chunk 0 (Bytes.length chunk) in
        if n > 0 then (
          for i = 0 to n - 1 do
            let c = Bytes.get chunk i in
            if c = '\n' then (
              push !line_start (Buffer.contents buf);
              Buffer.clear buf;
              line_start := !pos + 1)
            else Buffer.add_char buf c;
            incr pos
          done;
          loop ())
      in
      loop ();
      if Buffer.length buf > 0 then push !line_start (Buffer.contents buf);
      match !pending with
      | Some (n, o, l) -> f ~lineno:n ~offset:o ~last:true l
      | None -> ())

(* ---- loading ---- *)

let new_coll name =
  {
    name;
    lock = Lwt_mutex.create ();
    docs = Hashtbl.create 64;
    order = IntMap.empty;
    next_seq = 0;
    log_ops = 0;
    log_fd = None;
    log_size = 0;
    poisoned = None;
  }

let apply_put c id doc =
  match Hashtbl.find_opt c.docs id with
  | Some (seq, _) -> Hashtbl.replace c.docs id (seq, doc)
  | None ->
      let seq = c.next_seq in
      c.next_seq <- seq + 1;
      Hashtbl.replace c.docs id (seq, doc);
      c.order <- IntMap.add seq id c.order

let apply_delete c id =
  match Hashtbl.find_opt c.docs id with
  | Some (seq, _) ->
      Hashtbl.remove c.docs id;
      c.order <- IntMap.remove seq c.order
  | None -> ()

exception Corrupt of string

let corrupt path line msg =
  raise (Corrupt (Printf.sprintf "%s:%d: corrupt store data: %s" path line msg))

let load_snapshot c path =
  let ic = open_in_bin path in
  let s =
    Fun.protect
      ~finally:(fun () -> close_in_noerr ic)
      (fun () -> really_input_string ic (in_channel_length ic))
  in
  match Yojson.Safe.from_string ~fname:path s with
  | `Assoc l -> List.iter (fun (id, doc) -> apply_put c id doc) l
  | _ -> corrupt path 1 "expected a JSON object"
  | exception Yojson.Json_error m -> raise (Corrupt ("corrupt store snapshot: " ^ m))

let op_of_line path lineno line =
  match Yojson.Safe.from_string line with
  | `Assoc l -> (
      match (List.assoc_opt "op" l, List.assoc_opt "id" l, List.assoc_opt "doc" l) with
      | Some (`String "put"), Some (`String id), Some doc -> `Put (id, doc)
      | Some (`String "del"), Some (`String id), _ -> `Del id
      | _ -> corrupt path lineno "unknown operation")
  | _ -> corrupt path lineno "expected a JSON object"
  | exception Yojson.Json_error m -> corrupt path lineno m

let last_byte path len =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () ->
      seek_in ic (len - 1);
      input_char ic)

(* Replays the log. An unparsable last line is a torn append (crash mid-write): it is
   dropped and the file truncated to the end of the previous line, so the next append
   doesn't glue onto it. Any other unparsable line is fatal. *)
let load_log c path =
  let torn = ref None in
  read_lines_from path (fun ~lineno ~offset ~last line ->
      match op_of_line path lineno line with
      | `Put (id, doc) ->
          apply_put c id doc;
          c.log_ops <- c.log_ops + 1
      | `Del id ->
          apply_delete c id;
          c.log_ops <- c.log_ops + 1
      | exception Corrupt _ when last -> torn := Some (lineno, offset));
  match !torn with
  | Some (lineno, offset) ->
      log_stderr ~level:"warn"
        (Printf.sprintf "%s:%d: dropping torn last line" path lineno);
      Unix.truncate path offset
  | None ->
      (* a complete last op without its newline: terminate it before appending more *)
      let len = (Unix.stat path).st_size in
      if len > 0 && last_byte path len <> '\n' then (
        let oc = open_out_gen [ Open_append; Open_binary ] 0o640 path in
        output_char oc '\n';
        close_out oc)

let load_coll t name =
  let c = new_coll name in
  let sp = snapshot_path t name and lp = log_path t name in
  (try
     if Sys.file_exists sp then load_snapshot c sp;
     if Sys.file_exists lp then load_log c lp
   with
  | Corrupt m -> failwith m
  | Sys_error m -> failwith m
  | Unix.Unix_error (e, _, arg) ->
      failwith ((if arg = "" then lp else arg) ^ ": " ^ Unix.error_message e));
  c

let coll t name =
  if not (valid_name name) then invalid_arg ("Store: bad collection name " ^ name);
  match Hashtbl.find_opt t.colls name with
  | Some c -> c
  | None ->
      let c = load_coll t name in
      Hashtbl.replace t.colls name c;
      c

let create ?(compact_min_ops = 1000) d =
  try
    mkdir_p d;
    if not (Sys.is_directory d) then failwith (d ^ " is not a directory");
    let t = { dir = d; compact_min_ops; colls = Hashtbl.create 8 } in
    (* eager load: corrupt state fails here, at startup, not on every request *)
    Sys.readdir d |> Array.to_list |> List.sort compare
    |> List.iter (fun f ->
        let base = Filename.remove_extension f in
        match Filename.extension f with
        | (".json" | ".log") when valid_name base -> ignore (coll t base)
        | _ -> ());
    t
  with
  | Unix.Unix_error (e, _, arg) ->
      failwith ((if arg = "" then d else arg) ^ ": " ^ Unix.error_message e)
  | Sys_error m -> failwith m

(* ---- reads ---- *)

let get t c id = Option.map snd (Hashtbl.find_opt (coll t c).docs id)
let count t c = Hashtbl.length (coll t c).docs

let fold t c f init =
  let c = coll t c in
  (* [order] is immutable: folding over it is a snapshot even if writes land meanwhile *)
  IntMap.fold
    (fun _ id acc ->
      match Hashtbl.find_opt c.docs id with Some (_, doc) -> f id doc acc | None -> acc)
    c.order init

let iter t c f = fold t c (fun id doc () -> f id doc) ()

(* ---- writes ---- *)

let log_fd t c =
  match c.log_fd with
  | Some fd -> Lwt.return fd
  | None ->
      let p = log_path t c.name in
      let fresh = not (Sys.file_exists p) in
      let* fd =
        Lwt_unix.openfile p [ Unix.O_WRONLY; O_APPEND; O_CREAT; O_CLOEXEC ] 0o640
      in
      let* () =
        Lwt.catch
          (fun () ->
            let* st = Lwt_unix.fstat fd in
            c.log_size <- st.Unix.st_size;
            if fresh then fsync_dir t.dir else Lwt.return_unit)
          (fun e ->
            let* () =
              Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
            in
            Lwt.fail e)
      in
      c.log_fd <- Some fd;
      Lwt.return fd

let poisoned_error c why =
  Failure
    (Printf.sprintf
       "Store: collection %s refuses writes until restart: a failed append could not be \
        rolled back (%s)"
       c.name why)

let append_op t c op =
  match c.poisoned with
  | Some why -> Lwt.fail (poisoned_error c why)
  | None -> (
      let* fd = log_fd t c in
      let line = Yojson.Safe.to_string op ^ "\n" in
      let* r = append_line fd ~good_size:c.log_size line in
      match r with
      | `Ok ->
          c.log_size <- c.log_size + String.length line;
          c.log_ops <- c.log_ops + 1;
          Lwt.return_unit
      | `Rolled_back e -> Lwt.fail e
      | `Lost (e, e') ->
          let why =
            Printf.sprintf "%s; truncating %s back to %d bytes: %s" (describe_exn e)
              (log_path t c.name) c.log_size (describe_exn e')
          in
          c.poisoned <- Some why;
          log_stderr ~level:"error" (Printf.sprintf "store %s poisoned: %s" c.name why);
          Lwt.fail e)

let compact t c =
  let sp = snapshot_path t c.name in
  let tmp = sp ^ ".tmp" in
  let* fd = Lwt_unix.openfile tmp [ Unix.O_WRONLY; O_CREAT; O_TRUNC; O_CLOEXEC ] 0o640 in
  let* () =
    Lwt.finalize
      (fun () ->
        let oc = Lwt_io.of_fd ~mode:Lwt_io.output ~close:(fun () -> Lwt.return_unit) fd in
        let* () = Lwt_io.write oc "{" in
        let* _ =
          Lwt_list.fold_left_s
            (fun first (_, id) ->
              match Hashtbl.find_opt c.docs id with
              | None -> Lwt.return first
              | Some (_, doc) ->
                  let* () =
                    Lwt_io.write oc
                      ((if first then "\n" else ",\n")
                      ^ Yojson.Safe.to_string (`String id)
                      ^ ":" ^ Yojson.Safe.to_string doc)
                  in
                  Lwt.return false)
            true (IntMap.bindings c.order)
        in
        let* () = Lwt_io.write oc "\n}\n" in
        let* () = Lwt_io.flush oc in
        fsync fd)
      (fun () -> Lwt_unix.close fd)
  in
  let* () = io.rename tmp sp in
  let* () = fsync_dir t.dir in
  (* the snapshot holds every logged op; a crash before the truncate replays them again,
     which is harmless (puts and deletes are idempotent) *)
  let* lfd = log_fd t c in
  let* () = Lwt_unix.ftruncate lfd 0 in
  c.log_size <- 0;
  c.log_ops <- 0;
  fsync lfd

(* The write that triggered compaction is already durable and applied, so a compaction
   failure must not reject it: it is logged, the temporary file removed, and compaction
   retried on a later write (log_ops is still over the threshold). *)
let maybe_compact t c =
  if c.poisoned = None && c.log_ops > max t.compact_min_ops (2 * Hashtbl.length c.docs)
  then
    Lwt.catch
      (fun () -> compact t c)
      (fun e ->
        log_stderr ~level:"error"
          (Printf.sprintf "store %s: compaction failed, will retry: %s" c.name
             (describe_exn e));
        let tmp = snapshot_path t c.name ^ ".tmp" in
        Lwt.catch
          (fun () -> if Sys.file_exists tmp then Lwt_unix.unlink tmp else Lwt.return_unit)
          (fun _ -> Lwt.return_unit))
  else Lwt.return_unit

let update t cname id f =
  let c = coll t cname in
  Lwt_mutex.with_lock c.lock (fun () ->
      let next = f (Option.map snd (Hashtbl.find_opt c.docs id)) in
      (* once started, the append, the apply to memory and compaction run to the end
         even if the caller is cancelled (request timeout) *)
      Lwt.no_cancel
      @@ let* () =
           match next with
           | Some doc ->
               let* () =
                 append_op t c
                   (`Assoc [ ("op", `String "put"); ("id", `String id); ("doc", doc) ])
               in
               apply_put c id doc;
               Lwt.return_unit
           | None when Hashtbl.mem c.docs id ->
               let* () =
                 append_op t c (`Assoc [ ("op", `String "del"); ("id", `String id) ])
               in
               apply_delete c id;
               Lwt.return_unit
           | None -> Lwt.return_unit
         in
         let* () = maybe_compact t c in
         Lwt.return next)

let put t c id doc =
  let* _ = update t c id (fun _ -> Some doc) in
  Lwt.return_unit

let delete t c id =
  let* _ = update t c id (fun _ -> None) in
  Lwt.return_unit

let next_counter t name ~start =
  let* r =
    update t "counters" name (function
      | Some (`Int n) -> Some (`Int (n + 1))
      | _ -> Some (`Int start))
  in
  match r with Some (`Int n) -> Lwt.return n | _ -> assert false

(* ---- files beside the collections ---- *)

let blob_path t ~subdir name =
  if not (valid_name subdir) then invalid_arg "Store.blob_path";
  let d = Filename.concat t.dir subdir in
  mkdir_p d;
  Filename.concat d (Filename.basename name)

let writable t =
  let p = Filename.concat t.dir ".probe" in
  Lwt.catch
    (fun () ->
      let* fd =
        Lwt_unix.openfile p [ Unix.O_WRONLY; O_CREAT; O_TRUNC; O_CLOEXEC ] 0o640
      in
      let* () =
        Lwt.finalize
          (fun () ->
            let* () = write_all fd "ok" in
            fsync fd)
          (fun () -> Lwt_unix.close fd)
      in
      let* () = Lwt_unix.unlink p in
      Lwt.return_true)
    (fun _ -> Lwt.return_false)
