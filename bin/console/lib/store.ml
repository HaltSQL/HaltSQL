(* Durable console state: human input only (cases, signal workflow, evidence pack index,
   counters). One JSON file per collection in [state_dir], rewritten atomically (write to
   a temporary file, fsync, rename) under a per-store mutex. Everything else the console
   shows is rebuilt from the verifiers on restart.

   The interface is deliberately small so a Postgres-backed store can replace it. *)

type t = {
  dir : string;
  lock : Lwt_mutex.t;
  cache : (string, (string * Yojson.Safe.t) list) Hashtbl.t;  (** collection -> docs *)
}

let valid_name s =
  s <> ""
  && String.for_all
       (function 'a' .. 'z' | '0' .. '9' | '_' | '-' -> true | _ -> false)
       s

let rec mkdir_p d =
  if not (Sys.file_exists d) then (
    mkdir_p (Filename.dirname d);
    try Unix.mkdir d 0o750 with Unix.Unix_error (Unix.EEXIST, _, _) -> ())

let create dir =
  mkdir_p dir;
  if not (Sys.is_directory dir) then failwith (dir ^ " is not a directory");
  { dir; lock = Lwt_mutex.create (); cache = Hashtbl.create 8 }

let dir t = t.dir
let path t coll = Filename.concat t.dir (coll ^ ".json")

let read_file p =
  let ic = open_in_bin p in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () -> really_input_string ic (in_channel_length ic))

let write_atomic p contents =
  let tmp = p ^ ".tmp" in
  let fd = Unix.openfile tmp [ Unix.O_WRONLY; O_CREAT; O_TRUNC; O_CLOEXEC ] 0o640 in
  Fun.protect
    ~finally:(fun () -> try Unix.close fd with _ -> ())
    (fun () ->
      let b = Bytes.unsafe_of_string contents in
      let rec go off =
        if off < Bytes.length b then go (off + Unix.write fd b off (Bytes.length b - off))
      in
      go 0;
      Unix.fsync fd);
  Unix.rename tmp p

let load t coll =
  if not (valid_name coll) then invalid_arg ("Store: bad collection name " ^ coll);
  match Hashtbl.find_opt t.cache coll with
  | Some docs -> docs
  | None ->
      let p = path t coll in
      let docs =
        if Sys.file_exists p then
          match Yojson.Safe.from_string (read_file p) with
          | `Assoc l -> l
          | _ -> failwith (p ^ ": expected a JSON object")
        else []
      in
      Hashtbl.replace t.cache coll docs;
      docs

let save t coll docs =
  write_atomic (path t coll) (Yojson.Safe.pretty_to_string (`Assoc docs) ^ "\n");
  Hashtbl.replace t.cache coll docs

(** Every document of a collection, in insertion order. *)
let list t coll = load t coll

let get t coll id = List.assoc_opt id (load t coll)

(** Inserts or replaces a document. *)
let put t coll id doc =
  Lwt_mutex.with_lock t.lock (fun () ->
      let docs = load t coll in
      let docs =
        if List.mem_assoc id docs then
          List.map (fun (k, v) -> if k = id then (k, doc) else (k, v)) docs
        else docs @ [ (id, doc) ]
      in
      save t coll docs;
      Lwt.return_unit)

(** Atomically reads, transforms and writes one document ([None] = absent). Returning
    [None] deletes it. The result of [f] is returned. *)
let update t coll id (f : Yojson.Safe.t option -> Yojson.Safe.t option) =
  Lwt_mutex.with_lock t.lock (fun () ->
      let docs = load t coll in
      let next = f (List.assoc_opt id docs) in
      let docs =
        match next with
        | None -> List.remove_assoc id docs
        | Some d ->
            if List.mem_assoc id docs then
              List.map (fun (k, v) -> if k = id then (k, d) else (k, v)) docs
            else docs @ [ (id, d) ]
      in
      save t coll docs;
      Lwt.return next)

(** A persistent counter: returns the next value (first call returns [start]). *)
let next_counter t name ~start =
  Lwt_mutex.with_lock t.lock (fun () ->
      let docs = load t "counters" in
      let n = match List.assoc_opt name docs with Some (`Int n) -> n + 1 | _ -> start in
      save t "counters" ((name, `Int n) :: List.remove_assoc name docs);
      Lwt.return n)

(** Appends one line to an append-only JSONL log in the state dir. *)
let append_line t name (j : Yojson.Safe.t) =
  if not (valid_name name) then invalid_arg ("Store: bad log name " ^ name);
  Lwt_mutex.with_lock t.lock (fun () ->
      let p = Filename.concat t.dir (name ^ ".jsonl") in
      let oc = open_out_gen [ Open_append; Open_creat; Open_binary ] 0o640 p in
      Fun.protect
        ~finally:(fun () -> close_out_noerr oc)
        (fun () ->
          output_string oc (Yojson.Safe.to_string j);
          output_char oc '\n');
      Lwt.return_unit)

(** Every line of a JSONL log, oldest first; unparsable lines are skipped. *)
let read_lines t name =
  let p = Filename.concat t.dir (name ^ ".jsonl") in
  if not (Sys.file_exists p) then []
  else
    read_file p |> String.split_on_char '\n'
    |> List.filter_map (fun l ->
        if String.trim l = "" then None
        else try Some (Yojson.Safe.from_string l) with _ -> None)

(** A writable file path inside the state dir, for blobs such as evidence packs. *)
let blob_path t ~subdir name =
  if not (valid_name subdir) then invalid_arg "Store.blob_path";
  let d = Filename.concat t.dir subdir in
  mkdir_p d;
  Filename.concat d (Filename.basename name)

(** True when the state dir is writable (for /readyz). *)
let writable t =
  try
    let p = Filename.concat t.dir ".probe" in
    write_atomic p "ok";
    Sys.remove p;
    true
  with _ -> false
