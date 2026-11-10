(* Append-only activity log: who saw or did what, and why.

   Every entry gets a persisted, strictly increasing integer [seq]. Entries are appended
   (one JSON line, fsynced) to [activity.jsonl] in the state dir; when that file would
   exceed [max_file_bytes] it is renamed to [activity-<first seq>.jsonl] and a new one is
   started. Rotated files are kept forever: this is an audit trail, and retention or
   archival (moving old files to object storage, deleting them) is an operator concern.

   The most recent [window] entries are also held in memory (loaded at startup from the
   tail of the files); GET /api/v1/activity only queries that window. Evidence packs read
   every file through [iter_all].

   A failed append (write or fsync error) is rolled back by truncating the file to its
   last good size; if that fails too, the log refuses every later append until restart.
   A seq is consumed when an append starts, so it is never reused, even after a failure
   (the failed entry leaves a gap). Appends and rotations run under [Lwt.no_cancel]. *)

open Lwt.Syntax

let default_max_file_bytes = 64 * 1024 * 1024
let default_window = 50_000
let current_name = "activity.jsonl"

type entry = {
  seq : int;
  at : float option;
  actor : string option;
  action : string option;
  json : Yojson.Safe.t;  (** the stored line, including [seq] *)
}

type state = {
  dir : string;
  max_file_bytes : int;
  window : int;
  lock : Lwt_mutex.t;
  recent : entry Queue.t;  (** oldest first, at most [window] *)
  mutable last_seq : int;  (** last seq handed out; 0 before the first entry *)
  mutable cur_first_seq : int option;  (** seq of the first entry in [activity.jsonl] *)
  mutable cur_size : int;  (** bytes of complete, fsynced entries in [activity.jsonl] *)
  mutable fd : Lwt_unix.file_descr option;
  mutable poisoned : string option;  (** why appends are refused until restart *)
}

let str name j = match Api.member name j with Some (`String s) -> Some s | _ -> None

let entry_of_json seq j =
  let j =
    match j with
    | `Assoc l when not (List.mem_assoc "seq" l) -> `Assoc (("seq", `Int seq) :: l)
    | j -> j
  in
  {
    seq;
    at = Option.bind (str "at" j) Api.parse_time;
    actor = str "actor" j;
    action = str "action" j;
    json = j;
  }

let rotated_seq f = Scanf.sscanf_opt (Filename.basename f) "activity-%d.jsonl%!" Fun.id

(* [activity-<n>.jsonl] files, oldest first, then [activity.jsonl] if present. *)
let files dir =
  let rotated =
    Sys.readdir dir |> Array.to_list
    |> List.filter_map (fun f ->
        Option.map (fun n -> (n, Filename.concat dir f)) (rotated_seq f))
    |> List.sort compare |> List.map snd
  in
  let cur = Filename.concat dir current_name in
  if Sys.file_exists cur then rotated @ [ cur ] else rotated

(* Calls [f seq_opt json] for each line of one file. A torn last line of the current
   file (crash mid-append) is truncated away; other unparsable lines are reported and
   skipped (the bytes stay in the file for evidence). *)
let read_file ~current path f =
  let torn = ref None in
  Store.read_lines_from path (fun ~lineno ~offset ~last line ->
      match Yojson.Safe.from_string line with
      | j ->
          let seq = match Api.member "seq" j with Some (`Int n) -> Some n | _ -> None in
          f seq j
      | exception Yojson.Json_error _ when last && current -> torn := Some offset
      | exception Yojson.Json_error m ->
          Store.log_stderr ~level:"warn"
            (Printf.sprintf "%s:%d: skipping unparsable activity line: %s" path lineno m));
  Option.iter (Unix.truncate path) !torn

let load ~max_file_bytes ~window dir =
  let st =
    {
      dir;
      max_file_bytes;
      window;
      lock = Lwt_mutex.create ();
      recent = Queue.create ();
      last_seq = 0;
      cur_first_seq = None;
      cur_size = 0;
      fd = None;
      poisoned = None;
    }
  in
  let cur = Filename.concat dir current_name in
  (* Read files newest first until the window is full; each file's entries go in front
     of what newer files contributed. *)
  let rec go acc count = function
    | [] -> acc
    | _ when count >= window -> acc
    | path :: older ->
        let is_cur = path = cur in
        let q = Queue.create () in
        read_file ~current:is_cur path (fun seq j -> Queue.add (is_cur, seq, j) q);
        go (List.of_seq (Queue.to_seq q) @ acc) (count + Queue.length q) older
  in
  let all_files = files dir in
  let raw = go [] 0 (List.rev all_files) in
  (* entries written before seqs existed get one right after the previous entry *)
  let prev = ref 0 in
  let entries =
    List.map
      (fun (is_cur, seq, j) ->
        let seq = match seq with Some n when n > !prev -> n | _ -> !prev + 1 in
        prev := seq;
        if is_cur && st.cur_first_seq = None then st.cur_first_seq <- Some seq;
        entry_of_json seq j)
      raw
  in
  let n = List.length entries in
  List.iteri (fun i e -> if i >= n - window then Queue.add e st.recent) entries;
  (* a rotated file's name is the seq of its first entry: never reuse one *)
  st.last_seq <-
    List.fold_left
      (fun m f -> match rotated_seq f with Some s -> max m s | None -> m)
      !prev all_files;
  if Sys.file_exists cur then st.cur_size <- (Unix.stat cur).st_size;
  st

(* One state per store instance (physical identity), created by [init] or on first use. *)
module Tbl = Hashtbl.Make (struct
  type t = Store.t

  let equal = ( == )
  let hash s = Hashtbl.hash (Store.dir s)
end)

let states : state Tbl.t = Tbl.create 4

(** Loads the activity log of [store] (the in-memory window and the last seq). Call it at
    startup; otherwise the first use loads it with the defaults. A second call for the
    same store is a no-op. [max_file_bytes] (default 64 MiB) and [window] (default 50_000
    entries) are for tests. *)
let init ?(max_file_bytes = default_max_file_bytes) ?(window = default_window) store =
  if not (Tbl.mem states store) then
    Tbl.replace states store
      (load ~max_file_bytes ~window:(max 1 window) (Store.dir store))

let state store =
  match Tbl.find_opt states store with
  | Some st -> st
  | None ->
      init store;
      Tbl.find states store

let open_current st =
  match st.fd with
  | Some fd -> Lwt.return fd
  | None ->
      let p = Filename.concat st.dir current_name in
      let fresh = not (Sys.file_exists p) in
      let* fd =
        Lwt_unix.openfile p [ Unix.O_WRONLY; O_APPEND; O_CREAT; O_CLOEXEC ] 0o640
      in
      st.fd <- Some fd;
      let* () = if fresh then Store.fsync_dir st.dir else Lwt.return_unit in
      Lwt.return fd

let rotate st =
  match st.cur_first_seq with
  | None -> Lwt.return_unit
  | Some first ->
      let* () =
        match st.fd with
        | Some fd ->
            st.fd <- None;
            (* every entry in it is already fsynced *)
            Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
        | None -> Lwt.return_unit
      in
      let* () =
        Lwt_unix.rename
          (Filename.concat st.dir current_name)
          (Filename.concat st.dir (Printf.sprintf "activity-%d.jsonl" first))
      in
      (* the rename happened: [activity.jsonl] is gone whatever the directory fsync does,
         so the next append must start a new one *)
      st.cur_first_seq <- None;
      st.cur_size <- 0;
      Store.fsync_dir st.dir

let poisoned_error why =
  Failure
    ("activity log refuses appends until restart: a failed append could not be rolled \
      back (" ^ why ^ ")")

let append store fields =
  let st = state store in
  Lwt_mutex.with_lock st.lock (fun () ->
      match st.poisoned with
      | Some why -> Lwt.fail (poisoned_error why)
      | None -> (
          (* reserve the seq first: a failed append leaves a gap, never a reused seq *)
          let seq = st.last_seq + 1 in
          st.last_seq <- seq;
          let json = `Assoc (("seq", `Int seq) :: fields) in
          let line = Yojson.Safe.to_string json ^ "\n" in
          Lwt.no_cancel
          @@ let* () =
               if st.cur_size > 0 && st.cur_size + String.length line > st.max_file_bytes
               then rotate st
               else Lwt.return_unit
             in
             let* fd = open_current st in
             let* r = Store.append_line fd ~good_size:st.cur_size line in
             match r with
             | `Ok ->
                 st.cur_size <- st.cur_size + String.length line;
                 if st.cur_first_seq = None then st.cur_first_seq <- Some seq;
                 Queue.add (entry_of_json seq json) st.recent;
                 if Queue.length st.recent > st.window then ignore (Queue.take st.recent);
                 Lwt.return_unit
             | `Rolled_back e -> Lwt.fail e
             | `Lost (e, e') ->
                 let why =
                   Printf.sprintf "%s; truncating %s back to %d bytes: %s"
                     (Printexc.to_string e)
                     (Filename.concat st.dir current_name)
                     st.cur_size (Printexc.to_string e')
                 in
                 st.poisoned <- Some why;
                 Store.log_stderr ~level:"error" ("activity log poisoned: " ^ why);
                 Lwt.fail e))

(** Appends one entry, durably (fsynced before the promise resolves). *)
let log (ctx : Ctx.t) (p : Ctx.principal) ?reason ?(detail = `Assoc []) ~action ~target ()
    =
  append ctx.store
    [
      ("at", `String (Api.iso8601 (Ctx.now ())));
      ("actor", `String p.id);
      ("role", `String (Rbac.role_to_string p.role));
      ("auth", `String p.auth);
      ("action", `String action);
      ("target", `String target);
      ("reason", Api.opt_string reason);
      ("detail", detail);
    ]

(** The in-memory window, newest first. *)
let recent (ctx : Ctx.t) =
  Queue.fold (fun acc e -> e.json :: acc) [] (state ctx.store).recent

(** The last seq handed out (0 when the log is empty). A failed append consumes a seq, so
    this can be ahead of the last entry actually written. *)
let last_seq (ctx : Ctx.t) = (state ctx.store).last_seq

(** Streams every entry ever logged, oldest first, from every file (rotated and current),
    for evidence packs. Entries appended after the call starts are not included. Reads run
    off the event loop. *)
let iter_all (ctx : Ctx.t) (f : Yojson.Safe.t -> unit Lwt.t) =
  let st = state ctx.store in
  (* open every file and note the current file's size under the lock, so neither a
     concurrent rotation nor a half-written append is seen *)
  let opened = ref [] in
  let open_all () =
    Lwt_mutex.with_lock st.lock (fun () ->
        Lwt_list.iter_s
          (fun path ->
            let* ic = Lwt_io.open_file ~mode:Lwt_io.input path in
            let limit =
              if Filename.basename path = current_name then Some st.cur_size else None
            in
            opened := (ic, limit) :: !opened;
            Lwt.return_unit)
          (files st.dir))
  in
  let read (ic, limit) =
    let rec loop consumed =
      match limit with
      | Some l when consumed >= l -> Lwt.return_unit
      | _ -> (
          let* line = Lwt_io.read_line_opt ic in
          match line with
          | None -> Lwt.return_unit
          | Some line ->
              let* () =
                if String.trim line = "" then Lwt.return_unit
                else
                  match Yojson.Safe.from_string line with
                  | j -> f j
                  | exception Yojson.Json_error _ -> Lwt.return_unit
              in
              loop (consumed + String.length line + 1))
    in
    loop 0
  in
  (* every channel opened so far is closed on every path, including a failed open *)
  Lwt.finalize
    (fun () ->
      let* () = open_all () in
      Lwt_list.iter_s read (List.rev !opened))
    (fun () ->
      Lwt_list.iter_s
        (fun (ic, _) -> Lwt.catch (fun () -> Lwt_io.close ic) (fun _ -> Lwt.return_unit))
        !opened)

let routes =
  [
    Router.get "/api/v1/activity" (fun ctx p r ->
        let req = r.Router.http in
        ignore (Ctx.require p req Rbac.View_activity);
        let actor = Api.query req "actor" and action = Api.query req "action" in
        let since = Option.bind (Api.query req "since") Api.parse_time in
        let keep e =
          (match actor with None -> true | Some a -> e.actor = Some a)
          && (match action with
            | None -> true
            | Some a -> (
                match e.action with
                | Some x -> String.starts_with ~prefix:a x
                | None -> false))
          &&
          match since with
          | None -> true
          | Some t -> ( match e.at with Some x -> x >= t | None -> false)
        in
        let st = state ctx.store in
        (* newest first, as page_desc needs *)
        let matching =
          Queue.fold (fun acc e -> if keep e then e :: acc else acc) [] st.recent
        in
        let items, next, total = Api.page_desc req ~key:(fun e -> e.seq) matching in
        let oldest =
          match Queue.peek_opt st.recent with Some e -> `Int e.seq | None -> `Null
        in
        Api.json
          (`Assoc
             [
               ("entries", `List (List.map (fun e -> e.json) items));
               ("next_cursor", next);
               ("total", `Int total);
               ("window_oldest_seq", oldest);
             ]));
  ]
