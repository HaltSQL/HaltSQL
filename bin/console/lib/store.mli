(** Durable console state: human input only (cases, signal workflow, evidence pack index,
    counters). Everything else the console shows is rebuilt from the verifiers on restart.

    {1 Contract}

    This interface is the seam for a later Postgres-backed store; any implementation must
    satisfy the following, and callers must not rely on anything else:

    - A store holds named {e collections} of JSON documents keyed by a string id.
      Collection names match [[a-z0-9_-]+].
    - [put], [update] and [next_counter] are durable when their promise resolves: a crash
      afterwards never loses the write. A rejected promise means the write did not happen.
      A write that has started runs to completion even if its promise is cancelled.
    - Writes to one collection are serialised; writes to different collections are
      independent and may proceed concurrently. [update] is an atomic read-modify-write of
      one document.
    - Reads ([get], [count], [iter], [fold]) never block on I/O and see every write whose
      promise has resolved. [iter]/[fold] visit documents in insertion order (replacing a
      document keeps its position) over a consistent snapshot taken when they start.
    - There is deliberately no "return every document as a list": callers stream with
      [iter]/[fold] and keep only what they need.
    - [create] fails (raises [Failure] naming the file and line) when existing state is
      corrupt, so a bad state dir is found at startup rather than on every request.

    {1 File implementation}

    Each collection [c] is a snapshot [c.json] (a JSON object, one member per line, in
    insertion order) plus an append-only operation log [c.log] (one JSON line per
    put/delete, fsynced before the write resolves). Loading replays the snapshot and then
    the log; an unparsable {e last} log line is a torn append from a crash and is dropped,
    any other unparsable line is fatal. A write or fsync error truncates the log back to
    its last good size (and fsyncs) before the write is rejected; if that rollback fails
    too, the collection refuses every later write ([Failure]) until restart, and the
    rejected op may still be in the log. A compaction failure does not reject the write
    that triggered it: it is logged to stderr and retried on a later write. When the log
    exceeds [max compact_min_ops (2 * live documents)] operations the collection is
    compacted: a new snapshot is written to a temporary file, fsynced, renamed over
    [c.json], the directory is fsynced and the log truncated. All file I/O runs off the
    Lwt event loop. Each collection has its own lock. *)

type t

val create : ?compact_min_ops:int -> string -> t
(** [create dir] opens (creating if needed) the store in [dir] and eagerly loads every
    existing collection. Synchronous: call it at startup. [compact_min_ops] (default 1000)
    is the minimum log length before compaction; tests lower it. Raises [Failure] on
    corrupt state, naming the file and line, and on I/O errors (e.g. the directory cannot
    be created), as ["<path>: <message>"]. *)

val dir : t -> string
(** The state directory (file implementation only; evidence packs and the activity log
    live beside the collections). *)

val get : t -> string -> string -> Yojson.Safe.t option
(** [get t coll id] is the document [id] of [coll], if any. *)

val count : t -> string -> int
(** Number of documents in a collection. *)

val iter : t -> string -> (string -> Yojson.Safe.t -> unit) -> unit
(** [iter t coll f] calls [f id doc] for every document, in insertion order. *)

val fold : t -> string -> (string -> Yojson.Safe.t -> 'a -> 'a) -> 'a -> 'a
(** [fold t coll f init] folds over every document, in insertion order. *)

val put : t -> string -> string -> Yojson.Safe.t -> unit Lwt.t
(** Inserts or replaces a document (a replaced document keeps its position). *)

val update :
  t ->
  string ->
  string ->
  (Yojson.Safe.t option -> Yojson.Safe.t option) ->
  Yojson.Safe.t option Lwt.t
(** [update t coll id f] atomically reads document [id] ([None] = absent), applies [f] and
    stores the result; [None] deletes it. Returns the result of [f]. If [f] raises,
    nothing is written and the exception propagates. *)

val delete : t -> string -> string -> unit Lwt.t
(** Removes a document (no-op when absent). *)

val next_counter : t -> string -> start:int -> int Lwt.t
(** A persistent counter: returns the next value (the first call returns [start]). *)

val blob_path : t -> subdir:string -> string -> string
(** A writable file path inside the state dir, for blobs such as evidence packs (file
    implementation only). *)

val writable : t -> bool Lwt.t
(** True when the state dir accepts a durable write (for /readyz). Off the event loop. *)

(** {1 Off-event-loop file helpers}

    Shared with [Activity]; not part of the swappable contract. *)

val write_all : Lwt_unix.file_descr -> string -> unit Lwt.t
(** Writes the whole string. *)

val fsync : Lwt_unix.file_descr -> unit Lwt.t
(** fsyncs a file (through [io.fsync]). *)

val append_line :
  Lwt_unix.file_descr ->
  good_size:int ->
  string ->
  [ `Ok | `Rolled_back of exn | `Lost of exn * exn ] Lwt.t
(** [append_line fd ~good_size line] writes [line] to an append-mode [fd] and fsyncs it.
    On a write or fsync error [e] the file is truncated back to [good_size] and fsynced:
    [`Rolled_back e] when that worked, [`Lost (e, rollback_error)] when it did not (the
    file may now hold part or all of [line]; the caller must stop appending). Never
    rejects. *)

val log_stderr : level:string -> string -> unit
(** One JSON log line on stderr, in the console's log format. *)

val fsync_dir : string -> unit Lwt.t
(** fsyncs a directory so a create/rename/unlink in it is durable. Best effort on
    platforms that refuse to fsync directories. *)

val read_lines_from :
  string -> (lineno:int -> offset:int -> last:bool -> string -> unit) -> unit
(** [read_lines_from path f] calls [f ~lineno ~offset ~last line] for every non-blank line
    of [path] in order, streaming (synchronous; for startup loading and evidence packs).
    [offset] is the byte offset where the line starts; [last] is true for the final
    non-blank line, whether or not it ends with a newline. *)

(** {1 Fault injection}

    For tests only: the low-level calls the store and the activity log use for appends,
    fsyncs and compaction renames. Replace a field to inject a failure; [reset_io]
    restores the real calls. *)

type io_hooks = {
  mutable write : Lwt_unix.file_descr -> Bytes.t -> int -> int -> int Lwt.t;
  mutable fsync : Lwt_unix.file_descr -> unit Lwt.t;
  mutable rename : string -> string -> unit Lwt.t;
}

val io : io_hooks
val reset_io : unit -> unit
