(** A bounded pool of worker threads for work that would otherwise stall the event loop:
    policy verification ([Haltsql.verify] blocks its caller while the parser pool works)
    and audit writes to files and stdout.

    The proxy is one Lwt event loop; anything that blocks it blocks every session. Work
    handed to {!run} executes on a system thread while the loop keeps serving other
    sessions. OCaml code on these threads still shares the runtime lock with the loop
    (they interleave, they do not run in parallel); the parser releases it, as does a
    blocking [write]. *)

val default_threads : unit -> int
(** Number of CPUs, at least 2 and at most 8. *)

val configure : threads:int -> unit
(** Sets the pool's upper bound ([limits.worker_threads]). Threads are started on demand
    and kept. Lowering the bound takes effect as running jobs finish. *)

val threads : unit -> int
(** The configured bound. *)

val run : (unit -> 'a) -> 'a Lwt.t
(** [run f] evaluates [f ()] on a pool thread. When every thread is busy the job waits in
    FIFO order. [f] must not touch Lwt or state owned by the event loop. An exception
    raised by [f] rejects the promise. The promise cannot be cancelled once the job has
    started. *)
