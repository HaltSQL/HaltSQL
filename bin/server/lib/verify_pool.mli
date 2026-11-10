(** Runs {!Haltsql.verify} on a bounded pool of system threads so that a large or
    pathological statement cannot stall the event loop (other requests, the health
    listener, reloads, audit shipping).

    Pool size: [HALTSQL_VERIFY_THREADS] (1-256), default the number of CPUs (2-32).
    Waiting requests are queued up to 64 per thread; beyond that callers wait. *)

val verify : Haltsql.Policy.t -> Haltsql.Context.t -> string -> Haltsql.Verdict.t Lwt.t
(** Same verdict as [Haltsql.verify policy ctx sql]; never fails. *)
