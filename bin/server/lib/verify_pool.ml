(* Verification off the Lwt event loop; see verify_pool.mli. *)

let configured = ref false

let max_threads () =
  match Option.bind (Sys.getenv_opt "HALTSQL_VERIFY_THREADS") int_of_string_opt with
  | Some n when n >= 1 && n <= 256 -> n
  | Some _ | None -> max 2 (min 32 (Domain.recommended_domain_count ()))

let configure () =
  if not !configured then begin
    configured := true;
    let n = max_threads () in
    Lwt_preemptive.simple_init ();
    Lwt_preemptive.set_bounds (0, n);
    (* Requests beyond the pool wait in a bounded queue; when it is full, [detach]
       itself waits, which backpressures the accept loop instead of growing memory. *)
    Lwt_preemptive.set_max_number_of_threads_queued (n * 64)
  end

let verify policy ctx sql =
  configure ();
  (* [Haltsql.verify] never raises (every exception becomes an E_INTERNAL denial), and
     the parser layer is thread-safe and releases the runtime lock while it parses. *)
  Lwt_preemptive.detach (fun () -> Haltsql.verify policy ctx sql) ()
