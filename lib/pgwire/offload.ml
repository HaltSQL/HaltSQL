(** Worker threads; see offload.mli. *)

let default_threads () = max 2 (min 8 (Domain.recommended_domain_count ()))
let configure ~threads = Lwt_preemptive.init 0 (max 1 threads) ignore
let threads () = snd (Lwt_preemptive.get_bounds ())
let run f = Lwt_preemptive.detach f ()
