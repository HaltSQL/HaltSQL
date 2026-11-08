(** Wires the optional enterprise integrations into {!State}'s hooks.

    {!install} sets {!State.secret_resolver} and {!State.secret_prefetch} (secret
    providers), {!State.remote_sink} (S3 / GCS audit sinks) and {!State.bundle_loader}
    (signed policy bundles). {!Server.main} calls it once, before the configuration is
    loaded. In-process tests that build a {!State.t} directly run without it, and every
    hook fails closed when unset. *)

val install : unit -> unit
(** Sets every hook. Idempotent. *)
