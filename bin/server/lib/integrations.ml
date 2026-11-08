(* Wires the optional enterprise integrations into the server's hooks
   ([State.secret_resolver], [State.secret_prefetch], [State.remote_sink],
   [State.bundle_loader]). Called once by [Server.main] before the config is
   loaded; in-process tests that build [State] directly run without them, and
   every hook fails closed when unset. *)

open Haltsql
module Secrets = Haltsql_cloud.Secrets

let read_file f =
  match In_channel.with_open_bin f In_channel.input_all with
  | s -> s
  | exception Sys_error _ -> ""

(* Startup (before Lwt_main.run): fetches each provider placeholder on demand.
   Configs without provider placeholders never call it. *)
let blocking_secret_resolver (secrets : Config.secrets) =
  Ok (Secrets.blocking_resolver (Secrets.create secrets))

(* Reload (inside Lwt): prefetch every placeholder concurrently, then serve the
   cached values. A placeholder the scan cannot see (e.g. written with YAML
   escapes) fails closed with "secret was not prefetched". *)
let prefetching_secret_resolver ~file (secrets : Config.secrets) =
  let t = Secrets.create secrets in
  Lwt.map
    (fun () -> Secrets.cached_resolver t)
    (Secrets.prefetch t (Secrets.scan_placeholders (read_file file)))

let remote_sink (kind : Config.sink_kind) ~on_error =
  let on_event m = Log.warn "audit sink event" ~fields:[ ("event", `String m) ] in
  let created =
    match kind with
    | Config.Sink_s3 c -> Haltsql_cloud.S3_sink.create ~on_error ~on_event c
    | Config.Sink_gcs c -> Haltsql_cloud.Gcs_sink.create ~on_error ~on_event c
    | Config.Sink_stdout | Config.Sink_file _ -> Error "not an object-store sink"
  in
  Result.map
    (fun obj ->
      let sink = Audit.of_object_sink obj in
      Audit.start sink;
      sink)
    created

(* Verifies the bundle's detached signature against the configured keys before
   parsing it. Policies are returned unprefixed: State applies name_prefix and
   re-checks every policy reference afterwards. *)
let bundle_loader (r : Config.bundle_ref) =
  match Haltsql_bundle.load_config_ref { r with name_prefix = None } with
  | Ok ps -> Ok (List.map (fun (p : Policy.t) -> (p.name, p)) ps)
  | Error e -> Error (Haltsql_bundle.error_to_string e)

let install () =
  State.secret_resolver := Some blocking_secret_resolver;
  State.secret_prefetch := Some prefetching_secret_resolver;
  State.remote_sink := Some remote_sink;
  State.bundle_loader := Some bundle_loader
