(* The process-wide OpenTelemetry exporter (OTLP/HTTP JSON).

   [Metrics] mirrors every Prometheus observation into [exporter ()], and the
   verify handler records one span per request. Without [telemetry.otlp] the
   exporter is [Exporter.noop], so call sites never branch. The exporter is
   replaced on reload when the [otlp] section changes. Header values are
   secrets and never logged. *)

module Exporter = Haltsql_telemetry.Exporter

let current = ref Exporter.noop
let current_cfg : Haltsql.Config.otlp option ref = ref None
let exporter () = !current

let make (c : Haltsql.Config.otlp option) =
  Exporter.of_config ~service_version:Haltsql.version
    ~on_error:(fun m -> Log.warn "OTLP export failed" ~fields:[ ("error", `String m) ])
    c

(* Startup: builds and starts the exporter. An invalid endpoint is a startup
   error. *)
let configure (c : Haltsql.Config.otlp option) =
  match make c with
  | Error e -> Error ("telemetry.otlp: " ^ e)
  | Ok e ->
      current := e;
      current_cfg := c;
      Exporter.start e;
      Ok ()

(* Reload: swaps the exporter only if the otlp section changed; the old one is
   flushed and stopped in the background. On error the old exporter stays. *)
let reconfigure (c : Haltsql.Config.otlp option) =
  if c = !current_cfg then Ok ()
  else
    match make c with
    | Error e -> Error ("telemetry.otlp: " ^ e)
    | Ok e ->
        let old = !current in
        current := e;
        current_cfg := c;
        Exporter.start e;
        Lwt.async (fun () -> Exporter.shutdown old);
        Ok ()

let shutdown () = Exporter.shutdown !current
