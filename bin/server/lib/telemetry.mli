(** The process-wide OpenTelemetry exporter (OTLP/HTTP JSON, [telemetry.otlp]).

    {!Metrics} mirrors every Prometheus observation into [exporter ()], and the verify
    handler records one span per request (carrying the SQL hash, never the SQL). Without
    [telemetry.otlp] the exporter is [Exporter.noop], so call sites never branch. OTLP
    header values are secrets and are never logged. *)

module Exporter = Haltsql_telemetry.Exporter

val exporter : unit -> Exporter.t
(** The current exporter. *)

val current_cfg : Haltsql.Config.otlp option ref
(** The [otlp] section the current exporter was built from. Treat as read-only (exposed
    for tests). *)

val configure : Haltsql.Config.otlp option -> (unit, string) result
(** Startup: builds and starts the exporter. An invalid endpoint is an error. *)

val reconfigure : Haltsql.Config.otlp option -> (unit, string) result
(** Reload: replaces the exporter only if the section changed; the old one is flushed and
    stopped in the background. On error the old exporter stays. *)

val shutdown : unit -> unit Lwt.t
(** Final flush and stop, at process exit. *)
