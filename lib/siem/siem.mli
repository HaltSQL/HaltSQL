(** Streaming audit sinks (Elasticsearch / OpenSearch, Kafka) built from the
    configuration. This is the single entry point for haltsql-server: one {!Stream_sink.t}
    per [Config.t.stream_sinks] entry, then {!Stream_sink.start}, {!Stream_sink.write} per
    audit record, {!Stream_sink.healthy} for [/readyz], {!metrics_text} for [/metrics] and
    {!Stream_sink.close} on shutdown. *)

val of_config :
  ?now:(unit -> float) ->
  ?host:string ->
  ?run_id:string ->
  ?max_attempts:int ->
  ?base_backoff:float ->
  ?max_backoff:float ->
  ?on_event:(string -> unit) ->
  Haltsql_load.Config.stream_sink ->
  (Stream_sink.t, string) result Lwt.t
(** Builds the sink (not started). Loads TLS material; does not connect, so an unreachable
    destination at startup is handled by [on_error] like any later outage.

    - [host] (default: the host name) and [run_id] (default: process start time in UTC
      with microseconds, then the pid) form the chain id ["haltsql/<host>/<run_id>"]: the
      Kafka record key, which also selects the partition. Each process starts a new chain
      at genesis.
    - [on_event] receives operational messages (failures, recoveries, drops) without
      credentials or record contents.
    - Name: ["elasticsearch://<host:port>/<target>"] or ["kafka://<broker>/<topic>"]. *)

val chain_id : host:string -> run_id:string -> string

val metrics_text : Stream_sink.t list -> string
(** Same as {!Stream_sink.metrics_text}. *)
