(** Elasticsearch / OpenSearch transport for a {!Stream_sink}: one [_bulk] request per
    batch.

    - Each record is a [create] action with [_id] = the record's chain [hash] into the
      configured [index] or [data_stream]. The document is the record's fields (so they
      are searchable) plus [event.original] (ECS): the exact sealed line, the bytes the
      hash covers. Verification starts from [event.original], because ingest pipelines and
      synthetic [_source] (the default of [logs-*-*] data streams) re-serialize documents;
      a verifier also checks that the searchable fields equal it. [create] never
      overwrites: a [409] for that [_id] means this exact record is already stored (a
      retry after a lost response) and counts as delivered.
    - Records get an [@timestamp] field (a copy of [ts], or the current UTC time) before
      they are sealed, as data streams require; it is part of the hashed record. A
      top-level [event] field is renamed [haltsql_event].
    - Per-item results: [2xx] and [409] are delivered; [429] and [5xx] are retried
      individually; [400] with a mapping error ([mapper_parsing_exception],
      [document_parsing_exception], [strict_dynamic_mapping_exception],
      [mapper_exception]) rejects that record (dropped, counted as [mapping], hash and
      error type logged); any other item error is retried and, while it persists, the sink
      is failing ([on_error] applies). Item error reasons are never logged (they can quote
      field values); only the error type is.
    - Whole-request failures (connection errors, timeouts, [401]/[403], [413], [429],
      [5xx]) fail the attempt; connection errors and [5xx] rotate to the next URL.
    - [Authorization: ApiKey <key>] or basic auth; TLS with the system roots or
      [tls.ca_file]. *)

type t

val create : ?max_response:int -> Haltsql_load.Config.es_sink -> (t, string) result Lwt.t
(** Loads the CA bundle (if any) and checks the URLs. Does not connect. *)

val name : Haltsql_load.Config.es_sink -> string
(** ["elasticsearch://<first url host:port>/<index or data stream>"]. *)

val prepare : (string * Yojson.Safe.t) list -> (string * Yojson.Safe.t) list
(** Adds [@timestamp] in front unless present, and renames a top-level [event] field
    (reserved for [event.original]) to [haltsql_event]. *)

val deliver : t -> Stream_sink.deliver

val document : string -> string
(** The document for a sealed line: its fields plus [event.original] (exposed for tests).
*)

val bulk_body : Haltsql_load.Config.es_target -> Stream_sink.entry array -> string
(** NDJSON body (exposed for tests). *)

val classify_items : int -> string -> (Stream_sink.item_result array, string) result
(** [classify_items n body] maps a 2xx [_bulk] response with [n] items to per-record
    results (exposed for tests). *)
