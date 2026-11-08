(** The subset of the Kafka wire protocol a producer of audit records needs, using only
    non-flexible (pre-KIP-482) request versions: request header v1, response header v0.

    - ApiVersions v0 (always answered, whatever the broker version)
    - Metadata v1..v8
    - Produce v3..v8 with RecordBatch v2 (magic 2, CRC-32C, no compression, no
      idempotence/transactions)
    - SaslHandshake v1 and SaslAuthenticate v0..v1

    Decoders are bounds-checked and raise {!Malformed} on truncated or inconsistent input;
    sizes and counts read from the wire are validated before allocation. *)

exception Malformed of string

(** {1 Primitive encoding} *)

val zigzag_varint : Buffer.t -> int -> unit
(** Signed (zig-zag) variable-length integer, as in record fields. *)

val read_zigzag_varint : string -> int ref -> int
(** Reads one at [!pos] and advances it. *)

val murmur2 : string -> int32
(** Kafka's (and the Java client's) murmur2, used to pick a partition for a key. *)

val partition_for_key : string -> partitions:int -> int
(** [toPositive(murmur2 key) mod partitions], as the Java default partitioner. *)

(** {1 RecordBatch v2} *)

type record = { key : string option; value : string }

val record_batch : timestamp_ms:int64 -> record list -> string
(** One uncompressed batch (base offset 0, CreateTime, producer id -1). Every record has
    timestamp delta 0 and no headers. The list must not be empty. *)

type decoded_batch = {
  base_offset : int64;
  partition_leader_epoch : int32;
  magic : int;
  crc : int;
  crc_ok : bool;
  attributes : int;
  last_offset_delta : int;
  base_timestamp : int64;
  max_timestamp : int64;
  producer_id : int64;
  records : record list;
}

val decode_record_batch : string -> decoded_batch
(** Inverse of {!record_batch} (for tests and diagnostics). *)

(** {1 Requests and responses} *)

val api_versions : int
val metadata : int
val produce : int
val sasl_handshake : int
val sasl_authenticate : int

val frame :
  api_key:int ->
  api_version:int ->
  correlation_id:int32 ->
  client_id:string ->
  string ->
  string
(** Size prefix + request header v1 + body. *)

val response_correlation : string -> int32 * int
(** The correlation id of a response frame (without its size prefix) and the offset of the
    response body. *)

val decode_api_versions : string -> int * (int * int * int) list
(** [(error_code, [(api_key, min, max)])] of an ApiVersions v0 response body. *)

val metadata_request : version:int -> topic:string -> string

type broker = { node_id : int; host : string; port : int }
type partition_meta = { partition : int; leader : int; partition_error : int }

type topic_meta = {
  topic_error : int;
  partitions : partition_meta list;  (** sorted by partition index *)
}

val decode_metadata : version:int -> topic:string -> string -> broker list * topic_meta
(** Brokers and the requested topic. A response without the topic is {!Malformed}. *)

val produce_request :
  version:int ->
  acks:int ->
  timeout_ms:int ->
  topic:string ->
  partition:int ->
  string ->
  string
(** One topic, one partition, one batch ([acks] is [-1] or [1]). *)

val decode_produce :
  version:int -> topic:string -> partition:int -> string -> int * int64 * string option
(** [(error_code, base_offset, error_message)] for the partition. *)

val sasl_handshake_request : string -> string
val decode_sasl_handshake : string -> int * string list
val sasl_authenticate_request : string -> string

val decode_sasl_authenticate : version:int -> string -> int * string option * string
(** [(error_code, error_message, auth_bytes)]. *)

(** {1 Error codes} *)

val error_name : int -> string

val retriable : int -> bool
(** Transient errors worth retrying (leadership changes, timeouts, under-replication). *)

val refresh_metadata : int -> bool
(** Errors that mean the cached leader / partition metadata is stale. *)
