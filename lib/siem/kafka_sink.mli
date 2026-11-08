(** A minimal native Kafka producer for audit records (no librdkafka), used as the
    transport of a {!Stream_sink}.

    - Bootstrap: the configured brokers are tried in turn (rotating after a failure); each
      connection negotiates versions with ApiVersions, authenticates (SASL), then asks for
      the topic's metadata. Topics are never auto-created.
    - Partition: every record of a sink goes to {e one} partition so the hash chain is the
      partition's offset order. It is chosen once, like the Java default partitioner
      ([murmur2(key) mod partitions]), from the record key (the sink's chain id), and kept
      for the life of the sink even if partitions are added.
    - Produce: one RecordBatch v2 per request (no compression), [acks] -1 (all) or 1, one
      request in flight, waiting for the acknowledgement before the next one, so batches
      are never reordered. Leadership errors ([NOT_LEADER_OR_FOLLOWER],
      [LEADER_NOT_AVAILABLE], [UNKNOWN_TOPIC_OR_PARTITION], epoch errors) and connection
      failures drop the connection and the cached leader; the next attempt rediscovers the
      leader from the bootstrap brokers.
    - [MESSAGE_TOO_LARGE] / [RECORD_LIST_TOO_LARGE]: the batch is split in halves; a
      single record that is still too large is rejected (dropped, counted as [too_large]).
    - No idempotent producer: a request that times out after the broker stored it is sent
      again, so a record can appear twice (same [hash], adjacent offsets). Verifiers skip
      a record whose hash equals the previous one.
    - TLS through tls-lwt with CA verification and host name checks (system roots unless
      [tls.ca_file]); optional client certificate. SASL PLAIN, SCRAM-SHA-256 and
      SCRAM-SHA-512 (the broker's SCRAM signature is verified).

    Request versions: Produce v3-v8, Metadata v1-v8, SaslHandshake v1, SaslAuthenticate
    v0-v1 (Kafka 1.0 and later, including 4.x). *)

type t

val create :
  ?request_timeout:float ->
  ?connect_timeout:float ->
  ?on_event:(string -> unit) ->
  key:string ->
  Haltsql_load.Config.kafka_sink ->
  (t, string) result
(** Loads and checks the TLS material (CA, client certificate and key). Does not connect.
    Defaults: [request_timeout] 30 s (the broker-side produce timeout is 5 s less),
    [connect_timeout] 10 s. *)

val name : Haltsql_load.Config.kafka_sink -> string
(** ["kafka://<first broker>/<topic>"]. *)

val deliver : t -> Stream_sink.deliver
val close : t -> unit Lwt.t

val partition : t -> int option
(** The pinned partition, once known. *)
