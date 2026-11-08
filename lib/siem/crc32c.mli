(** CRC-32C (Castagnoli, reflected polynomial [0x82F63B78]), as used by Kafka RecordBatch
    v2. Values are non-negative and below 2{^ 32}. *)

val string : ?crc:int -> string -> int
(** [string s] is the CRC-32C of [s]. [?crc] continues a previous result. *)

val substring : ?crc:int -> string -> int -> int -> int
(** [substring s off len]. *)
