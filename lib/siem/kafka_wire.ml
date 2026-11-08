exception Malformed of string

let malformed fmt = Printf.ksprintf (fun s -> raise (Malformed s)) fmt

(* ---- encoding ---- *)

let int8 b n = Buffer.add_char b (Char.chr (n land 0xFF))
let int16 b n = Buffer.add_uint16_be b (n land 0xFFFF)
let int32 b n = Buffer.add_int32_be b n
let int32i b n = Buffer.add_int32_be b (Int32.of_int n)
let int64 b n = Buffer.add_int64_be b n

let string b s =
  if String.length s > 0x7FFF then invalid_arg "Kafka_wire: string too long";
  int16 b (String.length s);
  Buffer.add_string b s

let null_string b = int16 b (-1)

let bytes b s =
  int32i b (String.length s);
  Buffer.add_string b s

let array b f l =
  int32i b (List.length l);
  List.iter (f b) l

let uvarint b n =
  let rec go n =
    if n land lnot 0x7F = 0 then Buffer.add_char b (Char.chr n)
    else begin
      Buffer.add_char b (Char.chr (n land 0x7F lor 0x80));
      go (n lsr 7)
    end
  in
  go n

let zigzag_varint b n = uvarint b ((n lsl 1) lxor (n asr 62))

(* ---- decoding ---- *)

type cursor = { s : string; mutable pos : int }

let need c n what =
  if n < 0 || c.pos + n > String.length c.s then malformed "truncated %s" what

let r_int8 c =
  need c 1 "int8";
  let v = Char.code c.s.[c.pos] in
  c.pos <- c.pos + 1;
  if v > 127 then v - 256 else v

let r_int16 c =
  need c 2 "int16";
  let v = String.get_int16_be c.s c.pos in
  c.pos <- c.pos + 2;
  v

let r_int32 c =
  need c 4 "int32";
  let v = String.get_int32_be c.s c.pos in
  c.pos <- c.pos + 4;
  v

let r_int32i c = Int32.to_int (r_int32 c)

let r_int64 c =
  need c 8 "int64";
  let v = String.get_int64_be c.s c.pos in
  c.pos <- c.pos + 8;
  v

let r_bool c = r_int8 c <> 0

let r_string c =
  let n = r_int16 c in
  if n < 0 then malformed "unexpected null string";
  need c n "string";
  let v = String.sub c.s c.pos n in
  c.pos <- c.pos + n;
  v

let r_nullable_string c =
  let n = r_int16 c in
  if n < 0 then None
  else begin
    need c n "string";
    let v = String.sub c.s c.pos n in
    c.pos <- c.pos + n;
    Some v
  end

let r_bytes c =
  let n = r_int32i c in
  if n < 0 then ""
  else begin
    need c n "bytes";
    let v = String.sub c.s c.pos n in
    c.pos <- c.pos + n;
    v
  end

(* Every array element takes at least one byte, which bounds the count by the
   remaining input before anything is allocated. *)
let r_array c f =
  let n = r_int32i c in
  if n < 0 then []
  else if n > String.length c.s - c.pos then malformed "array count %d exceeds input" n
  else List.init n (fun _ -> f c)

let read_uvarint s pos =
  let rec go shift acc =
    if shift >= 63 then malformed "varint too long";
    if !pos >= String.length s then malformed "truncated varint";
    let byte = Char.code s.[!pos] in
    incr pos;
    let acc = acc lor ((byte land 0x7F) lsl shift) in
    if byte land 0x80 = 0 then acc else go (shift + 7) acc
  in
  go 0 0

let read_zigzag_varint s pos =
  let n = read_uvarint s pos in
  (n lsr 1) lxor -(n land 1)

(* ---- murmur2 (32-bit arithmetic on OCaml ints, masked) ---- *)

let mask32 = 0xFFFFFFFF

let murmur2 data =
  let len = String.length data in
  let m = 0x5bd1e995 and r = 24 in
  let h = ref (0x9747b28c lxor len land mask32) in
  let byte i = Char.code data.[i] in
  for i = 0 to (len / 4) - 1 do
    let i4 = i * 4 in
    let k =
      byte i4
      lor (byte (i4 + 1) lsl 8)
      lor (byte (i4 + 2) lsl 16)
      lor (byte (i4 + 3) lsl 24)
    in
    let k = k * m land mask32 in
    let k = k lxor (k lsr r) in
    let k = k * m land mask32 in
    h := !h * m land mask32;
    h := !h lxor k
  done;
  let base = len land lnot 3 in
  let rem = len mod 4 in
  if rem >= 3 then h := !h lxor (byte (base + 2) lsl 16);
  if rem >= 2 then h := !h lxor (byte (base + 1) lsl 8);
  if rem >= 1 then begin
    h := !h lxor byte base;
    h := !h * m land mask32
  end;
  h := !h lxor (!h lsr 13);
  h := !h * m land mask32;
  h := !h lxor (!h lsr 15);
  Int32.of_int (if !h > 0x7FFFFFFF then !h - 0x100000000 else !h)

let partition_for_key key ~partitions =
  if partitions <= 0 then invalid_arg "Kafka_wire.partition_for_key";
  Int32.to_int (murmur2 key) land 0x7FFFFFFF mod partitions

(* ---- RecordBatch v2 ---- *)

type record = { key : string option; value : string }

let encode_record b ~offset_delta r =
  let body = Buffer.create (String.length r.value + 32) in
  int8 body 0 (* attributes *);
  zigzag_varint body 0 (* timestamp delta *);
  zigzag_varint body offset_delta;
  (match r.key with
  | None -> zigzag_varint body (-1)
  | Some k ->
      zigzag_varint body (String.length k);
      Buffer.add_string body k);
  zigzag_varint body (String.length r.value);
  Buffer.add_string body r.value;
  zigzag_varint body 0 (* headers *);
  zigzag_varint b (Buffer.length body);
  Buffer.add_buffer b body

let record_batch ~timestamp_ms records =
  if records = [] then invalid_arg "Kafka_wire.record_batch: no records";
  let n = List.length records in
  (* from attributes to the end: the CRC-32C covers exactly this part *)
  let tail = Buffer.create 256 in
  int16 tail 0 (* attributes: no compression, CreateTime, not transactional *);
  int32i tail (n - 1) (* last offset delta *);
  int64 tail timestamp_ms (* base timestamp *);
  int64 tail timestamp_ms (* max timestamp *);
  int64 tail (-1L) (* producer id *);
  int16 tail (-1) (* producer epoch *);
  int32i tail (-1) (* base sequence *);
  int32i tail n;
  List.iteri (fun i r -> encode_record tail ~offset_delta:i r) records;
  let tail = Buffer.contents tail in
  let crc = Crc32c.string tail in
  let b = Buffer.create (String.length tail + 21) in
  int64 b 0L (* base offset *);
  (* batch length: everything after this field *)
  int32i b (4 + 1 + 4 + String.length tail);
  int32i b (-1) (* partition leader epoch *);
  int8 b 2 (* magic *);
  Buffer.add_int32_be b (Int32.of_int crc);
  Buffer.add_string b tail;
  Buffer.contents b

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

let decode_record_batch s =
  let c = { s; pos = 0 } in
  let base_offset = r_int64 c in
  let len = r_int32i c in
  if len <> String.length s - 12 then malformed "batch length %d does not match" len;
  let partition_leader_epoch = r_int32 c in
  let magic = r_int8 c in
  if magic <> 2 then malformed "magic %d is not 2" magic;
  let crc = Int32.to_int (r_int32 c) land mask32 in
  let crc_ok = Crc32c.substring s 21 (String.length s - 21) = crc in
  let attributes = r_int16 c in
  let last_offset_delta = r_int32i c in
  let base_timestamp = r_int64 c in
  let max_timestamp = r_int64 c in
  let producer_id = r_int64 c in
  ignore (r_int16 c);
  ignore (r_int32 c);
  let n = r_int32i c in
  if n < 0 || n > String.length s then malformed "record count %d" n;
  let pos = ref c.pos in
  let records =
    List.init n (fun _ ->
        let len = read_zigzag_varint s pos in
        let stop = !pos + len in
        if len < 0 || stop > String.length s then malformed "record length";
        incr pos (* attributes *);
        ignore (read_zigzag_varint s pos);
        ignore (read_zigzag_varint s pos);
        let take l =
          if l < 0 || !pos + l > stop then malformed "record field length";
          let v = String.sub s !pos l in
          pos := !pos + l;
          v
        in
        let kl = read_zigzag_varint s pos in
        let key = if kl < 0 then None else Some (take kl) in
        let value = take (read_zigzag_varint s pos) in
        let nh = read_zigzag_varint s pos in
        if nh < 0 then malformed "record header count";
        for _ = 1 to nh do
          ignore (take (read_zigzag_varint s pos));
          let vlen = read_zigzag_varint s pos in
          if vlen >= 0 then ignore (take vlen)
        done;
        if !pos <> stop then malformed "record length mismatch";
        { key; value })
  in
  {
    base_offset;
    partition_leader_epoch;
    magic;
    crc;
    crc_ok;
    attributes;
    last_offset_delta;
    base_timestamp;
    max_timestamp;
    producer_id;
    records;
  }

(* ---- requests ---- *)

let produce = 0
let metadata = 3
let sasl_handshake = 17
let api_versions = 18
let sasl_authenticate = 36

let frame ~api_key ~api_version ~correlation_id ~client_id body =
  let h = Buffer.create (String.length body + 32) in
  int16 h api_key;
  int16 h api_version;
  int32 h correlation_id;
  string h client_id;
  Buffer.add_string h body;
  let b = Buffer.create (Buffer.length h + 4) in
  int32i b (Buffer.length h);
  Buffer.add_buffer b h;
  Buffer.contents b

let response_correlation s =
  let c = { s; pos = 0 } in
  let id = r_int32 c in
  (id, c.pos)

let body_cursor s = { s; pos = 0 }

let decode_api_versions s =
  let c = body_cursor s in
  let err = r_int16 c in
  let apis =
    r_array c (fun c ->
        let k = r_int16 c in
        let lo = r_int16 c in
        let hi = r_int16 c in
        (k, lo, hi))
  in
  (err, apis)

let metadata_request ~version ~topic =
  let b = Buffer.create 64 in
  array b string [ topic ];
  if version >= 4 then int8 b 0 (* allow_auto_topic_creation: false *);
  if version >= 8 then begin
    int8 b 0;
    int8 b 0
  end;
  Buffer.contents b

type broker = { node_id : int; host : string; port : int }
type partition_meta = { partition : int; leader : int; partition_error : int }
type topic_meta = { topic_error : int; partitions : partition_meta list }

let decode_metadata ~version ~topic s =
  let c = body_cursor s in
  if version >= 3 then ignore (r_int32 c);
  let brokers =
    r_array c (fun c ->
        let node_id = r_int32i c in
        let host = r_string c in
        let port = r_int32i c in
        if version >= 1 then ignore (r_nullable_string c);
        { node_id; host; port })
  in
  if version >= 2 then ignore (r_nullable_string c);
  if version >= 1 then ignore (r_int32 c);
  let topics =
    r_array c (fun c ->
        let topic_error = r_int16 c in
        let name = r_string c in
        if version >= 1 then ignore (r_bool c);
        let partitions =
          r_array c (fun c ->
              let partition_error = r_int16 c in
              let partition = r_int32i c in
              let leader = r_int32i c in
              if version >= 7 then ignore (r_int32 c);
              ignore (r_array c r_int32);
              ignore (r_array c r_int32);
              if version >= 5 then ignore (r_array c r_int32);
              { partition; leader; partition_error })
        in
        if version >= 8 then ignore (r_int32 c);
        (name, { topic_error; partitions = List.sort compare partitions }))
  in
  if version >= 8 then ignore (r_int32 c);
  match List.assoc_opt topic topics with
  | Some t -> (brokers, t)
  | None -> malformed "metadata response does not mention the topic"

let produce_request ~version ~acks ~timeout_ms ~topic ~partition records =
  ignore version;
  let b = Buffer.create (String.length records + 64) in
  null_string b (* transactional id *);
  int16 b acks;
  int32i b timeout_ms;
  array b
    (fun b () ->
      string b topic;
      array b
        (fun b () ->
          int32i b partition;
          bytes b records)
        [ () ])
    [ () ];
  Buffer.contents b

let decode_produce ~version ~topic ~partition s =
  let c = body_cursor s in
  let results =
    r_array c (fun c ->
        let name = r_string c in
        let parts =
          r_array c (fun c ->
              let index = r_int32i c in
              let err = r_int16 c in
              let base_offset = r_int64 c in
              if version >= 2 then ignore (r_int64 c);
              if version >= 5 then ignore (r_int64 c);
              let msg =
                if version >= 8 then begin
                  ignore
                    (r_array c (fun c ->
                         ignore (r_int32 c);
                         r_nullable_string c));
                  r_nullable_string c
                end
                else None
              in
              (index, (err, base_offset, msg)))
        in
        (name, parts))
  in
  if version >= 1 then ignore (r_int32 c) (* throttle_time_ms *);
  match Option.bind (List.assoc_opt topic results) (List.assoc_opt partition) with
  | Some r -> r
  | None -> malformed "produce response does not mention the partition"

let sasl_handshake_request mechanism =
  let b = Buffer.create 32 in
  string b mechanism;
  Buffer.contents b

let decode_sasl_handshake s =
  let c = body_cursor s in
  let err = r_int16 c in
  let mechs = r_array c r_string in
  (err, mechs)

let sasl_authenticate_request auth =
  let b = Buffer.create (String.length auth + 4) in
  bytes b auth;
  Buffer.contents b

let decode_sasl_authenticate ~version s =
  let c = body_cursor s in
  let err = r_int16 c in
  let msg = r_nullable_string c in
  let auth = r_bytes c in
  if version >= 1 then ignore (r_int64 c);
  (err, msg, auth)

(* ---- errors ---- *)

let error_name = function
  | -1 -> "UNKNOWN_SERVER_ERROR"
  | 0 -> "NONE"
  | 2 -> "CORRUPT_MESSAGE"
  | 3 -> "UNKNOWN_TOPIC_OR_PARTITION"
  | 5 -> "LEADER_NOT_AVAILABLE"
  | 6 -> "NOT_LEADER_OR_FOLLOWER"
  | 7 -> "REQUEST_TIMED_OUT"
  | 8 -> "BROKER_NOT_AVAILABLE"
  | 9 -> "REPLICA_NOT_AVAILABLE"
  | 10 -> "MESSAGE_TOO_LARGE"
  | 13 -> "NETWORK_EXCEPTION"
  | 17 -> "INVALID_TOPIC_EXCEPTION"
  | 18 -> "RECORD_LIST_TOO_LARGE"
  | 19 -> "NOT_ENOUGH_REPLICAS"
  | 20 -> "NOT_ENOUGH_REPLICAS_AFTER_APPEND"
  | 21 -> "INVALID_REQUIRED_ACKS"
  | 29 -> "TOPIC_AUTHORIZATION_FAILED"
  | 31 -> "CLUSTER_AUTHORIZATION_FAILED"
  | 33 -> "UNSUPPORTED_SASL_MECHANISM"
  | 34 -> "ILLEGAL_SASL_STATE"
  | 35 -> "UNSUPPORTED_VERSION"
  | 56 -> "KAFKA_STORAGE_ERROR"
  | 58 -> "SASL_AUTHENTICATION_FAILED"
  | 74 -> "FENCED_LEADER_EPOCH"
  | 75 -> "UNKNOWN_LEADER_EPOCH"
  | 87 -> "INVALID_RECORD"
  | n -> Printf.sprintf "ERROR_%d" n

let refresh_metadata = function 3 | 5 | 6 | 9 | 13 | 74 | 75 -> true | _ -> false

let retriable = function
  | 2 | 3 | 5 | 6 | 7 | 8 | 9 | 13 | 19 | 20 | 56 | 74 | 75 -> true
  | _ -> false
