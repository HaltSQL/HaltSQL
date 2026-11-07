(** Pure OTLP/HTTP JSON encoders (the protobuf-JSON mapping of
    [opentelemetry/proto/collector/{trace,metrics}/v1]).

    Per the OTLP JSON rules: trace and span ids are lower-case hex strings, 64-bit
    integers ([*TimeUnixNano], [asInt], [count], [bucketCounts]) are decimal strings,
    enums are integers, and field names are lowerCamelCase. *)

type value =
  | String of string
  | Int of int
  | Float of float
  | Bool of bool
  | Strings of string list  (** encoded as an [arrayValue] of [stringValue]s *)

type attrs = (string * value) list

val any_value : value -> Yojson.Safe.t

val attributes : attrs -> Yojson.Safe.t
(** A list of [KeyValue] objects. *)

type span_kind = Internal | Server | Client

val span_kind_code : span_kind -> int
(** [SPAN_KIND_INTERNAL] = 1, [SERVER] = 2, [CLIENT] = 3. *)

type status = Unset | Ok | Error of string

type span = {
  trace_id : string;  (** 32 hex *)
  span_id : string;  (** 16 hex *)
  parent_span_id : string option;
  name : string;
  kind : span_kind;
  start_ns : int64;
  end_ns : int64;
  attributes : attrs;
  status : status;
  flags : int;  (** W3C trace flags *)
}

type scope = { scope_name : string; scope_version : string }

val traces_request : resource:attrs -> scope:scope -> span list -> Yojson.Safe.t
(** [ExportTraceServiceRequest]: one [resourceSpans] with one [scopeSpans]. *)

type hist_point = {
  h_attrs : attrs;
  bucket_counts : int array;  (** per bucket (not cumulative); length = bounds + 1 *)
  h_sum : float;
  h_count : int;
  h_min : float option;
  h_max : float option;
}

type metric =
  | Sum of {
      name : string;
      description : string;
      unit_ : string;
      points : (attrs * int) list;
    }  (** monotonic, cumulative integer counter *)
  | Gauge of {
      name : string;
      description : string;
      unit_ : string;
      points : (attrs * float) list;
    }
  | Histogram of {
      name : string;
      description : string;
      unit_ : string;
      bounds : float array;  (** [explicitBounds] *)
      points : hist_point list;
    }  (** cumulative explicit-bucket histogram *)

val metrics_request :
  resource:attrs ->
  scope:scope ->
  start_ns:int64 ->
  time_ns:int64 ->
  metric list ->
  Yojson.Safe.t
(** [ExportMetricsServiceRequest]; [start_ns] is the cumulative start time. *)

val temporality_cumulative : int
(** [AGGREGATION_TEMPORALITY_CUMULATIVE] = 2. *)
