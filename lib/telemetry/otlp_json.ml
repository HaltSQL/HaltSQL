type value =
  | String of string
  | Int of int
  | Float of float
  | Bool of bool
  | Strings of string list

type attrs = (string * value) list

let i64 n = `String (Int64.to_string n)
let int_s n = `String (string_of_int n)

let rec any_value : value -> Yojson.Safe.t = function
  | String s -> `Assoc [ ("stringValue", `String s) ]
  | Int i -> `Assoc [ ("intValue", int_s i) ]
  | Float f -> `Assoc [ ("doubleValue", `Float f) ]
  | Bool b -> `Assoc [ ("boolValue", `Bool b) ]
  | Strings l ->
      `Assoc
        [
          ( "arrayValue",
            `Assoc [ ("values", `List (List.map (fun s -> any_value (String s)) l)) ] );
        ]

let attributes (a : attrs) : Yojson.Safe.t =
  `List (List.map (fun (k, v) -> `Assoc [ ("key", `String k); ("value", any_value v) ]) a)

type span_kind = Internal | Server | Client

let span_kind_code = function Internal -> 1 | Server -> 2 | Client -> 3

type status = Unset | Ok | Error of string

type span = {
  trace_id : string;
  span_id : string;
  parent_span_id : string option;
  name : string;
  kind : span_kind;
  start_ns : int64;
  end_ns : int64;
  attributes : attrs;
  status : status;
  flags : int;
}

type scope = { scope_name : string; scope_version : string }

let scope_json s =
  `Assoc [ ("name", `String s.scope_name); ("version", `String s.scope_version) ]

let resource_json r = `Assoc [ ("attributes", attributes r) ]

let status_json = function
  | Unset -> `Assoc [ ("code", `Int 0) ]
  | Ok -> `Assoc [ ("code", `Int 1) ]
  | Error m -> `Assoc [ ("code", `Int 2); ("message", `String m) ]

let span_json (s : span) =
  `Assoc
    ([ ("traceId", `String s.trace_id); ("spanId", `String s.span_id) ]
    @ (match s.parent_span_id with
      | Some p -> [ ("parentSpanId", `String p) ]
      | None -> [])
    @ [
        ("flags", `Int (s.flags land 0xFF));
        ("name", `String s.name);
        ("kind", `Int (span_kind_code s.kind));
        ("startTimeUnixNano", i64 s.start_ns);
        ("endTimeUnixNano", i64 s.end_ns);
        ("attributes", attributes s.attributes);
        ("status", status_json s.status);
      ])

let traces_request ~resource ~scope spans =
  `Assoc
    [
      ( "resourceSpans",
        `List
          [
            `Assoc
              [
                ("resource", resource_json resource);
                ( "scopeSpans",
                  `List
                    [
                      `Assoc
                        [
                          ("scope", scope_json scope);
                          ("spans", `List (List.map span_json spans));
                        ];
                    ] );
              ];
          ] );
    ]

type hist_point = {
  h_attrs : attrs;
  bucket_counts : int array;
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
    }
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
      bounds : float array;
      points : hist_point list;
    }

let temporality_cumulative = 2

let metrics_request ~resource ~scope ~start_ns ~time_ns metrics =
  let times = [ ("startTimeUnixNano", i64 start_ns); ("timeUnixNano", i64 time_ns) ] in
  let head name description unit_ =
    [
      ("name", `String name); ("description", `String description); ("unit", `String unit_);
    ]
  in
  let metric_json = function
    | Sum { name; description; unit_; points } ->
        `Assoc
          (head name description unit_
          @ [
              ( "sum",
                `Assoc
                  [
                    ( "dataPoints",
                      `List
                        (List.map
                           (fun (a, v) ->
                             `Assoc
                               ((("attributes", attributes a) :: times)
                               @ [ ("asInt", int_s v) ]))
                           points) );
                    ("aggregationTemporality", `Int temporality_cumulative);
                    ("isMonotonic", `Bool true);
                  ] );
            ])
    | Gauge { name; description; unit_; points } ->
        `Assoc
          (head name description unit_
          @ [
              ( "gauge",
                `Assoc
                  [
                    ( "dataPoints",
                      `List
                        (List.map
                           (fun (a, v) ->
                             `Assoc
                               ((("attributes", attributes a) :: times)
                               @ [ ("asDouble", `Float v) ]))
                           points) );
                  ] );
            ])
    | Histogram { name; description; unit_; bounds; points } ->
        `Assoc
          (head name description unit_
          @ [
              ( "histogram",
                `Assoc
                  [
                    ( "dataPoints",
                      `List
                        (List.map
                           (fun p ->
                             `Assoc
                               ((("attributes", attributes p.h_attrs) :: times)
                               @ [
                                   ("count", int_s p.h_count);
                                   ("sum", `Float p.h_sum);
                                   ( "bucketCounts",
                                     `List
                                       (Array.to_list (Array.map int_s p.bucket_counts))
                                   );
                                   ( "explicitBounds",
                                     `List
                                       (Array.to_list
                                          (Array.map (fun b -> `Float b) bounds)) );
                                 ]
                               @ (match p.h_min with
                                 | Some m -> [ ("min", `Float m) ]
                                 | None -> [])
                               @
                               match p.h_max with
                               | Some m -> [ ("max", `Float m) ]
                               | None -> []))
                           points) );
                    ("aggregationTemporality", `Int temporality_cumulative);
                  ] );
            ])
  in
  `Assoc
    [
      ( "resourceMetrics",
        `List
          [
            `Assoc
              [
                ("resource", resource_json resource);
                ( "scopeMetrics",
                  `List
                    [
                      `Assoc
                        [
                          ("scope", scope_json scope);
                          ("metrics", `List (List.map metric_json metrics));
                        ];
                    ] );
              ];
          ] );
    ]
