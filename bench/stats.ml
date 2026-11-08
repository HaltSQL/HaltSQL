(* Latency summaries and the result records every suite produces. *)

type result = {
  suite : string;  (** library | cli | http | proxy | calibration *)
  name : string;  (** workload name, unique within the suite *)
  unit_ : string;  (** unit of the latency fields: "us" or "ms" *)
  samples : int;  (** number of timed operations *)
  p50 : float;
  p90 : float;
  p99 : float;
  p999 : float;
  max : float;
  mean : float;
  throughput : float;  (** operations per second over the timed window *)
  errors : int;
  gate : bool;  (** compared against the baseline by --baseline *)
  extra : (string * Yojson.Safe.t) list;
}

(* Nearest-rank percentile on a sorted array: the smallest sample such that at least
   [p] of the samples are <= it. *)
let percentile sorted p =
  let n = Array.length sorted in
  if n = 0 then nan
  else
    let rank = int_of_float (Float.ceil (p *. float_of_int n)) in
    sorted.(max 0 (min (n - 1) (rank - 1)))

let summarize ?(gate = false) ?(errors = 0) ?(extra = []) ~suite ~name ~unit_ ~wall
    (lat : float array) =
  let a = Array.copy lat in
  Array.sort Float.compare a;
  let n = Array.length a in
  let mean = if n = 0 then nan else Array.fold_left ( +. ) 0.0 a /. float_of_int n in
  {
    suite;
    name;
    unit_;
    samples = n;
    p50 = percentile a 0.50;
    p90 = percentile a 0.90;
    p99 = percentile a 0.99;
    p999 = percentile a 0.999;
    max = (if n = 0 then nan else a.(n - 1));
    mean;
    throughput = (if wall > 0.0 then float_of_int n /. wall else nan);
    errors;
    gate;
    extra;
  }

let key r = r.suite ^ "/" ^ r.name
let num f = if Float.is_finite f then `Float f else `Null

let to_json r =
  `Assoc
    ([
       ("suite", `String r.suite);
       ("name", `String r.name);
       ("unit", `String r.unit_);
       ("samples", `Int r.samples);
       ("p50", num r.p50);
       ("p90", num r.p90);
       ("p99", num r.p99);
       ("p99_9", num r.p999);
       ("max", num r.max);
       ("mean", num r.mean);
       ("throughput_per_s", num r.throughput);
       ("errors", `Int r.errors);
       ("gate", `Bool r.gate);
     ]
    @ r.extra)

(* Monotonic enough for our purposes: gettimeofday has microsecond resolution on
   Linux and macOS, and every timed region is at least a few microseconds. *)
let now = Unix.gettimeofday
