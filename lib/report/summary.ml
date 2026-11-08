(* Aggregation over normalized records. Everything is computed in one pass with
   hash tables, then sorted deterministically (count desc, key asc). *)

type count = { total : int; allowed : int; denied : int; shadow_denied : int }

type query = {
  key : string;
  count : count;
  codes : (string * int) list;
  callers : (string * int) list;
  policies : string list;
  example_sql : string option;
  example_sql_sha256 : string option;
  first_seen : float option;
  last_seen : float option;
}

type t = {
  records : int;
  first_ts : float option;
  last_ts : float option;
  untimed : int;
  with_sql : int;
  with_details : int;
  totals : count;
  by_code : (string * count) list;
  by_table : (string * count) list;
  by_column : (string * count) list;
  by_caller : (string * count) list;
  by_policy : (string * count) list;
  by_source : (string * count) list;
  bucket_seconds : int;
  buckets : (float * count) list;
  top_denied : query list;
}

let max_example_bytes = 2000
let zero = { total = 0; allowed = 0; denied = 0; shadow_denied = 0 }

let bump c (o : Record.outcome) =
  match o with
  | Allowed -> { c with total = c.total + 1; allowed = c.allowed + 1 }
  | Denied -> { c with total = c.total + 1; denied = c.denied + 1 }
  | Shadow_denied -> { c with total = c.total + 1; shadow_denied = c.shadow_denied + 1 }

let add_count tbl key o =
  let c = Option.value (Hashtbl.find_opt tbl key) ~default:zero in
  Hashtbl.replace tbl key (bump c o)

let sorted_counts tbl =
  Hashtbl.fold (fun k v acc -> (k, v) :: acc) tbl []
  |> List.sort (fun (k1, c1) (k2, c2) ->
      match compare c2.total c1.total with 0 -> compare k1 k2 | n -> n)

let sorted_ints tbl =
  Hashtbl.fold (fun k v acc -> (k, v) :: acc) tbl []
  |> List.sort (fun (k1, n1) (k2, n2) ->
      match compare n2 n1 with 0 -> compare k1 k2 | n -> n)

let auto_bucket first last =
  match (first, last) with
  | Some a, Some b ->
      let span = b -. a in
      if span <= 6. *. 3600. then 300 else if span <= 3. *. 86400. then 3600 else 86400
  | _ -> 3600

let dedup l =
  List.rev (List.fold_left (fun acc x -> if List.mem x acc then acc else x :: acc) [] l)

(* Tables and columns a record touched or was denied on. *)
let objects (r : Record.t) =
  let tables = ref r.tables and columns = ref r.columns in
  List.iter
    (fun d ->
      match Finding.of_reason d with
      | Finding.Column { table; column } ->
          tables := table :: !tables;
          columns := (table ^ "." ^ column) :: !columns
      | Finding.Column_star t -> tables := t :: !tables
      | Finding.Table { schema = Some s; name } -> tables := (s ^ "." ^ name) :: !tables
      | Finding.Table { schema = None; name } | Finding.System_relation name ->
          tables := name :: !tables
      | Finding.Function _ | Finding.Sql_value_function _ | Finding.Limit_value _
      | Finding.Limit_non_constant | Finding.Unrecognized ->
          ())
    r.details;
  (dedup !tables, dedup !columns)

let clip s =
  if String.length s <= max_example_bytes then s
  else String.sub s 0 max_example_bytes ^ " /* ... truncated */"

type qacc = {
  mutable qcount : count;
  qcodes : (string, int) Hashtbl.t;
  qcallers : (string, int) Hashtbl.t;
  mutable qpolicies : string list;
  mutable qsql : string option;
  mutable qsha : string option;
  mutable qfirst : float option;
  mutable qlast : float option;
}

let fmin a b =
  match (a, b) with
  | Some x, Some y -> Some (Float.min x y)
  | Some x, None | None, Some x -> Some x
  | None, None -> None

let fmax a b =
  match (a, b) with
  | Some x, Some y -> Some (Float.max x y)
  | Some x, None | None, Some x -> Some x
  | None, None -> None

let compute ?bucket_seconds ?(top = 20) (records : Record.t list) =
  let first_ts = List.fold_left (fun acc (r : Record.t) -> fmin acc r.ts) None records in
  let last_ts = List.fold_left (fun acc (r : Record.t) -> fmax acc r.ts) None records in
  let bucket_seconds =
    match bucket_seconds with Some b when b > 0 -> b | _ -> auto_bucket first_ts last_ts
  in
  let by_code = Hashtbl.create 32
  and by_table = Hashtbl.create 32
  and by_column = Hashtbl.create 64
  and by_caller = Hashtbl.create 16
  and by_policy = Hashtbl.create 8
  and by_source = Hashtbl.create 2
  and buckets = Hashtbl.create 64
  and queries : (string, qacc) Hashtbl.t = Hashtbl.create 64 in
  let totals = ref zero
  and untimed = ref 0
  and with_sql = ref 0
  and with_details = ref 0 in
  List.iter
    (fun (r : Record.t) ->
      let o = r.outcome in
      totals := bump !totals o;
      if r.ts = None then incr untimed;
      if r.sql <> None then incr with_sql;
      if r.details <> [] then incr with_details;
      List.iter (fun c -> add_count by_code c o) r.codes;
      let tables, columns = objects r in
      List.iter (fun t -> add_count by_table t o) tables;
      List.iter (fun c -> add_count by_column c o) columns;
      add_count by_caller r.caller o;
      add_count by_policy r.policy o;
      add_count by_source (Record.source_to_string r.source) o;
      (match r.ts with
      | Some ts ->
          let b =
            Float.floor (ts /. Float.of_int bucket_seconds) *. Float.of_int bucket_seconds
          in
          add_count buckets b o
      | None -> ());
      match o with
      | Allowed -> ()
      | Denied | Shadow_denied ->
          let key = Record.fingerprint_key r in
          let q =
            match Hashtbl.find_opt queries key with
            | Some q -> q
            | None ->
                let q =
                  {
                    qcount = zero;
                    qcodes = Hashtbl.create 4;
                    qcallers = Hashtbl.create 4;
                    qpolicies = [];
                    qsql = None;
                    qsha = None;
                    qfirst = None;
                    qlast = None;
                  }
                in
                Hashtbl.replace queries key q;
                q
          in
          q.qcount <- bump q.qcount o;
          List.iter
            (fun c ->
              Hashtbl.replace q.qcodes c
                (1 + Option.value (Hashtbl.find_opt q.qcodes c) ~default:0))
            r.codes;
          Hashtbl.replace q.qcallers r.caller
            (1 + Option.value (Hashtbl.find_opt q.qcallers r.caller) ~default:0);
          if not (List.mem r.policy q.qpolicies) then
            q.qpolicies <- r.policy :: q.qpolicies;
          (match (q.qsql, r.sql) with
          | None, Some s ->
              q.qsql <- Some (clip s);
              q.qsha <- r.sql_sha256
          | _ -> ());
          if q.qsha = None then q.qsha <- r.sql_sha256;
          q.qfirst <- fmin q.qfirst r.ts;
          q.qlast <- fmax q.qlast r.ts)
    records;
  let top_denied =
    Hashtbl.fold
      (fun key q acc ->
        {
          key;
          count = q.qcount;
          codes = sorted_ints q.qcodes;
          callers = sorted_ints q.qcallers;
          policies = List.sort compare q.qpolicies;
          example_sql = q.qsql;
          example_sql_sha256 = q.qsha;
          first_seen = q.qfirst;
          last_seen = q.qlast;
        }
        :: acc)
      queries []
    |> List.sort (fun a b ->
        let bad c = c.denied + c.shadow_denied in
        match compare (bad b.count) (bad a.count) with 0 -> compare a.key b.key | n -> n)
    |> List.filteri (fun i _ -> i < top)
  in
  {
    records = List.length records;
    first_ts;
    last_ts;
    untimed = !untimed;
    with_sql = !with_sql;
    with_details = !with_details;
    totals = !totals;
    by_code = sorted_counts by_code;
    by_table = sorted_counts by_table;
    by_column = sorted_counts by_column;
    by_caller = sorted_counts by_caller;
    by_policy = sorted_counts by_policy;
    by_source = sorted_counts by_source;
    bucket_seconds;
    buckets =
      Hashtbl.fold (fun k v acc -> (k, v) :: acc) buckets []
      |> List.sort (fun (a, _) (b, _) -> compare a b);
    top_denied;
  }

let count_to_json c : Yojson.Safe.t =
  `Assoc
    [
      ("total", `Int c.total);
      ("allowed", `Int c.allowed);
      ("denied", `Int c.denied);
      ("shadow_denied", `Int c.shadow_denied);
    ]

let ts_json = function Some t -> `String (Rtime.to_rfc3339 t) | None -> `Null
let opt_str = function Some s -> `String s | None -> `Null

let rows key l : Yojson.Safe.t =
  `List
    (List.map
       (fun (k, c) ->
         match count_to_json c with
         | `Assoc kv -> `Assoc ((key, `String k) :: kv)
         | j -> j)
       l)

let ints key l : Yojson.Safe.t =
  `List (List.map (fun (k, n) -> `Assoc [ (key, `String k); ("count", `Int n) ]) l)

let to_json t : Yojson.Safe.t =
  `Assoc
    [
      ("records", `Int t.records);
      ("first_ts", ts_json t.first_ts);
      ("last_ts", ts_json t.last_ts);
      ("untimed", `Int t.untimed);
      ("with_sql", `Int t.with_sql);
      ("with_details", `Int t.with_details);
      ("totals", count_to_json t.totals);
      ("by_code", rows "code" t.by_code);
      ("by_table", rows "table" t.by_table);
      ("by_column", rows "column" t.by_column);
      ("by_caller", rows "caller" t.by_caller);
      ("by_policy", rows "policy" t.by_policy);
      ("by_source", rows "source" t.by_source);
      ("bucket_seconds", `Int t.bucket_seconds);
      ( "buckets",
        `List
          (List.map
             (fun (b, c) ->
               match count_to_json c with
               | `Assoc kv -> `Assoc (("start", `String (Rtime.to_rfc3339 b)) :: kv)
               | j -> j)
             t.buckets) );
      ( "top_denied",
        `List
          (List.map
             (fun q ->
               `Assoc
                 [
                   ("fingerprint", `String q.key);
                   ("count", count_to_json q.count);
                   ("codes", ints "code" q.codes);
                   ("callers", ints "caller" q.callers);
                   ("policies", `List (List.map (fun p -> `String p) q.policies));
                   ("example_sql", opt_str q.example_sql);
                   ("example_sql_sha256", opt_str q.example_sql_sha256);
                   ("first_seen", ts_json q.first_seen);
                   ("last_seen", ts_json q.last_seen);
                 ])
             t.top_denied) );
    ]
