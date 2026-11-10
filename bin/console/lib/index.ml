module Record = Haltsql_report.Record

type entry = {
  record : Record.t;
  request_id : string;
  ts : float;
  verifier : string;
  hash : string option;
  prev_hash : string option;
  elapsed_us : int option;
  location : string;
  seq : int;
  raw : Yojson.Safe.t;
}

(* Entries live in a growable array in insertion order with a moving start offset, so
   eviction from the front is O(1) amortised. *)
type t = {
  mutable items : entry option array;
  mutable start : int;
  mutable stop : int;
  by_id : (string, entry) Hashtbl.t;
  max_records : int;
  retention : float;
}

let create ?(max_records = 2_000_000) ?(retention_seconds = 7. *. 86400.) () =
  {
    items = Array.make 1024 None;
    start = 0;
    stop = 0;
    by_id = Hashtbl.create 4096;
    max_records = max 1 max_records;
    retention = retention_seconds;
  }

let size t = t.stop - t.start

let compact t =
  let n = size t in
  let cap = max 1024 (2 * n) in
  let a = Array.make cap None in
  Array.blit t.items t.start a 0 n;
  t.items <- a;
  t.start <- 0;
  t.stop <- n

let drop_front t =
  match t.items.(t.start) with
  | None -> t.start <- t.start + 1
  | Some e ->
      (match Hashtbl.find_opt t.by_id e.request_id with
      | Some e' when e' == e -> Hashtbl.remove t.by_id e.request_id
      | _ -> ());
      t.items.(t.start) <- None;
      t.start <- t.start + 1

let add t e =
  let dup =
    match Hashtbl.find_opt t.by_id e.request_id with
    | Some e' -> e'.verifier = e.verifier && e'.location = e.location
    | None -> false
  in
  if not dup then begin
    if t.stop >= Array.length t.items then compact t;
    t.items.(t.stop) <- Some e;
    t.stop <- t.stop + 1;
    Hashtbl.replace t.by_id e.request_id e;
    while size t > t.max_records do
      drop_front t
    done
  end

let iter t f =
  for i = t.start to t.stop - 1 do
    match t.items.(i) with Some e -> f e | None -> ()
  done

let fold t ~init ~f =
  let acc = ref init in
  iter t (fun e -> acc := f !acc e);
  !acc

let expire t ~now =
  let cutoff = now -. t.retention in
  (* Insertion order is close to time order; drop old entries from the front, then filter
     any stragglers if many remain. *)
  let continue = ref true in
  while !continue && size t > 0 do
    match t.items.(t.start) with
    | Some e when e.ts < cutoff -> drop_front t
    | None -> t.start <- t.start + 1
    | Some _ -> continue := false
  done;
  if t.start > Array.length t.items / 2 then compact t

let oldest t =
  fold t ~init:None ~f:(fun acc e ->
      match acc with Some x when x <= e.ts -> acc | _ -> Some e.ts)

let newest t =
  fold t ~init:None ~f:(fun acc e ->
      match acc with Some x when x >= e.ts -> acc | _ -> Some e.ts)

let find t id = Hashtbl.find_opt t.by_id id

let between t ~since ~until =
  fold t ~init:[] ~f:(fun acc e ->
      if e.ts >= since && e.ts < until then e :: acc else acc)
  |> List.stable_sort (fun a b -> compare a.ts b.ts)

let verifier_stream t v =
  fold t ~init:[] ~f:(fun acc e -> if e.verifier = v then e :: acc else acc)
  |> List.stable_sort (fun a b -> compare a.seq b.seq)

let verifiers t =
  fold t ~init:[] ~f:(fun acc e ->
      if List.mem e.verifier acc then acc else e.verifier :: acc)
  |> List.sort compare

(* ---- building entries ---- *)

let str_member name = function
  | `Assoc l -> (
      match List.assoc_opt name l with Some (`String s) -> Some s | _ -> None)
  | _ -> None

let int_member name = function
  | `Assoc l -> (
      match List.assoc_opt name l with
      | Some (`Int i) -> Some i
      | Some (`Float f) -> Some (int_of_float f)
      | _ -> None)
  | _ -> None

let entry_of_json ~verifier ~location ~seq ~now (j : Yojson.Safe.t) =
  match Record.of_json j with
  | Error _ -> None
  | Ok record ->
      let request_id =
        match str_member "request_id" j with
        | Some id -> id
        | None -> (
            (* Proxy records have no request id: derive a stable one from the location. *)
            match str_member "session" j with
            | Some s -> Printf.sprintf "%s-%d" s seq
            | None ->
                Printf.sprintf "%s-%d"
                  (Haltsql.sha256_hex location |> fun h -> String.sub h 0 12)
                  seq)
      in
      Some
        {
          record;
          request_id;
          ts = Option.value record.ts ~default:now;
          verifier;
          hash = str_member "hash" j;
          prev_hash = str_member "prev_hash" j;
          elapsed_us = int_member "elapsed_us" j;
          location;
          seq;
          raw = j;
        }

(* ---- search ---- *)

type filter = {
  q : string option;
  caller : string option;
  policy : string option;
  outcome : Record.outcome option;
  code : string option;
  table : string option;
  fingerprint : string option;
  verifier : string option;
  since : float option;
  until : float option;
}

let no_filter =
  {
    q = None;
    caller = None;
    policy = None;
    outcome = None;
    code = None;
    table = None;
    fingerprint = None;
    verifier = None;
    since = None;
    until = None;
  }

let outcome_of_string = function
  | "allowed" -> Some Record.Allowed
  | "denied" -> Some Record.Denied
  | "shadow_denied" -> Some Record.Shadow_denied
  | _ -> None

let contains ~sub s =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  n = 0 || go 0

let starts_with ~prefix s = String.starts_with ~prefix s

let table_matches t tables =
  List.exists (fun x -> x = t || String.ends_with ~suffix:("." ^ t) x) tables

let matches f e =
  let r = e.record in
  let ok o p = match o with None -> true | Some v -> p v in
  ok f.caller (fun c -> contains ~sub:c r.caller)
  && ok f.policy (fun p -> r.policy = p)
  && ok f.outcome (fun o -> r.outcome = o)
  && ok f.code (fun c -> List.mem c r.codes)
  && ok f.table (fun t -> table_matches t r.tables)
  && ok f.fingerprint (fun fp ->
      match r.fingerprint with Some x -> starts_with ~prefix:fp x | None -> false)
  && ok f.verifier (fun v -> e.verifier = v)
  && ok f.since (fun s -> e.ts >= s)
  && ok f.until (fun u -> e.ts < u)
  && ok f.q (fun q ->
      starts_with ~prefix:q e.request_id
      || contains ~sub:q r.caller
      || (match r.fingerprint with Some x -> starts_with ~prefix:q x | None -> false)
      || table_matches q r.tables)

let search t f =
  fold t ~init:[] ~f:(fun acc e -> if matches f e then e :: acc else acc)
  |> List.stable_sort (fun a b -> compare b.ts a.ts)

(* ---- JSON ---- *)

let raw_sql e =
  match e.record.sql with
  | Some s -> Some s
  | None -> (
      match str_member "sql" e.raw with
      | Some s -> Some s
      | None -> str_member "statement" e.raw)

let opt_s = function None -> `Null | Some s -> `String s

let entry_to_json e =
  let r = e.record in
  `Assoc
    [
      ("request_id", `String e.request_id);
      ("ts", `String (Api.iso8601 e.ts));
      ("verifier", `String e.verifier);
      ("source", `String (Record.source_to_string r.source));
      ("caller", `String r.caller);
      ("caller_type", opt_s r.caller_type);
      ("policy", `String r.policy);
      ("policy_version", opt_s r.policy_version);
      ("outcome", `String (Record.outcome_to_string r.outcome));
      ("codes", Api.strings r.codes);
      ("tables", Api.strings r.tables);
      ("fingerprint", opt_s r.fingerprint);
      ("sql_sha256", opt_s r.sql_sha256);
      ("elapsed_us", match e.elapsed_us with None -> `Null | Some i -> `Int i);
      ("has_raw_sql", `Bool (raw_sql e <> None));
    ]
