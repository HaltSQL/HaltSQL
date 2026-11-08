(* GET /v1/admin/report: shadow-mode analytics over the server's recent audit records.

   An in-memory rolling window of records, fed from the audit path and grouped by query
   fingerprint, bounded three ways:
   - by age: records older than [server.admin.report_window] are dropped;
   - by distinct queries: at most [server.admin.max_tracked_queries] fingerprints are
     tracked; when a new one arrives at the limit, the least recently seen fingerprint
     and its records are evicted ("evicted_queries");
   - per query: at most [records_per_query] (32) recent records of one fingerprint are
     kept; older ones are counted in "sampled_out", so counts for very frequent queries
     are lower bounds. Only one record per fingerprint keeps its raw SQL.
   Nothing is kept while [server.admin] is disabled. Worst-case memory is about
   max_tracked_queries x 32 small records plus one SQL text (at most 4 KiB) per query.

   The report itself (summary, suggestions) is computed by haltsql.report. This module
   only depends on it through the BACKEND signature, so that it builds without that
   library; the integrator instantiates it once:

     module Report = Report_api.Make (Haltsql_report.Live)
     let report = Report.create cfg.admin           (* in State *)
     Report.observe_verdict report ~caller ~caller_type ~sql verdict   (* in Http.audit_record *)
     Report.handle report ~policies ~query          (* GET /v1/admin/report, behind admin auth *)

   Records hold reason messages and, only when audit.log_raw_sql is on, the SQL. The
   handler never returns SQL for records that did not contain it. *)

module type BACKEND = sig
  type record

  val of_audit_fields : (string * Yojson.Safe.t) list -> record option

  val of_verdict :
    ts:float ->
    caller:string ->
    caller_type:string ->
    sql:string option ->
    Haltsql.Verdict.t ->
    record

  val fingerprint : record -> string
  (** grouping key: the fingerprint, else the SQL hash *)

  val has_sql : record -> bool
  val strip_sql : record -> record

  val parse_since : now:float -> string -> (float, string) result
  (** RFC 3339, YYYY-MM-DD, or a duration before [now] (24h, 7d). *)

  val report :
    now:float ->
    since:float ->
    policy:string option ->
    suggest:bool ->
    top:int ->
    policies:(string * Haltsql.Policy.t) list ->
    verify:(Haltsql.Policy.t -> Haltsql.Context.t -> string -> Haltsql.Verdict.t) option ->
    record list ->
    Yojson.Safe.t
end

let max_sql_bytes = 4096
let max_policy_param = 256
let records_per_query = 32

module Lru = Map.Make (struct
  type t = float * int

  let compare = compare
end)

module Make (B : BACKEND) = struct
  type entry = {
    mutable key : float * int;  (** position in [order]: (last seen, sequence) *)
    recs : (float * B.record) Queue.t;  (** (arrival time, record), oldest first *)
  }

  type t = {
    mutable admin : Haltsql.Config.admin;
    entries : (string, entry) Hashtbl.t;
    mutable order : string Lru.t;  (** least recently seen first *)
    mutable seq : int;
    mutable evicted_queries : int;
    mutable sampled_out : int;
    now : unit -> float;
    lock : Mutex.t;
  }

  let with_lock t f =
    Mutex.lock t.lock;
    Fun.protect ~finally:(fun () -> Mutex.unlock t.lock) f

  let create ?(now = Unix.gettimeofday) (admin : Haltsql.Config.admin) =
    {
      admin;
      entries = Hashtbl.create 64;
      order = Lru.empty;
      seq = 0;
      evicted_queries = 0;
      sampled_out = 0;
      now;
      lock = Mutex.create ();
    }

  (* Caller holds the lock for all the helpers below. *)
  let remove t fp (e : entry) =
    Hashtbl.remove t.entries fp;
    t.order <- Lru.remove e.key t.order

  let clear t =
    Hashtbl.reset t.entries;
    t.order <- Lru.empty;
    t.evicted_queries <- 0;
    t.sampled_out <- 0

  let evict_to t limit =
    let rec go () =
      if Hashtbl.length t.entries > max 0 limit then
        match Lru.min_binding_opt t.order with
        | Some (k, fp) ->
            (match Hashtbl.find_opt t.entries fp with
            | Some e -> remove t fp e
            | None -> t.order <- Lru.remove k t.order);
            t.evicted_queries <- t.evicted_queries + 1;
            go ()
        | None -> ()
    in
    go ()

  let prune_age t now =
    let horizon = now -. Float.of_int t.admin.report_window_seconds in
    let empty = ref [] in
    Hashtbl.iter
      (fun fp (e : entry) ->
        let rec drop () =
          match Queue.peek_opt e.recs with
          | Some (arrived, _) when arrived < horizon ->
              ignore (Queue.pop e.recs);
              drop ()
          | Some _ | None -> ()
        in
        drop ();
        if Queue.is_empty e.recs then empty := (fp, e) :: !empty)
      t.entries;
    List.iter (fun (fp, e) -> remove t fp e) !empty

  (* A reload may disable the endpoint (drop everything) or shrink the bounds. *)
  let reconfigure t (admin : Haltsql.Config.admin) =
    with_lock t (fun () ->
        t.admin <- admin;
        if not admin.admin_enabled then clear t
        else begin
          prune_age t (t.now ());
          evict_to t admin.max_tracked_queries
        end)

  let push t r =
    with_lock t (fun () ->
        if t.admin.admin_enabled then begin
          let now = t.now () in
          let fp = B.fingerprint r in
          t.seq <- t.seq + 1;
          let key = (now, t.seq) in
          let e =
            match Hashtbl.find_opt t.entries fp with
            | Some e ->
                t.order <- Lru.remove e.key t.order;
                e.key <- key;
                e
            | None ->
                evict_to t (t.admin.max_tracked_queries - 1);
                let e = { key; recs = Queue.create () } in
                Hashtbl.replace t.entries fp e;
                e
          in
          t.order <- Lru.add key fp t.order;
          (* one SQL text per query is enough to name what it reads *)
          let r =
            if
              B.has_sql r
              && Queue.fold (fun acc (_, x) -> acc || B.has_sql x) false e.recs
            then B.strip_sql r
            else r
          in
          Queue.push (now, r) e.recs;
          while Queue.length e.recs > records_per_query do
            ignore (Queue.pop e.recs);
            t.sampled_out <- t.sampled_out + 1
          done
        end)

  let enabled t = t.admin.admin_enabled
  let tracked_queries t = with_lock t (fun () -> Hashtbl.length t.entries)

  let tracked t =
    with_lock t (fun () ->
        Hashtbl.fold (fun _ e n -> n + Queue.length e.recs) t.entries 0)

  let evicted t = with_lock t (fun () -> t.evicted_queries)
  let sampled_out t = with_lock t (fun () -> t.sampled_out)

  (* [fields]: an audit record exactly as passed to Audit.deliver. *)
  let observe t (fields : (string * Yojson.Safe.t) list) =
    if enabled t then
      let fields =
        List.map
          (fun (k, v) ->
            match (k, v) with
            | "sql", `String s when String.length s > max_sql_bytes ->
                (k, `String (String.sub s 0 max_sql_bytes))
            | _ -> (k, v))
          fields
      in
      match B.of_audit_fields fields with Some r -> push t r | None -> ()

  (* Preferred over [observe]: the verdict carries the detailed reasons, so the report
     can name denied columns, functions and tables without the raw SQL. Pass [sql] only
     when audit.log_raw_sql is on. *)
  let observe_verdict t ~caller ~caller_type ~sql (v : Haltsql.Verdict.t) =
    if enabled t then
      let sql =
        Option.map
          (fun s ->
            if String.length s > max_sql_bytes then String.sub s 0 max_sql_bytes else s)
          sql
      in
      push t (B.of_verdict ~ts:(t.now ()) ~caller ~caller_type ~sql v)

  let error status code message =
    ( status,
      `Assoc
        [ ("error", `Assoc [ ("code", `String code); ("message", `String message) ]) ] )

  type params = {
    since : float option;
    policy : string option;
    suggest : bool;
    top : int;
  }

  let parse_params ~now (query : (string * string list) list) =
    let rec go acc = function
      | [] -> Ok acc
      | (k, vs) :: rest -> (
          let one () =
            match vs with
            | [ v ] -> Ok v
            | _ -> Error (Printf.sprintf "parameter %S must be given exactly once" k)
          in
          let ( let* ) = Result.bind in
          match k with
          | "since" ->
              let* v = one () in
              let* t = B.parse_since ~now v in
              go { acc with since = Some t } rest
          | "policy" ->
              let* v = one () in
              if v = "" || String.length v > max_policy_param then
                Error "parameter \"policy\" must be a policy name"
              else go { acc with policy = Some v } rest
          | "suggest" -> (
              let* v = one () in
              match v with
              | "true" | "1" -> go { acc with suggest = true } rest
              | "false" | "0" -> go { acc with suggest = false } rest
              | _ -> Error "parameter \"suggest\" must be true or false")
          | "top" -> (
              let* v = one () in
              match int_of_string_opt v with
              | Some n when n >= 1 && n <= 100 -> go { acc with top = n } rest
              | _ -> Error "parameter \"top\" must be an integer from 1 to 100")
          | _ ->
              Error
                (Printf.sprintf
                   "unknown parameter %S (allowed: since, policy, suggest, top)"
                   (if String.length k > 64 then String.sub k 0 64 else k)))
    in
    let seen = List.map fst query in
    if List.length (List.sort_uniq compare seen) <> List.length seen then
      Error "a parameter is given more than once"
    else go { since = None; policy = None; suggest = true; top = 20 } query

  (* Returns (HTTP status, JSON body). The integrator mounts it behind the admin
     callers of server.admin; it answers 404 when the admin API is disabled. *)
  let handle ?(verify = Some Haltsql.verify) t
      ~(policies : (string * Haltsql.Policy.t) list)
      ~(query : (string * string list) list) =
    if not (enabled t) then
      error 404 "NOT_FOUND" "the admin API is disabled (server.admin)"
    else
      let now = t.now () in
      match parse_params ~now query with
      | Error m -> error 400 "BAD_REQUEST" m
      | Ok p ->
          let records, queries, evicted, sampled, window_s, max_tracked =
            with_lock t (fun () ->
                prune_age t now;
                let recs =
                  Hashtbl.fold
                    (fun _ (e : entry) acc ->
                      Queue.fold (fun acc x -> x :: acc) acc e.recs)
                    t.entries []
                  |> List.sort (fun (a, _) (b, _) -> compare a b)
                  |> List.map snd
                in
                ( recs,
                  Hashtbl.length t.entries,
                  t.evicted_queries,
                  t.sampled_out,
                  t.admin.report_window_seconds,
                  t.admin.max_tracked_queries ))
          in
          let horizon = now -. Float.of_int window_s in
          let since =
            match p.since with Some s -> Float.max s horizon | None -> horizon
          in
          let body =
            B.report ~now ~since ~policy:p.policy ~suggest:p.suggest ~top:p.top ~policies
              ~verify records
          in
          let meta =
            [
              ("window_seconds", `Int window_s);
              ("max_tracked_queries", `Int max_tracked);
              ("tracked_queries", `Int queries);
              ("tracked_records", `Int (List.length records));
              ("evicted_queries", `Int evicted);
              ("records_per_query", `Int records_per_query);
              ("sampled_out", `Int sampled);
            ]
          in
          let body = match body with `Assoc kv -> `Assoc (meta @ kv) | j -> j in
          (200, body)
end
