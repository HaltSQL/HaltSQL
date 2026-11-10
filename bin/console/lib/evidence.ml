(* Evidence packs and control mappings (docs/console/api.md#evidence-and-controls).

   A pack is a .tar.gz under state_dir/packs/ with, for one framework and period:
   README.md (scope, disclaimer, gaps), manifest.json (every file with its SHA-256,
   record counts, chain results, builder, period), records/<verifier>.jsonl (the raw
   audit lines from the index), chains.json (hash-chain verification of those records
   with Haltsql_cloud.Audit_chain), policies.json, activity.jsonl, exceptions.json and
   controls.json. Pack metadata is kept in the [packs] store collection. *)

open Lwt.Syntax
module C = Console_config
module Record = Haltsql_report.Record

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"component\":\"evidence\",\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

(* ---- controls ---- *)

let framework_param = function
  | None | Some "" -> "soc2"
  | Some f when Controls.for_framework f <> None -> f
  | Some f ->
      Api.bad_request "framework must be one of %s (got %S)"
        (String.concat ", " Controls.frameworks)
        f

let controls_handler (_ : Ctx.t) _p (r : Router.req) =
  let f = framework_param (Router.query r "framework") in
  Api.json (Controls.to_json f (Option.get (Controls.for_framework f)))

(* ---- gaps ---- *)

let gap kind name detail =
  `Assoc [ ("kind", `String kind); ("name", `String name); ("detail", `String detail) ]

(* Ingest.status is a list of per-source objects. A source with a non-null [error] (or
   state error/failing) could not be read. *)
let ingest_errors (ctx : Ctx.t) =
  match Ingest.status ctx with
  | `List l ->
      List.filter_map
        (fun s ->
          let str k =
            match Api.member k s with Some (`String x) -> Some x | _ -> None
          in
          let name =
            List.find_map str [ "source"; "name"; "id"; "location"; "uri"; "path" ]
            |> Option.value ~default:"(unknown source)"
          in
          match (str "error", str "state") with
          | Some e, _ when e <> "" -> Some (name, e)
          | _, Some (("error" | "failing") as st) -> Some (name, st)
          | _ -> None)
        l
  | _ -> []

(* The period starts before the index's retention window, or records of the period were
   evicted by [audit.max_records]: either way the pack cannot hold them, and says so. *)
let retention_gap (ctx : Ctx.t) ~since =
  let a = ctx.config.audit in
  let window_start = Ctx.now () -. (float_of_int a.retention_hours *. 3600.) in
  let oldest = Index.oldest ctx.index in
  let first_covered =
    match oldest with Some o -> Float.max o window_start | None -> window_start
  in
  if since < window_start then
    Some
      (gap "retention" "console index"
         (Printf.sprintf
            "The period starts before the console's retention window (%d hours): records \
             before %s are not in this pack. Verify the full audit store with `haltsql \
             audit verify`."
            a.retention_hours (Api.iso8601 first_covered)))
  else
    match oldest with
    | Some o when since < o && Index.size ctx.index >= a.max_records ->
        Some
          (gap "retention" "console index"
             (Printf.sprintf
                "The console's index is full (audit.max_records = %d) and has evicted \
                 older records: records before %s are not in this pack. Verify the full \
                 audit store with `haltsql audit verify`."
                a.max_records (Api.iso8601 o)))
    | _ -> None

let gaps (ctx : Ctx.t) ~since =
  List.filter_map
    (fun (a : C.agent) ->
      if a.a_via = "in_process" then
        Some
          (gap "in_process_agent" a.a_name
             "Runs HaltSQL in process; its decisions are audited in the application, not \
              centrally, and are not in this pack.")
      else None)
    ctx.config.agents
  @ List.map
      (fun (name, e) -> gap "source_error" name ("Audit source could not be read: " ^ e))
      (ingest_errors ctx)
  @ Option.to_list (retention_gap ctx ~since)

(* ---- chains ---- *)

(* Chained records split into segments at every genesis [prev_hash], as [Chain.check]
   does (a restart without a spool starts a new chain). *)
let segments_of (chained : Index.entry list) =
  List.fold_left
    (fun acc (e : Index.entry) ->
      match acc with
      | cur :: rest when e.prev_hash <> Some Haltsql_cloud.Audit_chain.genesis ->
          (e :: cur) :: rest
      | _ -> [ e ] :: acc)
    [] chained
  |> List.rev_map List.rev

(** Hash-chain verification of one verifier's included records, in stream order, with the
    same rules as the console's chain page ({!Chain.check}): records without a [hash] are
    not chained (counted as [unchained]), a genesis [prev_hash] starts a new segment, and
    the first record of each segment is accepted as is (the period rarely starts at
    genesis). Verification runs on the records as ingested. [first_break.line] is the line
    of the records file. *)
let chain_report verifier (entries : Index.entry list) =
  let n = List.length entries in
  let hashed = List.filter (fun (e : Index.entry) -> e.hash <> None) entries in
  let n_hashed = List.length hashed in
  let base state extra =
    `Assoc
      ([ ("verifier", `String verifier); ("records", `Int n); ("state", `String state) ]
      @ extra)
  in
  if n = 0 then (false, base "unknown" [ ("detail", `String "no records") ])
  else if hashed = [] then
    (false, base "unknown" [ ("detail", `String "records carry no hash chain") ])
  else
    let segs = List.map Chain.verify_segment (segments_of hashed) in
    let common =
      [ ("segments", `Int (List.length segs)); ("unchained", `Int (n - n_hashed)) ]
    in
    match List.find_map (fun (s : Chain.segment) -> s.break) segs with
    | None ->
        ( true,
          base "intact"
            ([
               ("verified", `Int n_hashed);
               ("first_hash", Api.opt_string (List.hd hashed).hash);
               ("head_hash", Api.opt_string (List.nth hashed (n_hashed - 1)).hash);
             ]
            @ common) )
    | Some (bad, problem) ->
        let rec pos i hashed_before = function
          | [] -> (i, hashed_before)
          | (e : Index.entry) :: rest ->
              if e == bad then (i, hashed_before)
              else pos (i + 1) (hashed_before + if e.hash <> None then 1 else 0) rest
        in
        let line, verified = pos 1 0 entries in
        ( false,
          base "broken"
            ([
               ("verified", `Int verified);
               ( "first_break",
                 `Assoc
                   [
                     ("line", `Int line);
                     ("problem", `String problem);
                     ("request_id", `String bad.request_id);
                     ("location", `String bad.location);
                   ] );
             ]
            @ common) )

(* ---- pack contents ---- *)

(* Fields that hold SQL text in an audit record ([Index.raw_sql] reads the same ones). *)
let sql_fields = [ "sql"; "statement" ]

(** The record line written into a pack: the original JSON, with [sql]/[statement] removed
    unless [include_sql] ([sql_sha256] stays). Returns whether SQL was removed. *)
let record_line ~include_sql (e : Index.entry) =
  match e.raw with
  | `Assoc l when (not include_sql) && List.exists (fun (k, _) -> List.mem k sql_fields) l
    ->
      ( Yojson.Safe.to_string
          (`Assoc (List.filter (fun (k, _) -> not (List.mem k sql_fields)) l)),
        true )
  | j -> (Yojson.Safe.to_string j, false)

let safe_file_name s =
  let s =
    String.map
      (fun c ->
        match c with
        | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '_' | '.' -> c
        | _ -> '_')
      s
  in
  let s = if s = "" || s.[0] = '.' then "v" ^ s else s in
  if String.length s > 60 then String.sub s 0 60 else s

(** [records/<name>.jsonl] for each verifier, never two the same (compared without case,
    for case-insensitive file systems). A name changed by [safe_file_name] gets a short
    hash of the verifier name, so two verifiers that map to the same safe name differ. *)
let record_file_names verifiers =
  let used = Hashtbl.create 8 in
  List.map
    (fun v ->
      let safe = safe_file_name v in
      let base =
        if safe = v then safe
        else
          let h = String.sub Digestif.SHA256.(to_hex (digest_string v)) 0 8 in
          let keep = min (String.length safe) 51 in
          String.sub safe 0 keep ^ "-" ^ h
      in
      let rec pick name k =
        if Hashtbl.mem used (String.lowercase_ascii name) then
          pick (Printf.sprintf "%s-%d" base k) (k + 1)
        else name
      in
      let name = pick base 2 in
      Hashtbl.add used (String.lowercase_ascii name) ();
      (v, "records/" ^ name ^ ".jsonl"))
    verifiers

let pretty j = Yojson.Safe.pretty_to_string j ^ "\n"

let policies_json (policies : (string * Haltsql.Policy.t) list)
    (entries : Index.entry list) =
  let seen : (string * string, int * float * float) Hashtbl.t = Hashtbl.create 8 in
  List.iter
    (fun (e : Index.entry) ->
      let k = (e.record.policy, Option.value e.record.policy_version ~default:"(none)") in
      let n, a, b = Option.value (Hashtbl.find_opt seen k) ~default:(0, e.ts, e.ts) in
      Hashtbl.replace seen k (n + 1, Float.min a e.ts, Float.max b e.ts))
    entries;
  let seen = Hashtbl.fold (fun k v acc -> (k, v) :: acc) seen [] |> List.sort compare in
  `Assoc
    [
      ( "seen_in_records",
        `List
          (List.map
             (fun ((name, version), (n, first, last)) ->
               `Assoc
                 [
                   ("policy", `String name);
                   ("version", `String version);
                   ("records", `Int n);
                   ("first_seen", `String (Api.iso8601 first));
                   ("last_seen", `String (Api.iso8601 last));
                 ])
             seen) );
      ( "loaded",
        `List
          (List.map
             (fun (name, (p : Haltsql.Policy.t)) ->
               `Assoc
                 [
                   ("name", `String name);
                   ("version", `String p.version);
                   ( "mode",
                     `String
                       (match p.mode with
                       | Haltsql.Policy.Enforce -> "enforce"
                       | Shadow -> "shadow") );
                   ("owner", Api.opt_string p.owner);
                   ("document", Haltsql.Policy_load.to_json p);
                 ])
             policies) );
    ]

(* Every activity entry of the period, streamed from every activity file (rotated ones
   included) off the event loop. *)
let activity_lines (ctx : Ctx.t) ~since ~until =
  let b = Buffer.create 4096 in
  let+ () =
    Activity.iter_all ctx (fun j ->
        (match Api.member "at" j with
        | Some (`String s) -> (
            match Api.parse_time s with
            | Some t when t >= since && t < until ->
                Buffer.add_string b (Yojson.Safe.to_string j);
                Buffer.add_char b '\n'
            | _ -> ())
        | _ -> ());
        Lwt.return_unit)
  in
  Buffer.contents b

let readme ~id ~framework ~since ~until ~builder ~created ~records ~chains ~gaps ~files
    ~include_sql =
  let b = Buffer.create 2048 in
  let p fmt = Printf.bprintf b fmt in
  p "# HaltSQL evidence pack %s\n\n" id;
  p "- Framework: %s\n" (Controls.framework_name framework);
  p "- Period: %s to %s (UTC, end exclusive)\n" (Api.iso8601 since) (Api.iso8601 until);
  p "- Built by: %s, %s\n" builder (Api.iso8601 created);
  p "- Audit records: %d\n" records;
  p "- Audit chains intact: %d of %d verifiers\n\n" (fst chains) (snd chains);
  p "## Disclaimer\n\n%s\n\n" Controls.disclaimer;
  p "## Scope\n\n";
  p
    "This pack holds what the HaltSQL console had for the period: the audit records it \
     ingested from the configured audit sources (within its retention window), the \
     verification of their hash chains, the policy versions in those records and the \
     policies loaded now, the console's activity log, the configured PII exceptions and \
     the control mapping. Records outside the console's retention window are not \
     included; verify the full audit store with `haltsql audit verify`.\n\n";
  p "## Raw SQL\n\n";
  if include_sql then
    p
      "SQL text is included in the records, as ingested. The builder gave a reason for \
       seeing raw SQL; it is in `manifest.json` (`raw_sql`) and the console's activity \
       log.\n\n"
  else
    p
      "SQL text (`sql`, `statement`) is removed from the records; `sql_sha256` is kept. \
       `chains.json` is verified on the records as ingested, so a record whose SQL was \
       removed no longer verifies on its own from this pack: verify it against the audit \
       store with `haltsql audit verify`. A pack with SQL needs the `see_raw_sql` \
       permission and a reason.\n\n";
  p "## Gaps\n\n";
  if gaps = [] then p "None detected.\n\n"
  else
    List.iter
      (fun g ->
        let s k = match Api.member k g with Some (`String x) -> x | _ -> "" in
        p "- %s (%s): %s\n" (s "name") (s "kind") (s "detail"))
      gaps;
  if gaps <> [] then p "\n";
  p "## Files\n\n";
  List.iter (fun (path, what) -> p "- `%s`: %s\n" path what) files;
  p "\nEvery file's SHA-256 is in `manifest.json`.\n";
  Buffer.contents b

let sha256 s = Digestif.SHA256.(to_hex (digest_string s))

type built = {
  manifest_sha256 : string;
  records : int;
  chains : int * int;
  bytes : int;
  sql_redacted : int;  (** records whose SQL text was removed *)
}

type input = {
  id : string;
  framework : string;
  since : float;
  until : float;
  builder : Ctx.principal;
  created : float;
  gaps : Yojson.Safe.t list;
  activity : string;
  entries : Index.entry list;  (** the period's records, oldest first *)
  policies : (string * Haltsql.Policy.t) list;
  exceptions : C.exception_ list;
  environment : C.environment;
  sql_reason : string option;  (** [Some reason] when the pack includes SQL text *)
}
(** Everything a build reads, gathered on the Lwt thread so the build itself can run in a
    worker thread without touching shared mutable state (index, registry). *)

(* Groups entries per verifier (sorted by name), each in [seq] order. *)
let group_by_verifier (entries : Index.entry list) =
  let tbl : (string, Index.entry list) Hashtbl.t = Hashtbl.create 8 in
  List.iter
    (fun (e : Index.entry) ->
      Hashtbl.replace tbl e.verifier
        (e :: Option.value (Hashtbl.find_opt tbl e.verifier) ~default:[]))
    entries;
  Hashtbl.fold (fun v es acc -> (v, es) :: acc) tbl []
  |> List.sort (fun (a, _) (b, _) -> compare a b)
  |> List.map (fun (v, es) ->
      (v, List.sort (fun (a : Index.entry) b -> compare a.seq b.seq) es))

(** Builds the pack into [out] (a .tar.gz stream; see {!Pack.create}), one file at a time:
    only the file being written is held in memory. Pure apart from [out], so it can run in
    a worker thread. Files are written in order README.md, records, the other data files,
    manifest.json (which hashes every file before it). *)
let write_pack_to (inp : input) (out : Pack.sink) =
  let include_sql = inp.sql_reason <> None in
  let by_verifier = group_by_verifier inp.entries in
  let n_records = List.length inp.entries in
  let chain_results = List.map (fun (v, es) -> chain_report v es) by_verifier in
  let chains_ok = List.length (List.filter fst chain_results) in
  let chains = (chains_ok, List.length chain_results) in
  let names = record_file_names (List.map fst by_verifier) in
  let now = Ctx.now () in
  let controls = Option.get (Controls.for_framework inp.framework) in
  let small_files =
    [
      ( "chains.json",
        fun () ->
          pretty
            (`Assoc
               [
                 ("verified", `Int chains_ok);
                 ("total", `Int (snd chains));
                 ("chains", `List (List.map snd chain_results));
               ]) );
      ("policies.json", fun () -> pretty (policies_json inp.policies inp.entries));
      ("activity.jsonl", fun () -> inp.activity);
      ( "exceptions.json",
        fun () ->
          pretty
            (`Assoc
               [
                 ( "exceptions",
                   `List
                     (List.map
                        (fun e ->
                          match Data.exception_to_json ~now e with
                          | `Assoc l ->
                              `Assoc
                                (l
                                @ [ ("status", `String (Data.exception_status ~now e)) ])
                          | j -> j)
                        inp.exceptions) );
               ]) );
      ("controls.json", fun () -> pretty (Controls.to_json inp.framework controls));
    ]
  in
  let describe = function
    | "chains.json" -> "hash-chain verification per verifier"
    | "policies.json" -> "policy versions seen in records and loaded now"
    | "activity.jsonl" -> "console activity log for the period"
    | "exceptions.json" -> "configured PII exceptions and their status"
    | "controls.json" -> "control mapping for the framework"
    | "README.md" -> "this file"
    | "manifest.json" -> "file hashes, counts, chain results, builder and period"
    | f -> (
        match List.find_opt (fun (_, path) -> path = f) names with
        | Some (v, _) -> "audit records of verifier " ^ v
        | None -> f)
  in
  let file_list =
    ("README.md", describe "README.md")
    :: ("manifest.json", describe "manifest.json")
    :: List.map (fun (_, path) -> (path, describe path)) names
    @ List.map (fun (f, _) -> (f, describe f)) small_files
  in
  let readme_s =
    readme ~id:inp.id ~framework:inp.framework ~since:inp.since ~until:inp.until
      ~builder:inp.builder.id ~created:inp.created ~records:n_records ~chains
      ~gaps:inp.gaps ~files:file_list ~include_sql
  in
  let w = Pack.create ~mtime:inp.created out in
  let hashed = ref [] in
  let add ?verifier path contents =
    Pack.add_file w ~name:(inp.id ^ "/" ^ path) contents;
    hashed :=
      `Assoc
        ([
           ("path", `String path);
           ("sha256", `String (sha256 contents));
           ("bytes", `Int (String.length contents));
         ]
        @ match verifier with Some v -> [ ("verifier", `String v) ] | None -> [])
      :: !hashed
  in
  add "README.md" readme_s;
  let redacted = ref 0 in
  List.iter2
    (fun (v, es) (_, path) ->
      let b = Buffer.create 4096 in
      List.iter
        (fun e ->
          let line, removed = record_line ~include_sql e in
          if removed then incr redacted;
          Buffer.add_string b line;
          Buffer.add_char b '\n')
        es;
      add ~verifier:v path (Buffer.contents b))
    by_verifier names;
  List.iter (fun (path, contents) -> add path (contents ())) small_files;
  let b = inp.builder in
  let manifest =
    `Assoc
      [
        ("id", `String inp.id);
        ("framework", `String inp.framework);
        ( "period",
          `Assoc
            [
              ("since", `String (Api.iso8601 inp.since));
              ("until", `String (Api.iso8601 inp.until));
            ] );
        ("created", `String (Api.iso8601 inp.created));
        ( "builder",
          `Assoc
            [
              ("id", `String b.id);
              ("name", `String b.name);
              ("role", `String (Rbac.role_to_string b.role));
              ( "roles",
                `List (List.map (fun r -> `String (Rbac.role_to_string r)) b.roles) );
              ("auth", `String b.auth);
            ] );
        ("generator", `String ("haltsql-console " ^ Haltsql.version));
        ( "environment",
          `Assoc
            [
              ("org", `String inp.environment.org);
              ("name", `String inp.environment.env_name);
            ] );
        ( "records",
          `Assoc
            [
              ("total", `Int n_records);
              ( "by_verifier",
                `Assoc (List.map (fun (v, es) -> (v, `Int (List.length es))) by_verifier)
              );
            ] );
        ( "raw_sql",
          `Assoc
            [
              ("included", `Bool include_sql);
              ("reason", Api.opt_string inp.sql_reason);
              ("redacted_records", `Int !redacted);
            ] );
        ( "chains",
          `Assoc
            [
              ("verified", `Int chains_ok);
              ("total", `Int (snd chains));
              ( "results",
                `List
                  (List.map
                     (fun (_, j) ->
                       let pick k = Option.value (Api.member k j) ~default:`Null in
                       `Assoc
                         [
                           ("verifier", pick "verifier");
                           ("state", pick "state");
                           ("records", pick "records");
                         ])
                     chain_results) );
            ] );
        ("gaps", `List inp.gaps);
        ("files", `List (List.rev !hashed));
        ("disclaimer", `String Controls.disclaimer);
      ]
  in
  let manifest_s = pretty manifest in
  Pack.add_file w ~name:(inp.id ^ "/manifest.json") manifest_s;
  Pack.finish w;
  (sha256 manifest_s, n_records, chains, !redacted)

(** Builds the pack into [tmp] with blocking I/O and fsyncs it. Run in a worker thread
    ([Lwt_preemptive.detach]), never on the event loop. *)
let build_to_file (inp : input) ~tmp =
  let oc = open_out_gen [ Open_wronly; Open_creat; Open_trunc; Open_binary ] 0o600 tmp in
  Fun.protect
    ~finally:(fun () -> close_out_noerr oc)
    (fun () ->
      let bytes = ref 0 in
      let manifest_sha256, records, chains, sql_redacted =
        write_pack_to inp (fun s ->
            bytes := !bytes + String.length s;
            output_string oc s)
      in
      flush oc;
      Unix.fsync (Unix.descr_of_out_channel oc);
      { manifest_sha256; records; chains; bytes = !bytes; sql_redacted })

(* ---- pack metadata ---- *)

let pack_path (ctx : Ctx.t) id = Store.blob_path ctx.store ~subdir:"packs" (id ^ ".tar.gz")

let set_fields (ctx : Ctx.t) id fields =
  let* _ =
    Store.update ctx.store "packs" id (function
      | Some (`Assoc l) ->
          let l =
            List.map
              (fun (k, v) ->
                match List.assoc_opt k fields with Some v' -> (k, v') | None -> (k, v))
              l
          in
          Some (`Assoc (l @ List.filter (fun (k, _) -> not (List.mem_assoc k l)) fields))
      | other -> other)
  in
  Lwt.return_unit

let public_fields =
  [
    "id";
    "framework";
    "since";
    "until";
    "built_by";
    "created";
    "state";
    "records";
    "chains";
    "manifest_sha256";
    "bytes";
    "include_sql";
    "sql_redacted";
    "gaps";
    "error";
  ]

let public (doc : Yojson.Safe.t) =
  match doc with
  | `Assoc l -> `Assoc (List.filter (fun (k, _) -> List.mem k public_fields) l)
  | j -> j

(* ---- limits and retention ---- *)

(** At most this many records per pack; a larger period is refused (400) so a build's
    memory stays bounded. A ref so tests can lower it. *)
let max_pack_records = ref 1_000_000

(** Packs kept: after each successful build, the oldest finished packs (and their files)
    beyond this count are deleted. A ref so tests can lower it. *)
let max_packs = ref 20

(* One build at a time per console. *)
let building_key : bool ref Ctx.Key.t = Ctx.Key.create "evidence.building"

let building (ctx : Ctx.t) =
  match Ctx.get ctx building_key with
  | Some b -> b
  | None ->
      let b = ref false in
      Ctx.set ctx building_key b;
      b

(** For tests only. *)
module Testing = struct
  (** Runs before a build starts its work (after the 202 went out). *)
  let before_build : (unit -> unit Lwt.t) ref = ref (fun () -> Lwt.return_unit)
end

let remove_file path =
  Lwt.catch
    (fun () -> Lwt_unix.unlink path)
    (function Unix.Unix_error (Unix.ENOENT, _, _) -> Lwt.return_unit | e -> Lwt.fail e)

(* Deletes a pack's file and its metadata (file first: a crash in between leaves
   metadata without a file, which download reports as missing). *)
let delete_pack (ctx : Ctx.t) id =
  let* () = remove_file (pack_path ctx id) in
  Store.delete ctx.store "packs" id

(** Deletes the oldest finished packs beyond {!max_packs}. *)
let prune (ctx : Ctx.t) =
  let finished =
    Store.fold ctx.store "packs"
      (fun id doc acc ->
        match Api.member "state" doc with
        | Some (`String "building") -> acc
        | _ -> id :: acc)
      []
    |> List.rev
  in
  let excess = List.length finished - !max_packs in
  let rec take n = function x :: t when n > 0 -> x :: take (n - 1) t | _ -> [] in
  Lwt_list.iter_s
    (fun id ->
      log "info" "evidence pack %s deleted (retention: %d packs)" id !max_packs;
      delete_pack ctx id)
    (take excess finished)

let build_async (ctx : Ctx.t) ~id ~framework ~since ~until ~builder ~created ~gaps
    ~sql_reason =
  let flag = building ctx in
  let path = pack_path ctx id in
  let tmp = path ^ ".tmp" in
  Lwt.async (fun () ->
      Lwt.finalize
        (fun () ->
          Lwt.catch
            (fun () ->
              (* Let the 202 response go out first. *)
              let* () = Lwt.pause () in
              let* () = !Testing.before_build () in
              let* activity = activity_lines ctx ~since ~until in
              let inp =
                {
                  id;
                  framework;
                  since;
                  until;
                  builder;
                  created;
                  gaps;
                  activity;
                  entries = Index.between ctx.index ~since ~until;
                  policies = Policy_set.get ctx;
                  exceptions = ctx.config.exceptions;
                  environment = ctx.config.environment;
                  sql_reason;
                }
              in
              (* Serialising, hashing and archiving run in a worker thread, so the event
                 loop keeps serving requests; the file is written there with blocking,
                 fsynced I/O, then renamed into place. *)
              let* b = Lwt_preemptive.detach (fun () -> build_to_file inp ~tmp) () in
              let* () = Lwt_unix.rename tmp path in
              let* () = Store.fsync_dir (Filename.dirname path) in
              let* () =
                set_fields ctx id
                  [
                    ("state", `String "ready");
                    ("records", `Int b.records);
                    ( "chains",
                      `Assoc
                        [
                          ("verified", `Int (fst b.chains)); ("total", `Int (snd b.chains));
                        ] );
                    ("manifest_sha256", `String b.manifest_sha256);
                    ("bytes", `Int b.bytes);
                    ("sql_redacted", `Int b.sql_redacted);
                  ]
              in
              prune ctx)
            (fun e ->
              log "error" "evidence pack %s failed: %s" id (Printexc.to_string e);
              let* () =
                Lwt.catch (fun () -> remove_file tmp) (fun _ -> Lwt.return_unit)
              in
              set_fields ctx id
                [
                  ("state", `String "failed");
                  ("error", `String "the pack could not be built");
                ]))
        (fun () ->
          flag := false;
          Lwt.return_unit))

let time_field name body ~default =
  match Api.str_field name body with
  | None -> (
      match default with
      | Some t -> t
      | None -> Api.bad_request "field %s is required" name)
  | Some s -> (
      match Api.parse_time s with
      | Some t -> t
      | None -> Api.bad_request "field %s is not RFC 3339" name)

let create_handler (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let* body = Router.json_body r in
  let reason = Ctx.require ~body p r.http Rbac.Build_evidence in
  let framework =
    match Api.str_field ~required:true "framework" body with
    | Some f when Controls.for_framework f <> None -> f
    | Some f ->
        Api.bad_request "framework must be one of %s (got %S)"
          (String.concat ", " Controls.frameworks)
          f
    | None -> assert false
  in
  (* SQL text is only included on request, under the same rule as viewing one record's
     SQL: [see_raw_sql], with its reason. *)
  let sql_reason =
    match Api.bool_field "include_sql" body with
    | Some true -> (
        match Ctx.require ~body p r.http Rbac.See_raw_sql with
        | Some r -> Some r
        | None -> Some (Option.value reason ~default:"(granted without a reason)"))
    | _ -> None
  in
  let now = Ctx.now () in
  let until = time_field "until" body ~default:(Some now) in
  let since = time_field "since" body ~default:None in
  if since >= until then Api.bad_request "since must be before until";
  let flag = building ctx in
  if !flag then
    Api.fail `Conflict "BUILD_IN_PROGRESS"
      "an evidence pack is already being built; retry when it is ready";
  let n_records =
    Index.count ctx.index { Index.no_filter with since = Some since; until = Some until }
  in
  if n_records > !max_pack_records then
    Api.bad_request
      "the period holds %d records; a pack holds at most %d: narrow the period" n_records
      !max_pack_records;
  flag := true;
  Lwt.catch
    (fun () ->
      let* n = Store.next_counter ctx.store "packs" ~start:1 in
      let id = Printf.sprintf "pack_%d" n in
      let gaps = gaps ctx ~since in
      let include_sql = sql_reason <> None in
      let doc =
        `Assoc
          [
            ("id", `String id);
            ("framework", `String framework);
            ("since", `String (Api.iso8601 since));
            ("until", `String (Api.iso8601 until));
            ("built_by", `String p.id);
            ("created", `String (Api.iso8601 now));
            ("state", `String "building");
            ("records", `Null);
            ("chains", `Null);
            ("manifest_sha256", `Null);
            ("bytes", `Null);
            ("include_sql", `Bool include_sql);
            ("sql_redacted", `Null);
            ("gaps", `List gaps);
            ("error", `Null);
          ]
      in
      let* () = Store.put ctx.store "packs" id doc in
      let* () =
        Activity.log ctx p
          ?reason:(match sql_reason with Some _ as r -> r | None -> reason)
          ~action:"evidence.build" ~target:id
          ~detail:
            (`Assoc
               [
                 ("framework", `String framework);
                 ("since", `String (Api.iso8601 since));
                 ("until", `String (Api.iso8601 until));
                 ("include_sql", `Bool include_sql);
               ])
          ()
      in
      build_async ctx ~id ~framework ~since ~until ~builder:p ~created:now ~gaps
        ~sql_reason;
      Api.json ~status:`Accepted
        (`Assoc [ ("id", `String id); ("state", `String "building") ]))
    (fun e ->
      flag := false;
      Lwt.fail e)

let list_handler (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  ignore (Ctx.require p r.http Rbac.Build_evidence);
  let packs = Store.fold ctx.store "packs" (fun _ d acc -> public d :: acc) [] in
  Api.json (`Assoc [ ("packs", `List packs) ])

let download_chunk = 65536

(* Streams the file in chunks with Lwt_io: never held in memory as a whole. *)
let stream_file path =
  let* ic = Lwt_io.open_file ~flags:[ Unix.O_RDONLY ] ~mode:Lwt_io.input path in
  let* size = Lwt_io.length ic in
  let closed = ref false in
  let close () =
    if !closed then Lwt.return_unit
    else (
      closed := true;
      Lwt_io.close ic)
  in
  let stream =
    Lwt_stream.from (fun () ->
        Lwt.catch
          (fun () ->
            let* s = Lwt_io.read ~count:download_chunk ic in
            if s = "" then
              let* () = close () in
              Lwt.return_none
            else Lwt.return_some s)
          (fun e ->
            let* () = close () in
            Lwt.fail e))
  in
  Lwt.return (size, stream)

let download_handler (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let reason = Ctx.require p r.http Rbac.Build_evidence in
  let id = Router.param r "id" in
  match Store.get ctx.store "packs" id with
  | None -> Api.not_found "no evidence pack %s" id
  | Some doc -> (
      match Api.member "state" doc with
      | Some (`String "ready") ->
          let path = pack_path ctx id in
          let* size, stream =
            Lwt.catch
              (fun () -> stream_file path)
              (function
                | Unix.Unix_error (Unix.ENOENT, _, _) ->
                    Api.not_found "evidence pack %s is missing" id
                | e -> Lwt.fail e)
          in
          let* () =
            Activity.log ctx p ?reason ~action:"evidence.download" ~target:id
              ~detail:
                (`Assoc
                   [
                     ( "manifest_sha256",
                       Option.value (Api.member "manifest_sha256" doc) ~default:`Null );
                   ])
              ()
          in
          let headers =
            Cohttp.Header.of_list
              ((("content-type", "application/gzip") :: Api.base_headers)
              @ [
                  ("content-length", Int64.to_string size);
                  ( "content-disposition",
                    Printf.sprintf "attachment; filename=\"haltsql-evidence-%s.tar.gz\""
                      id );
                ])
          in
          Cohttp_lwt_unix.Server.respond ~headers ~status:`OK
            ~body:(Cohttp_lwt.Body.of_stream stream)
            ()
      | Some (`String st) -> Api.conflict "evidence pack %s is %s" id st
      | _ -> Api.conflict "evidence pack %s is not ready" id)

let delete_handler (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let reason = Ctx.require p r.http Rbac.Build_evidence in
  let id = Router.param r "id" in
  match Store.get ctx.store "packs" id with
  | None -> Api.not_found "no evidence pack %s" id
  | Some doc ->
      (match Api.member "state" doc with
      | Some (`String "building") -> Api.conflict "evidence pack %s is building" id
      | _ -> ());
      let* () = delete_pack ctx id in
      let* () =
        Activity.log ctx p ?reason ~action:"evidence.delete" ~target:id
          ~detail:
            (`Assoc
               [
                 ( "manifest_sha256",
                   Option.value (Api.member "manifest_sha256" doc) ~default:`Null );
               ])
          ()
      in
      Api.json (`Assoc [ ("id", `String id); ("deleted", `Bool true) ])

let routes : Router.route list =
  [
    Router.get "/api/v1/evidence/controls" controls_handler;
    Router.post "/api/v1/evidence/packs" create_handler;
    Router.get "/api/v1/evidence/packs" list_handler;
    Router.get "/api/v1/evidence/packs/:id/download" download_handler;
    Router.delete "/api/v1/evidence/packs/:id" delete_handler;
  ]

(* Packs left "building" by a restart can never finish: mark them failed and remove
   their partial files. *)
let start (ctx : Ctx.t) : unit Lwt.t =
  Lwt.catch
    (fun () ->
      let building =
        Store.fold ctx.store "packs"
          (fun id doc acc ->
            match Api.member "state" doc with
            | Some (`String "building") -> id :: acc
            | _ -> acc)
          []
      in
      Lwt_list.iter_s
        (fun id ->
          let* () = remove_file (pack_path ctx id ^ ".tmp") in
          set_fields ctx id
            [ ("state", `String "failed"); ("error", `String "interrupted by a restart") ])
        (List.rev building))
    (fun e ->
      log "error" "evidence startup check failed: %s" (Printexc.to_string e);
      Lwt.return_unit)
