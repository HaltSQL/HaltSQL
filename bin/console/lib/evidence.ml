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

let gaps (ctx : Ctx.t) =
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

(* ---- chains ---- *)

let line_of (e : Index.entry) = Yojson.Safe.to_string e.raw

(** Hash-chain verification of one verifier's included records, in stream order. The first
    record's [prev_hash] is accepted as is (the period rarely starts at genesis). *)
let chain_report verifier (entries : Index.entry list) =
  let n = List.length entries in
  let hashed = List.filter (fun (e : Index.entry) -> e.hash <> None) entries in
  let base state extra =
    `Assoc
      ([ ("verifier", `String verifier); ("records", `Int n); ("state", `String state) ]
      @ extra)
  in
  if n = 0 then (false, base "unknown" [ ("detail", `String "no records") ])
  else if hashed = [] then
    (false, base "unknown" [ ("detail", `String "records carry no hash chain") ])
  else
    match
      Haltsql_cloud.Audit_chain.verify_lines ~initial_prev:None (List.map line_of entries)
    with
    | Ok k ->
        ( true,
          base "intact"
            [
              ("verified", `Int k);
              ("first_hash", Api.opt_string (List.hd entries).hash);
              ("head_hash", Api.opt_string (List.nth entries (n - 1)).hash);
            ] )
    | Error (line, problem) ->
        let bad = List.nth_opt entries (line - 1) in
        ( false,
          base "broken"
            [
              ("verified", `Int (max 0 (line - 1)));
              ( "first_break",
                `Assoc
                  [
                    ("line", `Int line);
                    ("problem", `String problem);
                    ( "request_id",
                      match bad with Some e -> `String e.request_id | None -> `Null );
                    ( "location",
                      match bad with Some e -> `String e.location | None -> `Null );
                  ] );
            ] )

(* ---- pack contents ---- *)

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

let pretty j = Yojson.Safe.pretty_to_string j ^ "\n"

let policies_json (ctx : Ctx.t) (entries : Index.entry list) =
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
             (Policy_set.get ctx)) );
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

let readme ~id ~framework ~since ~until ~builder ~created ~records ~chains ~gaps ~files =
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

type built = { tgz : string; manifest_sha256 : string; records : int; chains : int * int }

let build_pack (ctx : Ctx.t) ~id ~framework ~since ~until ~(builder : Ctx.principal)
    ~created ~gaps ~activity =
  let entries = Index.between ctx.index ~since ~until in
  let by_verifier =
    List.sort_uniq compare (List.map (fun (e : Index.entry) -> e.verifier) entries)
    |> List.map (fun v ->
        ( v,
          List.filter (fun (e : Index.entry) -> e.verifier = v) entries
          |> List.sort (fun (a : Index.entry) b -> compare a.seq b.seq) ))
  in
  let chain_results = List.map (fun (v, es) -> chain_report v es) by_verifier in
  let chains_ok = List.length (List.filter fst chain_results) in
  let chains = (chains_ok, List.length chain_results) in
  let record_files =
    List.map
      (fun (v, es) ->
        ( "records/" ^ safe_file_name v ^ ".jsonl",
          String.concat "" (List.map (fun e -> line_of e ^ "\n") es) ))
      by_verifier
  in
  let now = Ctx.now () in
  let controls = Option.get (Controls.for_framework framework) in
  let data_files =
    record_files
    @ [
        ( "chains.json",
          pretty
            (`Assoc
               [
                 ("verified", `Int chains_ok);
                 ("total", `Int (snd chains));
                 ("chains", `List (List.map snd chain_results));
               ]) );
        ("policies.json", pretty (policies_json ctx entries));
        ("activity.jsonl", activity);
        ( "exceptions.json",
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
                        ctx.config.exceptions) );
               ]) );
        ("controls.json", pretty (Controls.to_json framework controls));
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
    | f ->
        "raw audit records of verifier " ^ Filename.remove_extension (Filename.basename f)
  in
  let file_list =
    ("README.md", describe "README.md")
    :: ("manifest.json", describe "manifest.json")
    :: List.map (fun (f, _) -> (f, describe f)) data_files
  in
  let readme_s =
    readme ~id ~framework ~since ~until ~builder:builder.id ~created
      ~records:(List.length entries) ~chains ~gaps ~files:file_list
  in
  let hashed = ("README.md", readme_s) :: data_files in
  let manifest =
    `Assoc
      [
        ("id", `String id);
        ("framework", `String framework);
        ( "period",
          `Assoc
            [
              ("since", `String (Api.iso8601 since));
              ("until", `String (Api.iso8601 until));
            ] );
        ("created", `String (Api.iso8601 created));
        ( "builder",
          `Assoc
            [
              ("id", `String builder.id);
              ("name", `String builder.name);
              ("role", `String (Rbac.role_to_string builder.role));
              ( "roles",
                `List (List.map (fun r -> `String (Rbac.role_to_string r)) builder.roles)
              );
              ("auth", `String builder.auth);
            ] );
        ("generator", `String ("haltsql-console " ^ Haltsql.version));
        ( "environment",
          `Assoc
            [
              ("org", `String ctx.config.environment.org);
              ("name", `String ctx.config.environment.env_name);
            ] );
        ( "records",
          `Assoc
            [
              ("total", `Int (List.length entries));
              ( "by_verifier",
                `Assoc (List.map (fun (v, es) -> (v, `Int (List.length es))) by_verifier)
              );
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
        ("gaps", `List gaps);
        ( "files",
          `List
            (List.map
               (fun (path, contents) ->
                 `Assoc
                   [
                     ("path", `String path);
                     ("sha256", `String (sha256 contents));
                     ("bytes", `Int (String.length contents));
                   ])
               hashed) );
        ("disclaimer", `String Controls.disclaimer);
      ]
  in
  let manifest_s = pretty manifest in
  let files =
    List.map (fun (p, c) -> (id ^ "/" ^ p, c)) (("manifest.json", manifest_s) :: hashed)
  in
  {
    tgz = Pack.tar_gz ~mtime:created files;
    manifest_sha256 = sha256 manifest_s;
    records = List.length entries;
    chains;
  }

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
    "gaps";
    "error";
  ]

let public (doc : Yojson.Safe.t) =
  match doc with
  | `Assoc l -> `Assoc (List.filter (fun (k, _) -> List.mem k public_fields) l)
  | j -> j

(* Writes the pack durably off the event loop: a temporary file, fsynced, renamed into
   place, then the directory fsynced. *)
let write_pack path contents =
  let tmp = path ^ ".tmp" in
  let* fd =
    Lwt_unix.openfile tmp
      [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC; Unix.O_CLOEXEC ]
      0o600
  in
  let* () =
    Lwt.finalize
      (fun () ->
        let* () = Store.write_all fd contents in
        Store.fsync fd)
      (fun () -> Lwt_unix.close fd)
  in
  let* () = Lwt_unix.rename tmp path in
  Store.fsync_dir (Filename.dirname path)

let build_async (ctx : Ctx.t) ~id ~framework ~since ~until ~builder ~created ~gaps =
  Lwt.async (fun () ->
      Lwt.catch
        (fun () ->
          (* Let the 202 response go out first. *)
          let* () = Lwt.pause () in
          let* activity = activity_lines ctx ~since ~until in
          let b =
            build_pack ctx ~id ~framework ~since ~until ~builder ~created ~gaps ~activity
          in
          let* () = write_pack (pack_path ctx id) b.tgz in
          set_fields ctx id
            [
              ("state", `String "ready");
              ("records", `Int b.records);
              ( "chains",
                `Assoc
                  [ ("verified", `Int (fst b.chains)); ("total", `Int (snd b.chains)) ] );
              ("manifest_sha256", `String b.manifest_sha256);
              ("bytes", `Int (String.length b.tgz));
            ])
        (fun e ->
          log "error" "evidence pack %s failed: %s" id (Printexc.to_string e);
          set_fields ctx id
            [
              ("state", `String "failed"); ("error", `String "the pack could not be built");
            ]))

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
  let now = Ctx.now () in
  let until = time_field "until" body ~default:(Some now) in
  let since = time_field "since" body ~default:None in
  if since >= until then Api.bad_request "since must be before until";
  let* n = Store.next_counter ctx.store "packs" ~start:1 in
  let id = Printf.sprintf "pack_%d" n in
  let gaps = gaps ctx in
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
        ("gaps", `List gaps);
        ("error", `Null);
      ]
  in
  let* () = Store.put ctx.store "packs" id doc in
  let* () =
    Activity.log ctx p ?reason ~action:"evidence.build" ~target:id
      ~detail:
        (`Assoc
           [
             ("framework", `String framework);
             ("since", `String (Api.iso8601 since));
             ("until", `String (Api.iso8601 until));
           ])
      ()
  in
  build_async ctx ~id ~framework ~since ~until ~builder:p ~created:now ~gaps;
  Api.json ~status:`Accepted
    (`Assoc [ ("id", `String id); ("state", `String "building") ])

let list_handler (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  ignore (Ctx.require p r.http Rbac.Build_evidence);
  let packs = Store.fold ctx.store "packs" (fun _ d acc -> public d :: acc) [] in
  Api.json (`Assoc [ ("packs", `List packs) ])

let download_handler (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let reason = Ctx.require p r.http Rbac.Build_evidence in
  let id = Router.param r "id" in
  match Store.get ctx.store "packs" id with
  | None -> Api.not_found "no evidence pack %s" id
  | Some doc -> (
      match Api.member "state" doc with
      | Some (`String "ready") ->
          let path = pack_path ctx id in
          if not (Sys.file_exists path) then
            Api.not_found "evidence pack %s is missing" id;
          let body = In_channel.with_open_bin path In_channel.input_all in
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
          Api.bytes ~content_type:"application/gzip"
            ~headers:
              [
                ( "content-disposition",
                  Printf.sprintf "attachment; filename=\"haltsql-evidence-%s.tar.gz\"" id
                );
              ]
            body
      | Some (`String st) -> Api.conflict "evidence pack %s is %s" id st
      | _ -> Api.conflict "evidence pack %s is not ready" id)

let routes : Router.route list =
  [
    Router.get "/api/v1/evidence/controls" controls_handler;
    Router.post "/api/v1/evidence/packs" create_handler;
    Router.get "/api/v1/evidence/packs" list_handler;
    Router.get "/api/v1/evidence/packs/:id/download" download_handler;
  ]

(* Packs left "building" by a restart can never finish: mark them failed. *)
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
          set_fields ctx id
            [ ("state", `String "failed"); ("error", `String "interrupted by a restart") ])
        (List.rev building))
    (fun e ->
      log "error" "evidence startup check failed: %s" (Printexc.to_string e);
      Lwt.return_unit)
