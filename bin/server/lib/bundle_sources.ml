(* Remote signed policy bundles ([policies[].bundle_source]): starts one
   Haltsql_bundle_source poller per entry and plugs the verified bundles into
   State.

   - At startup every source must yield a verified bundle (from the source, or
     from its cache_dir when the source is down); otherwise the server does not
     start (fail closed: the policies it would provide are missing).
   - While running, each newly verified bundle triggers a full State reload with
     that bundle in place of the source's previous one. The reload re-runs the
     duplicate-name checks (against the config file, local bundles and the other
     sources) and every policy-reference check; if anything fails the bundle is
     rejected (not current, not cached) and the last good set stays active.
   - Signature verification, rollback protection, name_prefix and the cache are
     handled by Haltsql_bundle_source itself.
   - The list of sources is read at startup: adding, removing or changing a
     bundle_source entry needs a restart (a reload keeps the running pollers). *)

open Lwt.Syntax
open Haltsql
module B = Haltsql_bundle_source

type mode = Startup of (string, (string * Policy.t) list) Hashtbl.t | Running of State.t

let log_error src (e : B.error) =
  Log.warn "bundle source poll failed; keeping the last good bundle"
    ~fields:
      [
        ("source", `String src);
        ("code", `String (B.error_code e));
        ("error", `String (B.error_to_string e));
      ]

let replace_assoc k v l =
  if List.mem_assoc k l then
    List.map (fun (k', v') -> if k' = k then (k, v) else (k', v')) l
  else l @ [ (k, v) ]

let on_update (mode : mode ref) (u : B.update) =
  match !mode with
  | Startup tbl ->
      Hashtbl.replace tbl u.source u.policies;
      Lwt.return_ok ()
  | Running st -> (
      (* The candidate is built from st.remote inside State's reload lock, after
         any other source's reload committed: never from a snapshot taken before. *)
      let* r =
        State.reload_lwt ~reason:("bundle-source " ^ u.source)
          ~update_remote:(replace_assoc u.source u.policies)
          st
      in
      match r with
      | Ok () ->
          Log.info "bundle source updated"
            ~fields:
              [
                ("source", `String u.source);
                ("bundle", `String u.bundle.metadata.name);
                ("bundle_version", `String u.bundle.metadata.version);
                ("signed_by", `String u.signed_by);
                ("revision", match u.revision with Some r -> `String r | None -> `Null);
              ];
          Lwt.return_ok ()
      | Error errs -> Lwt.return_error (String.concat "; " errs))

(* Creates and starts every source of [cfg]. Returns the running pollers and the
   policies of each source (in config order), or the startup errors. *)
let start (cfg : Config.t) ~(mode : mode ref) =
  let tbl = Hashtbl.create 4 in
  mode := Startup tbl;
  let* created =
    Lwt_list.map_s
      (fun (s : Config.bundle_source) ->
        let* r = B.create s in
        Lwt.return r)
      cfg.bundle_sources
  in
  let errs = List.filter_map (function Error e -> Some e | Ok _ -> None) created in
  if errs <> [] then Lwt.return_error (List.map (fun e -> "bundle_source: " ^ e) errs)
  else
    let srcs = List.filter_map Result.to_option created in
    let* results =
      Lwt_list.map_p
        (fun src ->
          let id = B.source_id src in
          let* r =
            B.start ~defer_cache:true src ~on_update:(on_update mode)
              ~on_error:(log_error id)
          in
          Lwt.return (id, r))
        srcs
    in
    let failed =
      List.filter_map
        (fun (id, r) ->
          match r with
          | Ok () -> None
          | Error e ->
              Some
                (Printf.sprintf
                   "bundle source %s: no verified bundle is available (%s: %s)" id
                   (B.error_code e) (B.error_to_string e)))
        results
    in
    if failed <> [] then begin
      List.iter B.stop srcs;
      Lwt.return_error failed
    end
    else
      let remote =
        List.filter_map
          (fun src ->
            let id = B.source_id src in
            Option.map (fun ps -> (id, ps)) (Hashtbl.find_opt tbl id))
          srcs
      in
      Lwt.return_ok (srcs, remote)

(* ---- startup hand-over ----

   Bundles fetched at startup are only cached once the server accepted them
   ([commit]): a bundle the startup checks refuse must not replace the last good
   one in the cache, or every later restart would restore the refused bundle. *)

let current_remote srcs =
  List.filter_map
    (fun src -> Option.map (fun (u : B.update) -> (u.source, u.policies)) (B.current src))
    srcs

(* The policies of each source with the freshly fetched bundles replaced by the
   ones restored from the cache, and the sources that were replaced; [None] when no
   source fetched a bundle different from its cached one. *)
let restored_remote srcs =
  let replaced = ref [] in
  let remote =
    List.filter_map
      (fun src ->
        match (B.current src, B.restored_update src) with
        | Some c, Some r when c != r && c.bundle.metadata <> r.bundle.metadata ->
            replaced := src :: !replaced;
            Some (r.source, r.policies)
        | Some c, _ -> Some (c.source, c.policies)
        | None, _ -> None)
      srcs
  in
  if !replaced = [] then None else Some (remote, List.rev !replaced)

let fall_back srcs ~reason =
  List.iter
    (fun src ->
      if B.fall_back_to_restored src ~reason then
        Log.warn "bundle refused at startup; starting from the cached last good bundle"
          ~fields:
            (("source", `String (B.source_id src))
            :: ("error", `String reason)
            ::
            (match B.current src with
            | Some u ->
                [
                  ("bundle", `String u.bundle.metadata.name);
                  ("bundle_version", `String u.bundle.metadata.version);
                ]
            | None -> [])))
    srcs

let commit srcs =
  List.iter
    (fun src ->
      match B.commit_startup src with
      | Ok () -> ()
      | Error e -> log_error (B.source_id src) e)
    srcs

let stop (st : State.t) = List.iter B.stop st.bundle_sources

(* ---- status and metrics ---- *)

let status_json src : Yojson.Safe.t =
  let s = B.status src in
  `Assoc
    [
      ("source", `String (B.source_id src));
      ( "current",
        match B.current src with
        | None -> `Null
        | Some u ->
            `Assoc
              [
                ("bundle", `String u.bundle.metadata.name);
                ("version", `String u.bundle.metadata.version);
                ("signed_by", `String u.signed_by);
                ("revision", match u.revision with Some r -> `String r | None -> `Null);
                ( "origin",
                  `String
                    (match u.origin with
                    | B.From_cache -> "cache"
                    | B.From_source -> "source") );
                ("policies", `List (List.map (fun (n, _) -> `String n) u.policies));
              ] );
      ("checks", `Int s.checks);
      ( "last_success",
        match s.last_success with Some t -> `String (Log.rfc3339 t) | None -> `Null );
      ( "last_error",
        match s.last_error with
        | None -> `Null
        | Some e ->
            `Assoc
              [
                ("code", `String (B.error_code e));
                ("message", `String (B.error_to_string e));
              ] );
    ]

let metrics_text srcs =
  if srcs = [] then ""
  else
    let b = Buffer.create 512 in
    let p fmt = Printf.bprintf b fmt in
    let label = Metrics.escape_label in
    p
      "# HELP haltsql_bundle_source_healthy 1 when the last poll of the bundle source \
       succeeded.\n\
       # TYPE haltsql_bundle_source_healthy gauge\n";
    List.iter
      (fun src ->
        let s = B.status src in
        p "haltsql_bundle_source_healthy{source=\"%s\"} %d\n"
          (label (B.source_id src))
          (if s.last_error = None then 1 else 0))
      srcs;
    p
      "# HELP haltsql_bundle_source_checks_total Completed polls of the bundle source.\n\
       # TYPE haltsql_bundle_source_checks_total counter\n";
    List.iter
      (fun src ->
        p "haltsql_bundle_source_checks_total{source=\"%s\"} %d\n"
          (label (B.source_id src))
          (B.status src).checks)
      srcs;
    Buffer.contents b
