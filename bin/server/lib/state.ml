(** Server state: static settings, the hot-reloadable snapshot (policies, tokens, OIDC
    providers, mTLS identities, TLS material), audit sinks, and the reload logic. *)

open Haltsql
module Oidc_client = Haltsql_auth.Oidc_client

type snapshot = {
  policies : (string * Policy.t) list;
  tokens : Config.token list;
  default_policy : string option;
  oidc : Oidc_client.registry;
  mtls : Config.mtls_identity list;
  allow_unauthenticated : bool;
      (** [server.auth.allow_unauthenticated]; reloadable so that turning anonymous access
          off takes effect without a restart *)
  watched : string list;  (** files whose changes trigger a reload *)
  opa : Config.opa option;  (** [opa]; reloadable *)
  admin : Config.admin;  (** [server.admin]; reloadable *)
}

type sources = {
  config_file : string option;
  policy_files : string list;  (** from --policy flags *)
  overrides : Config.t -> Config.t;  (** command-line flags, applied last *)
}

type t = {
  cfg : Config.t;
      (** effective settings at startup (listen, audit, ...). Reloadable settings
          (policies, tokens, OIDC, mTLS, allow_unauthenticated) must be read from [snap],
          never from here. *)
  sources : sources;
  mutable snap : snapshot;
  mutable signatures : (string * (float * int * int)) list;
  mutable tls : Tls.Config.server option;
      (** current TLS configuration; [Some] iff TLS was configured at startup *)
  sinks : Audit.sink list;
  started : float;
  mutable draining : bool;
  report : Admin_report.t;  (** shadow analytics window for GET /v1/admin/report *)
  mutable remote : (string * (string * Policy.t) list) list;
      (** policies of the last accepted bundle of each [bundle_source], by source id *)
  mutable bundle_sources : Haltsql_bundle_source.t list;
      (** running pollers (started by [Bundle_sources.start]) *)
  mutable generation : int;  (** incremented by every successful reload *)
  reload_lock : Lwt_mutex.t;
      (** serializes [reload_lwt]: a reload that waits on the secret prefetch must not
          commit a [remote] computed before another reload committed *)
  mutable audit_restart_pending : bool;
      (** the last successful reload carried different audit sinks than the running ones;
          they only take effect after a restart (the running sinks stay) *)
}

(* ---- integration hooks (set by the integrator before [Server.main]) ---- *)

let secret_resolver : (Config.secrets -> (Config.resolver, string) result) option ref =
  ref None

let remote_sink :
    (Config.sink_kind -> on_error:Config.on_error -> (Audit.sink, string) result) option
    ref =
  ref None

let bundle_loader :
    (Config.bundle_ref -> ((string * Policy.t) list, string) result) option ref =
  ref None

let oidc_fetch : Oidc_client.fetch option ref = ref None

let stream_sink : (Config.stream_sink -> (Audit.sink, string) result) option ref =
  ref None

(* Asynchronous secret resolution for reloads, which run inside the Lwt loop
   (no nested [Lwt_main.run]): fetches every provider placeholder of [file]
   concurrently and returns a resolver serving only those cached values. *)
let secret_prefetch : (file:string -> Config.secrets -> Config.resolver Lwt.t) option ref
    =
  ref None

(* ---- loading ---- *)

let errors_to_strings errs = List.map Load_error.to_string errs

let abs path =
  if Filename.is_relative path then Filename.concat (Sys.getcwd ()) path else path

let load_config_file ?resolver f =
  match Config.secrets_of_file f with
  | Error errs -> Error (errors_to_strings errs)
  | Ok secrets -> (
      (* Without a resolver, provider placeholders fail the load with
         "secret provider not configured". *)
      let resolve =
        match (resolver, !secret_resolver) with
        | Some r, _ -> Ok (Some r)
        | None, Some build -> (
            match build secrets with Ok r -> Ok (Some r) | Error e -> Error [ e ])
        | None, None -> Ok None
      in
      match resolve with
      | Error e -> Error e
      | Ok resolve -> Config.of_file ?resolve f |> Result.map_error errors_to_strings)

(* Bundle policies may not shadow a policy defined in the config file or in
   another bundle: a silent override would let one signer replace another's
   policy. ([--policy] flags still override, explicitly.) *)
let check_bundle_duplicates (cfg : Config.t) bundled =
  let rec go seen errs = function
    | [] -> List.rev errs
    | (n, _) :: rest ->
        let errs =
          if List.mem_assoc n cfg.policies then
            Printf.sprintf
              "bundle policy %S duplicates a policy defined in the config file" n
            :: errs
          else if List.mem n seen then
            Printf.sprintf "bundle policy %S is defined by more than one bundle" n :: errs
          else errs
        in
        go (n :: seen) errs rest
  in
  match go [] [] bundled with [] -> Ok bundled | errs -> Error errs

let load_bundles ?(remote = []) (cfg : Config.t) =
  let remote_policies = List.concat_map snd remote in
  match (cfg.policy_bundles, !bundle_loader) with
  | [], _ -> check_bundle_duplicates cfg remote_policies
  | _ :: _, None ->
      Error
        [
          "policies: signed bundles are configured, but this build of haltsql-server \
           cannot load them";
        ]
  | bundles, Some load ->
      List.fold_left
        (fun acc (b : Config.bundle_ref) ->
          match acc with
          | Error _ -> acc
          | Ok ps -> (
              match load b with
              | Error e -> Error [ Printf.sprintf "bundle %s: %s" b.bundle_path e ]
              | Ok loaded ->
                  let prefix = Option.value b.name_prefix ~default:"" in
                  Ok
                    (ps
                    @ List.map
                        (fun (n, (p : Policy.t)) ->
                          (prefix ^ n, { p with Policy.name = prefix ^ p.name }))
                        loaded)))
        (Ok []) bundles
      |> fun r ->
      Result.bind r (fun ps -> check_bundle_duplicates cfg (ps @ remote_policies))

(* Every policy referenced by tokens, default_policy, OIDC and mTLS must be
   loaded: Config can only check this when no bundles are involved. *)
let check_policy_refs (cfg : Config.t) =
  let have n = List.mem_assoc n cfg.policies in
  let refs =
    List.map
      (fun (t : Config.token) -> (Printf.sprintf "token %S" t.token_name, t.token_policy))
      cfg.tokens
    @ (match cfg.default_policy with Some d -> [ ("default_policy", d) ] | None -> [])
    @ List.concat_map
        (fun (o : Config.oidc_provider) ->
          match o.oidc_policy with
          | Config.Oidc_pinned n -> [ (Printf.sprintf "oidc provider %S" o.oidc_name, n) ]
          | Config.Oidc_from_claim { allowed; _ } ->
              List.map
                (fun n -> (Printf.sprintf "oidc provider %S" o.oidc_name, n))
                allowed)
        cfg.oidc
    @ List.map
        (fun (m : Config.mtls_identity) ->
          let who =
            match m.mtls_match with
            | Config.Spiffe_id s -> s
            | Config.Subject_cn c -> "CN=" ^ c
          in
          (Printf.sprintf "mtls identity %S" who, m.mtls_policy))
        cfg.mtls
    @ List.concat_map
        (fun (provider, (g : Config.groups_policy)) ->
          (* Located like Config's own reference errors, so the entry to fix is
             named even when the policy only went missing in a later bundle. *)
          let base =
            match
              List.find_index
                (fun (o : Config.oidc_provider) -> o.oidc_name = provider)
                cfg.oidc
            with
            | Some i -> Printf.sprintf "server.auth.oidc[%d].policy_from_groups" i
            | None -> "policy_from_groups"
          in
          let who loc = Printf.sprintf "oidc provider %S (%s.%s)" provider base loc in
          List.mapi
            (fun j (r : Config.group_rule) ->
              (who (Printf.sprintf "map[%d].policy" j), r.group_policy))
            g.group_rules
          @ match g.group_default with Some d -> [ (who "default", d) ] | None -> [])
        cfg.oidc_group_policies
  in
  match List.filter (fun (_, n) -> not (have n)) refs with
  | [] -> Ok ()
  | missing ->
      Error
        (List.map
           (fun (who, n) ->
             Printf.sprintf "%s references policy %S, which is not loaded" who n)
           missing)

(* Loads the config file (if any), bundles, the policies of the remote bundle
   sources already fetched ([remote]) and the --policy files, then applies flag
   overrides. Fails if anything fails to load. [load_unchecked] skips the
   policy-reference check (used at startup to read [bundle_sources] before
   they are fetched). *)
let rec load ?resolver ?remote (src : sources) : (Config.t, string list) result =
  match load_unchecked ?resolver ?remote src with
  | Error e -> Error e
  | Ok cfg -> ( match check_policy_refs cfg with Ok () -> Ok cfg | Error e -> Error e)

and load_unchecked ?resolver ?remote (src : sources) : (Config.t, string list) result =
  let base =
    match src.config_file with
    | None -> (
        (* No config file: still apply HALTSQL_* environment variables. *)
        let minimal =
          `Assoc [ ("apiVersion", `String "haltsql.dev/v1"); ("kind", `String "Config") ]
        in
        match Config.of_json ~base_dir:(Sys.getcwd ()) minimal with
        | Ok c -> Ok c
        | Error errs ->
            let has_env =
              Array.exists
                (fun kv -> String.length kv > 8 && String.sub kv 0 8 = "HALTSQL_")
                (Unix.environment ())
            in
            if has_env then Error (errors_to_strings errs) else Ok Config.default)
    | Some f -> load_config_file ?resolver f
  in
  match base with
  | Error e -> Error e
  | Ok cfg -> (
      match load_bundles ?remote cfg with
      | Error e -> Error e
      | Ok bundled ->
          let loaded, errs =
            List.fold_left
              (fun (ok, errs) f ->
                match Policy_load.of_file f with
                | Ok p -> ((p.Policy.name, p, abs f) :: ok, errs)
                | Error e -> (ok, errs @ errors_to_strings e))
              ([], []) src.policy_files
          in
          if errs <> [] then Error errs
          else
            let loaded = List.rev loaded in
            let flag_names = List.map (fun (n, _, _) -> n) loaded in
            let base_policies =
              List.filter (fun (n, _) -> not (List.mem_assoc n bundled)) cfg.policies
              @ bundled
            in
            let policies =
              List.filter (fun (n, _) -> not (List.mem n flag_names)) base_policies
              @ List.map (fun (n, p, _) -> (n, p)) loaded
            in
            let cfg =
              {
                cfg with
                policies;
                policy_files =
                  cfg.policy_files
                  @ List.concat_map
                      (fun (b : Config.bundle_ref) ->
                        (* hot reload re-verifies when the bundle or its
                           signature changes *)
                        [ b.bundle_path; b.bundle_path ^ ".sig" ])
                      cfg.policy_bundles
                  @ List.map (fun (_, _, f) -> f) loaded;
              }
            in
            Ok (src.overrides cfg))

let tls_files (cfg : Config.t) =
  match cfg.tls with Some t -> Tls_setup.files t | None -> []

let snapshot_of_config ?config_file ?previous (cfg : Config.t) =
  let group_policies = cfg.oidc_group_policies in
  let oidc =
    match previous with
    | Some (p : snapshot) -> Oidc_client.update ~group_policies p.oidc cfg.oidc
    | None -> Oidc_client.registry ?fetch:!oidc_fetch ~group_policies cfg.oidc
  in
  {
    policies = cfg.policies;
    tokens = cfg.tokens;
    default_policy = cfg.default_policy;
    oidc;
    mtls = cfg.mtls;
    allow_unauthenticated = cfg.allow_unauthenticated;
    watched =
      Option.to_list (Option.map abs config_file) @ cfg.policy_files @ tls_files cfg;
    opa = cfg.opa;
    admin = cfg.admin;
  }

let signature path =
  match Unix.stat path with
  | st -> (st.st_mtime, st.st_size, st.st_ino)
  | exception Unix.Unix_error _ -> (-1., -1, -1)

let signatures files = List.map (fun f -> (f, signature f)) files

let open_sink (s : Config.sink) =
  match s.sink with
  | Config.Sink_stdout -> Audit.open_stdout ~on_error:s.on_error ()
  | Config.Sink_file p -> Audit.open_file ~on_error:s.on_error p
  | (Config.Sink_s3 _ | Config.Sink_gcs _) as k -> (
      let kind = match k with Config.Sink_s3 _ -> "s3" | _ -> "gcs" in
      match !remote_sink with
      | None ->
          failwith
            (Printf.sprintf
               "audit sink type %s is configured, but this build of haltsql-server does \
                not support it"
               kind)
      | Some make -> (
          match make k ~on_error:s.on_error with
          | Ok sink -> sink
          | Error e -> failwith (Printf.sprintf "audit sink %s: %s" kind e)))

let open_stream_sink (s : Config.stream_sink) =
  let kind =
    match s.stream with
    | Config.Stream_elasticsearch _ -> "elasticsearch"
    | Config.Stream_kafka _ -> "kafka"
  in
  match !stream_sink with
  | None ->
      failwith
        (Printf.sprintf
           "audit sink type %s (audit.sinks[%d]) is configured, but this build of \
            haltsql-server does not support it"
           kind s.sink_index)
  | Some make -> (
      match make s with
      | Ok sink -> sink
      | Error e ->
          failwith
            (Printf.sprintf "audit sink %s (audit.sinks[%d]): %s" kind s.sink_index e))

(* Opens every sink (stdout/file/s3/gcs, then elasticsearch/kafka); on failure
   closes the ones already opened. *)
let open_sinks (cfg : Config.t) =
  let opened = ref [] in
  try
    List.iter (fun s -> opened := open_sink s :: !opened) cfg.sinks;
    List.iter (fun s -> opened := open_stream_sink s :: !opened) cfg.stream_sinks;
    List.rev !opened
  with e ->
    List.iter Audit.close !opened;
    raise e

let load_tls (cfg : Config.t) =
  match cfg.tls with
  | None -> Ok None
  | Some t -> Result.map Option.some (Tls_setup.load t)

let create ?(sources = { config_file = None; policy_files = []; overrides = Fun.id })
    (cfg : Config.t) =
  let tls = match load_tls cfg with Ok t -> t | Error e -> failwith e in
  let snap = snapshot_of_config ?config_file:sources.config_file cfg in
  {
    cfg;
    sources;
    snap;
    signatures = signatures snap.watched;
    tls;
    sinks = open_sinks cfg;
    started = Unix.gettimeofday ();
    draining = false;
    report = Admin_report.create cfg.admin;
    remote = [];
    bundle_sources = [];
    generation = 1;
    reload_lock = Lwt_mutex.create ();
    audit_restart_pending = false;
  }

let close t = List.iter Audit.close t.sinks

(* Audit sinks (stdout/file/s3/gcs and elasticsearch/kafka) are opened once at
   startup: two sinks on one file, prefix or topic would fork the hash chain. *)
let audit_sinks_differ (running : Config.t) (cfg : Config.t) =
  running.sinks <> cfg.sinks || running.stream_sinks <> cfg.stream_sinks

(* Reloads every source (policies, auth settings, TLS material). Swaps
   atomically only if everything loaded. TLS cannot be switched on or off
   without a restart. *)
let reload ?(reason = "manual") ?resolver ?remote t =
  let candidate_remote = Option.value remote ~default:t.remote in
  let result =
    match load ?resolver ~remote:candidate_remote t.sources with
    | Error e -> Error e
    | Ok cfg -> (
        match (t.tls, cfg.tls) with
        | Some _, None ->
            Error [ "server.tls was removed; disabling TLS requires a restart" ]
        | None, Some _ ->
            Error [ "server.tls was added; enabling TLS requires a restart" ]
        | None, None -> Ok (cfg, None)
        | Some _, Some _ -> (
            match load_tls cfg with
            | Ok tls ->
                Metrics.observe_tls_reload ~ok:true;
                Ok (cfg, tls)
            | Error e ->
                Metrics.observe_tls_reload ~ok:false;
                Error [ e ]))
  in
  let result =
    Result.bind result (fun (cfg, tls) ->
        match Telemetry.reconfigure cfg.otlp with
        | Ok () -> Ok (cfg, tls)
        | Error e -> Error [ e ])
  in
  match result with
  | Ok (cfg, tls) ->
      t.snap <- snapshot_of_config ?config_file:t.sources.config_file ~previous:t.snap cfg;
      t.remote <- candidate_remote;
      t.generation <- t.generation + 1;
      t.audit_restart_pending <- audit_sinks_differ t.cfg cfg;
      (* Never silently ignore a changed audit.sinks: records keep going to the
         running sinks, and the operator is told the new ones are not in use. *)
      if t.audit_restart_pending then
        Log.warn "audit sink changes need a restart; keeping the current audit sinks"
          ~fields:
            [
              ("reason", `String reason);
              ( "running_audit_sinks",
                `List (List.map (fun (s : Audit.sink) -> `String s.name) t.sinks) );
            ];
      Admin_report.reconfigure t.report cfg.admin;
      (match tls with Some _ -> t.tls <- tls | None -> ());
      t.signatures <- signatures t.snap.watched;
      Metrics.observe_reload ~ok:true;
      Metrics.set_policies_loaded (List.length t.snap.policies);
      Log.info "policies reloaded"
        ~fields:
          [
            ("reason", `String reason);
            ( "policies",
              `List
                (List.map
                   (fun (n, (p : Policy.t)) -> `String (n ^ "@" ^ p.version))
                   t.snap.policies) );
            ("tls_reloaded", `Bool (tls <> None));
            ( "auth",
              `String (if t.snap.allow_unauthenticated then "optional" else "required") );
          ];
      Ok ()
  | Error errs ->
      (* Remember the broken files' signatures so we do not retry every poll. *)
      t.signatures <- signatures t.snap.watched;
      Metrics.observe_reload ~ok:false;
      Log.error "reload failed; keeping the last good configuration"
        ~fields:
          [
            ("reason", `String reason);
            ("errors", `List (List.map (fun e -> `String e) errs));
          ];
      Error errs

(* Reload from inside the Lwt loop (file watcher, SIGHUP, bundle sources):
   secrets from providers are prefetched asynchronously first, with a fresh
   cache, so rotated secrets are picked up.

   Reloads are serialized by [t.reload_lock], held across the prefetch and the
   commit. [update_remote] derives the new [remote] from [t.remote] as it is
   once the lock is held, so two bundle sources updating while a prefetch is
   pending never overwrite each other's policies with older ones. *)
let reload_lwt ?reason ?update_remote t =
  Lwt_mutex.with_lock t.reload_lock (fun () ->
      let run ?resolver () =
        let remote = Option.map (fun f -> f t.remote) update_remote in
        reload ?reason ?resolver ?remote t
      in
      match (t.sources.config_file, !secret_prefetch) with
      | Some f, Some prefetch -> (
          match Config.secrets_of_file f with
          | Error _ -> Lwt.return (run ()) (* reports the located errors *)
          | Ok secrets ->
              Lwt.bind (prefetch ~file:f secrets) (fun resolver ->
                  Lwt.return (run ~resolver ())))
      | _ -> Lwt.return (run ()))

let changed t = List.exists (fun (f, sg) -> signature f <> sg) t.signatures
let snapshot_find_policy (snap : snapshot) name = List.assoc_opt name snap.policies

let snapshot_default_policy (snap : snapshot) =
  match snap.default_policy with
  | Some n -> Some n
  | None -> ( match snap.policies with [ (n, _) ] -> Some n | _ -> None)

let find_policy t name = snapshot_find_policy t.snap name
let default_policy t = snapshot_default_policy t.snap
