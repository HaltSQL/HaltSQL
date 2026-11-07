(* Server state: static settings, the hot-reloadable policy/token snapshot,
   audit sinks, and the reload logic. *)

open Haltsql

type snapshot = {
  policies : (string * Policy.t) list;
  tokens : Config.token list;
  default_policy : string option;
  watched : string list;  (** files whose changes trigger a reload *)
}

type sources = {
  config_file : string option;
  policy_files : string list;  (** from --policy flags *)
  overrides : Config.t -> Config.t;  (** command-line flags, applied last *)
}

type t = {
  cfg : Config.t;  (** effective settings at startup (listen, auth mode, audit, ...) *)
  sources : sources;
  mutable snap : snapshot;
  mutable signatures : (string * (float * int * int)) list;
  sinks : Audit.sink list;
  started : float;
}

let errors_to_strings errs = List.map Load_error.to_string errs

let abs path =
  if Filename.is_relative path then Filename.concat (Sys.getcwd ()) path else path

(* Loads the config file (if any) and the --policy files, then applies flag
   overrides. Fails if anything fails to load. *)
let load (src : sources) : (Config.t, string list) result =
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
    | Some f -> Config.of_file f |> Result.map_error errors_to_strings
  in
  match base with
  | Error e -> Error e
  | Ok cfg ->
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
        let policies =
          List.filter
            (fun (n, _) -> not (List.exists (fun (m, _, _) -> m = n) loaded))
            cfg.policies
          @ List.map (fun (n, p, _) -> (n, p)) loaded
        in
        let cfg =
          {
            cfg with
            policies;
            policy_files = cfg.policy_files @ List.map (fun (_, _, f) -> f) loaded;
          }
        in
        Ok (src.overrides cfg)

let snapshot_of_config ?config_file (cfg : Config.t) =
  {
    policies = cfg.policies;
    tokens = cfg.tokens;
    default_policy = cfg.default_policy;
    watched = Option.to_list (Option.map abs config_file) @ cfg.policy_files;
  }

let signature path =
  match Unix.stat path with
  | st -> (st.st_mtime, st.st_size, st.st_ino)
  | exception Unix.Unix_error _ -> (-1., -1, -1)

let signatures files = List.map (fun f -> (f, signature f)) files

let open_sinks (cfg : Config.t) =
  List.map
    (function
      | Config.Audit_stdout -> Audit.open_stdout ()
      | Config.Audit_file p -> Audit.open_file p)
    cfg.audit_sinks

let create ?(sources = { config_file = None; policy_files = []; overrides = Fun.id })
    (cfg : Config.t) =
  let snap = snapshot_of_config ?config_file:sources.config_file cfg in
  {
    cfg;
    sources;
    snap;
    signatures = signatures snap.watched;
    sinks = open_sinks cfg;
    started = Unix.gettimeofday ();
  }

let close t = List.iter Audit.close t.sinks

(* Reloads every source. Swaps atomically only if everything loaded. *)
let reload ?(reason = "manual") t =
  match load t.sources with
  | Ok cfg ->
      t.snap <- snapshot_of_config ?config_file:t.sources.config_file cfg;
      t.signatures <- signatures t.snap.watched;
      Metrics.observe_reload ~ok:true;
      Log.info "policies reloaded"
        ~fields:
          [
            ("reason", `String reason);
            ( "policies",
              `List
                (List.map
                   (fun (n, (p : Policy.t)) -> `String (n ^ "@" ^ p.version))
                   t.snap.policies) );
          ];
      Ok ()
  | Error errs ->
      (* Remember the broken files' signatures so we do not retry every poll. *)
      t.signatures <- signatures t.snap.watched;
      Metrics.observe_reload ~ok:false;
      Log.error "policy reload failed; keeping the last good policies"
        ~fields:
          [
            ("reason", `String reason);
            ("errors", `List (List.map (fun e -> `String e) errs));
          ];
      Error errs

let changed t = List.exists (fun (f, sg) -> signature f <> sg) t.signatures
let find_policy t name = List.assoc_opt name t.snap.policies

let default_policy t =
  match t.snap.default_policy with
  | Some n -> Some n
  | None -> ( match t.snap.policies with [ (n, _) ] -> Some n | _ -> None)
