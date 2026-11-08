open Lwt.Infix
module Oci_ref = Oci_ref
module Www_auth = Www_auth
module Fetch_error = Fetch_error
module Content_digest = Content_digest
module Registry = Registry
module Oci_artifact = Oci_artifact
module Remote = Remote
module Cache = Cache
module B = Haltsql_bundle
module Config = Haltsql_load.Config
module Policy = Haltsql_core.Policy

type origin = From_cache | From_source

type update = {
  source : string;
  bundle : B.t;
  policies : (string * Policy.t) list;
  signed_by : string;
  revision : string option;
  origin : origin;
}

type error =
  | Fetch_failed of Fetch_error.t
  | Verification_failed of B.error
  | Rollback_refused of string
  | Rejected of string
  | Cache_failed of string

let error_code = function
  | Fetch_failed (Fetch_error.Unavailable _) -> "bundle_source_unavailable"
  | Fetch_failed (Fetch_error.Denied _) -> "bundle_source_denied"
  | Fetch_failed (Fetch_error.Not_found _) -> "bundle_source_not_found"
  | Fetch_failed (Fetch_error.Integrity _) -> "bundle_source_integrity"
  | Fetch_failed (Fetch_error.Protocol _) -> "bundle_source_protocol"
  | Verification_failed (B.Signature_invalid _ | B.Invalid_key _) ->
      "bundle_source_signature"
  | Verification_failed
      ( B.Io _ | B.Too_large _ | B.Malformed _ | B.Digest_mismatch _ | B.Invalid_policy _
      | B.Invalid_catalog _ ) ->
      "bundle_source_invalid"
  | Rollback_refused _ -> "bundle_source_rollback"
  | Rejected _ -> "bundle_source_rejected"
  | Cache_failed _ -> "bundle_source_cache"

let error_to_string = function
  | Fetch_failed e -> Fetch_error.to_string e
  | Verification_failed e -> "bundle verification failed: " ^ B.error_to_string e
  | Rollback_refused m -> "rollback refused: " ^ m
  | Rejected m -> "bundle rejected: " ^ m
  | Cache_failed m -> "bundle cache: " ^ m

(* ---------------------------------------------------------------- versions *)

type vtok = Num of string | Str of string

let tokenize v =
  let n = String.length v in
  let is_d c = c >= '0' && c <= '9' in
  let rec go i acc =
    if i >= n then List.rev acc
    else
      let d = is_d v.[i] in
      let j = ref i in
      while !j < n && is_d v.[!j] = d do
        incr j
      done;
      let s = String.sub v i (!j - i) in
      go !j ((if d then Num s else Str s) :: acc)
  in
  go 0 []

let strip_zeros s =
  let n = String.length s in
  let i = ref 0 in
  while !i < n - 1 && s.[!i] = '0' do
    incr i
  done;
  String.sub s !i (n - !i)

let compare_num a b =
  let a = strip_zeros a and b = strip_zeros b in
  match compare (String.length a) (String.length b) with
  | 0 -> String.compare a b
  | c -> c

let compare_versions a b =
  let pre = function
    | Str s :: _ -> String.length s > 0 && (s.[0] = '-' || s.[0] = '~')
    | _ -> false
  in
  let rec go xs ys =
    match (xs, ys) with
    | [], [] -> 0
    | [], rest -> if pre rest then 1 else -1
    | rest, [] -> if pre rest then -1 else 1
    | Num x :: xs, Num y :: ys -> ( match compare_num x y with 0 -> go xs ys | c -> c)
    | Str x :: xs, Str y :: ys -> (
        match String.compare x y with 0 -> go xs ys | c -> c)
    | Num _ :: _, Str _ :: _ -> -1
    | Str _ :: _, Num _ :: _ -> 1
  in
  go (tokenize a) (tokenize b)

let check_rollback ~allow_downgrade ~(current : B.metadata option) (offered : B.metadata)
    =
  match current with
  | None -> Ok ()
  | Some _ when allow_downgrade -> Ok ()
  | Some cur ->
      if cur.name <> offered.name then
        Error
          (Printf.sprintf "the source now serves bundle %S, the current bundle is %S"
             offered.name cur.name)
      else
        let c = compare_versions offered.version cur.version in
        if c < 0 then
          Error
            (Printf.sprintf "bundle %s version %s is older than the current version %s"
               offered.name offered.version cur.version)
        else if c = 0 then
          Error
            (Printf.sprintf
               "bundle %s version %s has different content than the current bundle with \
                the same version"
               offered.name offered.version)
        else Ok ()

(* ----------------------------------------------------------------- sources *)

type backend =
  | Oci of { registry : Registry.t; pinned : string option }
  | S3 of { src : Config.s3_source; credentials : Haltsql_cloud.Aws_creds.t }
  | Https of { url : string; authorization : string option }

type current = {
  upd : update;
  bundle_sha : string;
  bundle_bytes : string;
  signature_bytes : string;
}

type status = { checks : int; last_success : float option; last_error : error option }
type outcome = Unchanged | Updated of update
type on_update = update -> (unit, string) result Lwt.t

type t = {
  id : string;
  cfg : Config.bundle_source;
  keys : B.Key.public list;
  backend : backend;
  ctx : Haltsql_cloud.Http.ctx option;
  timeout : float;
  allow_downgrade : bool;
  jitter : float;
  interval : float;
  now : unit -> float;
  cache_dir : string option;
  lock : Lwt_mutex.t;
  rng : Random.State.t;
  mutable cur : current option;
  mutable checks : int;
  mutable last_success : float option;
  mutable last_error : error option;
  mutable stopped : bool;
  stop_p : unit Lwt.t;
  stop_w : unit Lwt.u;
}

let source_id_of (c : Config.bundle_source) =
  match c.location with
  | Config.Source_oci o -> "oci:" ^ o.oci_reference
  | Config.Source_s3 s ->
      Printf.sprintf "s3://%s/%s%s" s.src_bucket s.src_key
        (match s.src_endpoint with Some e -> "@" ^ e | None -> "")
  | Config.Source_https u -> u

let ( let* ) = Result.bind

let decode_keys keys =
  if keys = [] then
    Error "bundle source: public_keys must not be empty (signatures are mandatory)"
  else
    List.fold_left
      (fun acc k ->
        let* acc = acc in
        match B.Key.of_config k with
        | Ok k -> Ok (k :: acc)
        | Error m -> Error ("bundle source: invalid public key: " ^ m))
      (Ok []) keys
    |> Result.map List.rev

let create ?(allow_downgrade = false) ?ca_file ?(timeout = 30.) ?(jitter = 0.1)
    ?poll_interval ?env ?(now = Unix.gettimeofday) ?aws_credentials
    (cfg : Config.bundle_source) =
  Http_fetch.ensure_rng ();
  let ctx_p =
    match ca_file with
    | None -> Lwt.return (Ok None)
    | Some f -> Haltsql_cloud.Http.ctx_of_ca_file f >|= Result.map Option.some
  in
  ctx_p >|= fun ctx ->
  let* ctx = ctx in
  let* keys = decode_keys cfg.source_public_keys in
  let* backend =
    match cfg.location with
    | Config.Source_oci o ->
        let* r = Oci_ref.of_config o in
        let credentials =
          match cfg.source_auth with
          | None -> Registry.Anonymous
          | Some (Config.Source_basic { username; password }) ->
              Registry.Basic { username; password }
          | Some (Config.Source_token tok) -> Registry.Bearer tok
        in
        let* registry =
          Registry.create ?ctx ~timeout ~plain_http:o.oci_plain_http ~now ~credentials r
        in
        Ok (Oci { registry; pinned = r.digest })
    | Config.Source_s3 src ->
        if cfg.source_auth <> None then
          Error "bundle source: auth is not used by s3 sources"
        else
          let credentials =
            match aws_credentials with
            | Some c -> c
            | None ->
                Haltsql_cloud.Aws_creds.create ?env ~region:src.src_region
                  (Haltsql_cloud.Aws_creds.source_of_s3 src.src_credentials)
          in
          Ok (S3 { src; credentials })
    | Config.Source_https url ->
        let* () =
          Http_fetch.check_url ~what:"bundle source" (Uri.of_string url)
          |> Result.map_error (fun e -> "bundle source: " ^ e)
        in
        let authorization =
          match cfg.source_auth with
          | None -> None
          | Some (Config.Source_basic { username; password }) ->
              Some (Http_fetch.basic ~username ~password)
          | Some (Config.Source_token tok) -> Some ("Bearer " ^ tok)
        in
        Ok (Https { url; authorization })
  in
  let* () =
    if jitter < 0. || jitter >= 1. then Error "bundle source: jitter must be in [0, 1)"
    else Ok ()
  in
  let interval =
    match poll_interval with
    | Some p -> Float.max 0.01 p
    | None -> float_of_int cfg.poll_interval_s
  in
  let stop_p, stop_w = Lwt.wait () in
  Ok
    {
      id = source_id_of cfg;
      cfg;
      keys;
      backend;
      ctx;
      timeout;
      allow_downgrade;
      jitter;
      interval;
      now;
      cache_dir = cfg.cache_dir;
      lock = Lwt_mutex.create ();
      rng = Random.State.make_self_init ();
      cur = None;
      checks = 0;
      last_success = None;
      last_error = None;
      stopped = false;
      stop_p;
      stop_w;
    }

let source_id t = t.id
let current t = Option.map (fun c -> c.upd) t.cur

let status t =
  { checks = t.checks; last_success = t.last_success; last_error = t.last_error }

let verify_raw t ~bundle ~signature =
  if String.length bundle > B.default_max_bytes then
    Error
      (B.Too_large
         { what = "bundle"; size = String.length bundle; limit = B.default_max_bytes })
  else if String.length signature > B.max_signature_bytes then
    Error
      (B.Too_large
         {
           what = "signature file";
           size = String.length signature;
           limit = B.max_signature_bytes;
         })
  else
    let* sigs = B.signatures_of_string signature in
    let* key = B.verify_signatures t.keys bundle sigs in
    (* only now is anything in the bundle parsed *)
    let* parsed = B.parse_unverified ?name_prefix:t.cfg.source_name_prefix bundle in
    Ok (parsed, key)

let verify t ~bundle ~signature =
  match verify_raw t ~bundle ~signature with
  | Error e -> Error (Verification_failed e)
  | Ok (b, key) ->
      Ok
        {
          source = t.id;
          bundle = b;
          policies = List.map (fun (p : Policy.t) -> (p.name, p)) b.policies;
          signed_by = B.Key.keyid key;
          revision = None;
          origin = From_source;
        }

let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let call_on_update (on_update : on_update) u =
  Lwt.catch
    (fun () -> on_update u)
    (fun e -> Lwt.return (Error ("on_update raised " ^ Printexc.to_string e)))

let store_cache t c =
  match t.cache_dir with
  | None -> Ok ()
  | Some cache_dir ->
      Cache.store
        ~dir:(Cache.dir_for ~cache_dir ~source:t.id)
        {
          source = t.id;
          bundle = c.bundle_bytes;
          signature = c.signature_bytes;
          revision = c.upd.revision;
        }
      |> Result.map_error (fun m -> Cache_failed m)

let load_cache t ~on_update =
  Lwt_mutex.with_lock t.lock (fun () ->
      match (t.cache_dir, t.cur) with
      | None, _ | _, Some _ -> Lwt.return (Ok Unchanged)
      | Some cache_dir, None -> (
          match Cache.load ~dir:(Cache.dir_for ~cache_dir ~source:t.id) ~source:t.id with
          | Error m -> Lwt.return (Error (Cache_failed m))
          | Ok None -> Lwt.return (Ok Unchanged)
          | Ok (Some e) -> (
              match verify t ~bundle:e.bundle ~signature:e.signature with
              | Error err -> Lwt.return (Error err)
              | Ok u -> (
                  let u = { u with revision = e.revision; origin = From_cache } in
                  call_on_update on_update u >|= function
                  | Error m -> Error (Rejected m)
                  | Ok () ->
                      t.cur <-
                        Some
                          {
                            upd = u;
                            bundle_sha = sha256_hex e.bundle;
                            bundle_bytes = e.bundle;
                            signature_bytes = e.signature;
                          };
                      Ok (Updated u)))))

type fetched =
  | Not_modified
  | Got of { bundle : string; signature : string; revision : string option }

let fetch t =
  let prev = Option.bind t.cur (fun c -> c.upd.revision) in
  match t.backend with
  | Oci { registry; pinned } -> (
      match (pinned, prev) with
      | Some d, Some p when d = p -> Lwt.return (Ok Not_modified)
      | _ -> (
          let reference = Oci_ref.reference (Registry.reference registry) in
          (match prev with
            | None -> Lwt.return (Ok None)
            | Some _ -> Registry.head_manifest registry reference)
          >>= function
          | Error e -> Lwt.return (Error e)
          | Ok (Some d) when Some d = prev -> Lwt.return (Ok Not_modified)
          | Ok _ -> (
              Oci_artifact.pull ~reference registry >|= function
              | Error e -> Error e
              | Ok p when Some p.manifest_digest = prev -> Ok Not_modified
              | Ok p ->
                  Ok
                    (Got
                       {
                         bundle = p.bundle;
                         signature = p.signature;
                         revision = Some p.manifest_digest;
                       }))))
  | S3 { src; credentials } -> (
      Remote.s3 ?ctx:t.ctx ~timeout:t.timeout ~now:t.now ~credentials ~etag:prev src
      >|= function
      | Error e -> Error e
      | Ok Remote.Not_modified -> Ok Not_modified
      | Ok (Remote.Fetched f) ->
          Ok (Got { bundle = f.bundle; signature = f.signature; revision = f.etag }))
  | Https { url; authorization } -> (
      Remote.https ?ctx:t.ctx ~timeout:t.timeout ?authorization ~etag:prev url
      >|= function
      | Error e -> Error e
      | Ok Remote.Not_modified -> Ok Not_modified
      | Ok (Remote.Fetched f) ->
          Ok (Got { bundle = f.bundle; signature = f.signature; revision = f.etag }))

let finish t r =
  t.checks <- t.checks + 1;
  (match r with
  | Ok _ ->
      t.last_success <- Some (t.now ());
      t.last_error <- None
  | Error (Fetch_failed _ as e) -> t.last_error <- Some e
  | Error e ->
      (* the source was reached; what it served was refused *)
      t.last_success <- Some (t.now ());
      t.last_error <- Some e);
  r

let poll_once t ~on_update ?(on_warning = fun _ -> ()) () =
  Lwt_mutex.with_lock t.lock (fun () ->
      fetch t >>= function
      | Error e -> Lwt.return (finish t (Error (Fetch_failed e)))
      | Ok Not_modified -> Lwt.return (finish t (Ok Unchanged))
      | Ok (Got { bundle; signature; revision }) -> (
          let sha = sha256_hex bundle in
          match t.cur with
          | Some c when c.bundle_sha = sha ->
              (* same bundle under a new manifest / ETag: remember the new revision *)
              let c = { c with upd = { c.upd with revision } } in
              t.cur <- Some c;
              (match store_cache t c with Ok () -> () | Error e -> on_warning e);
              Lwt.return (finish t (Ok Unchanged))
          | cur -> (
              match verify t ~bundle ~signature with
              | Error e -> Lwt.return (finish t (Error e))
              | Ok u -> (
                  let u = { u with revision } in
                  match
                    check_rollback ~allow_downgrade:t.allow_downgrade
                      ~current:(Option.map (fun c -> c.upd.bundle.metadata) cur)
                      u.bundle.metadata
                  with
                  | Error m -> Lwt.return (finish t (Error (Rollback_refused m)))
                  | Ok () -> (
                      call_on_update on_update u >|= function
                      | Error m -> finish t (Error (Rejected m))
                      | Ok () ->
                          let c =
                            {
                              upd = u;
                              bundle_sha = sha;
                              bundle_bytes = bundle;
                              signature_bytes = signature;
                            }
                          in
                          t.cur <- Some c;
                          (match store_cache t c with
                          | Ok () -> ()
                          | Error e -> on_warning e);
                          finish t (Ok (Updated u)))))))

let next_delay t =
  let j =
    if t.jitter = 0. then 0. else Random.State.float t.rng (2. *. t.jitter) -. t.jitter
  in
  t.interval *. (1. +. j)

let start t ~on_update ~on_error =
  let report r = match r with Error e -> on_error e | Ok _ -> () in
  let safe_report e = try on_error e with _ -> () in
  (load_cache t ~on_update >|= function Error e -> safe_report e | Ok _ -> ())
  >>= fun () ->
  poll_once t ~on_update ~on_warning:safe_report () >>= fun first ->
  (try report first with _ -> ());
  let rec loop () =
    if t.stopped then Lwt.return_unit
    else
      Lwt.pick
        [
          (Lwt_unix.sleep (next_delay t) >|= fun () -> `Tick);
          (t.stop_p >|= fun () -> `Stop);
        ]
      >>= function
      | `Stop -> Lwt.return_unit
      | `Tick ->
          if t.stopped then Lwt.return_unit
          else
            Lwt.catch
              (fun () ->
                poll_once t ~on_update ~on_warning:safe_report () >|= function
                | Error e -> safe_report e
                | Ok _ -> ())
              (fun ex ->
                Lwt.return
                  (safe_report
                     (Fetch_failed (Fetch_error.Protocol (Printexc.to_string ex)))))
            >>= loop
  in
  if not t.stopped then Lwt.async loop;
  Lwt.return
    (match (t.cur, first) with
    | Some _, _ -> Ok ()
    | None, Error e -> Error e
    | None, Ok _ -> Error (Fetch_failed (Fetch_error.Protocol "no bundle was obtained")))

let stop t =
  if not t.stopped then begin
    t.stopped <- true;
    Lwt.wakeup_later t.stop_w ()
  end
