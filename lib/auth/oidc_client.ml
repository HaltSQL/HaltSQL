(* OIDC providers at runtime: discovery, JWKS cache, verification. *)

open Lwt.Syntax
module Config = Haltsql.Config

type fetch = Uri.t -> (string, string) result Lwt.t

let forced_refresh_interval = 30.
let failed_retry_interval = 5.

let logger : ([ `Info | `Warn ] -> string -> (string * string) list -> unit) ref =
  ref (fun _ _ _ -> ())

let set_logger f = logger := f
let log lvl msg fields = try !logger lvl msg fields with _ -> ()

exception Body_too_large

let http_fetch ?(timeout = 5.0) ?(max_bytes = 1_048_576) () : fetch =
 fun uri ->
  let body_ref = ref None in
  let drain () =
    match !body_ref with
    | None -> Lwt.return_unit
    | Some b ->
        body_ref := None;
        Lwt.catch (fun () -> Cohttp_lwt.Body.drain_body b) (fun _ -> Lwt.return_unit)
  in
  let get () =
    let* resp, body = Cohttp_lwt_unix.Client.get uri in
    body_ref := Some body;
    let status = Cohttp.Code.code_of_status (Cohttp.Response.status resp) in
    if status <> 200 then
      let* () = drain () in
      Lwt.return_error (Printf.sprintf "HTTP %d" status)
    else
      let buf = Buffer.create 4096 in
      Lwt.catch
        (fun () ->
          let* () =
            Lwt_stream.iter
              (fun chunk ->
                if Buffer.length buf + String.length chunk > max_bytes then
                  raise Body_too_large;
                Buffer.add_string buf chunk)
              (Cohttp_lwt.Body.to_stream body)
          in
          body_ref := None;
          Lwt.return_ok (Buffer.contents buf))
        (function
          | Body_too_large ->
              Lwt.async drain;
              Lwt.return_error (Printf.sprintf "response exceeds %d bytes" max_bytes)
          | e ->
              Lwt.async drain;
              Lwt.reraise e)
  in
  Lwt.catch
    (fun () ->
      Lwt.pick
        [
          get ();
          (let* () = Lwt_unix.sleep timeout in
           Lwt.async drain;
           Lwt.return_error (Printf.sprintf "timed out after %.0fs" timeout));
        ])
    (fun e ->
      Lwt.async drain;
      Lwt.return_error ("request failed: " ^ Printexc.to_string e))

(* ---- one provider ---- *)

type provider = {
  cfg : Config.oidc_provider;
  fetch : fetch;
  now : unit -> float;
  mutable keys : Jwk.t list;
  mutable fetched_at : float option;  (** last successful JWKS fetch *)
  mutable last_failure : float option;  (** last failed refresh attempt *)
  mutable last_forced : float;  (** last unknown-kid forced refresh *)
  mutable discovered : string option;  (** jwks_uri from discovery *)
  mutable inflight : (int, string) result Lwt.t option;
  mutable groups : Config.groups_policy option;  (** [policy_from_groups] *)
}

let provider ?fetch ?(now = Unix.gettimeofday) ?groups (cfg : Config.oidc_provider) =
  let fetch = match fetch with Some f -> f | None -> http_fetch () in
  {
    cfg;
    fetch;
    now;
    keys = [];
    fetched_at = None;
    last_failure = None;
    last_forced = neg_infinity;
    discovered = None;
    inflight = None;
    groups;
  }

let config p = p.cfg
let groups p = p.groups

let issuer_is_loopback p =
  match Uri.host (Uri.of_string p.cfg.issuer) with
  | Some h -> Haltsql_core.Loopback.is_host h
  | None -> false

let check_url p what s =
  let u = Uri.of_string s in
  match (Uri.scheme u, Uri.host u, Uri.userinfo u) with
  | _, _, Some _ -> Error (what ^ " must not contain credentials")
  | _, (None | Some ""), _ -> Error (what ^ " has no host")
  | (Some "https" | Some "http"), Some h, None
    when what <> "issuer" && Haltsql_core.Loopback.is_host h && not (issuer_is_loopback p)
    ->
      Error (what ^ " must not point to a loopback host when issuer is not on loopback")
  | Some "https", _, _ -> Ok u
  | Some "http", _, _ when p.cfg.allow_insecure_http -> Ok u
  | _ -> Error (what ^ " must be an https URL")

let ( let*? ) r f = match r with Ok v -> f v | Error e -> Lwt.return_error e

let discovery_url issuer =
  let i =
    if String.length issuer > 0 && issuer.[String.length issuer - 1] = '/' then
      String.sub issuer 0 (String.length issuer - 1)
    else issuer
  in
  i ^ "/.well-known/openid-configuration"

let jwks_uri p =
  match (p.cfg.jwks_uri, p.discovered) with
  | Some u, _ | None, Some u -> Lwt.return (check_url p "jwks_uri" u)
  | None, None -> (
      let*? url = check_url p "issuer" (discovery_url p.cfg.issuer) in
      let* body = p.fetch url in
      match body with
      | Error e -> Lwt.return_error ("discovery: " ^ e)
      | Ok body -> (
          match Yojson.Safe.from_string body with
          | exception Yojson.Json_error _ ->
              Lwt.return_error "discovery: document is not valid JSON"
          | `Assoc kv -> (
              match (List.assoc_opt "issuer" kv, List.assoc_opt "jwks_uri" kv) with
              | Some (`String i), _ when i <> p.cfg.issuer ->
                  Lwt.return_error
                    "discovery: document issuer does not equal the configured issuer"
              | Some (`String _), Some (`String j) ->
                  let*? u = check_url p "discovered jwks_uri" j in
                  p.discovered <- Some j;
                  Lwt.return_ok u
              | _ -> Lwt.return_error "discovery: document lacks issuer or jwks_uri")
          | _ -> Lwt.return_error "discovery: document is not a JSON object"))

let do_refresh p =
  let* r =
    let* u = jwks_uri p in
    match u with
    | Error e -> Lwt.return_error e
    | Ok u -> (
        let* body = p.fetch u in
        match body with
        | Error e -> Lwt.return_error ("jwks: " ^ e)
        | Ok body -> (
            match Jwk.set_of_string body with
            | Error e -> Lwt.return_error ("jwks: " ^ e)
            | Ok (keys, skipped) ->
                if skipped <> [] then
                  log `Warn "oidc: skipped unusable JWKS entries"
                    [
                      ("provider", p.cfg.oidc_name);
                      ("problems", String.concat "; " skipped);
                    ];
                Lwt.return_ok keys))
  in
  match r with
  | Ok keys ->
      p.keys <- keys;
      p.fetched_at <- Some (p.now ());
      p.last_failure <- None;
      log `Info "oidc: signing keys refreshed"
        [ ("provider", p.cfg.oidc_name); ("keys", string_of_int (List.length keys)) ];
      Lwt.return_ok (List.length keys)
  | Error e ->
      p.last_failure <- Some (p.now ());
      (* A failed discovery may be stale: rediscover next time. *)
      if p.cfg.jwks_uri = None then p.discovered <- None;
      log `Warn "oidc: signing key refresh failed"
        [ ("provider", p.cfg.oidc_name); ("error", e) ];
      Lwt.return_error e

let refresh p =
  match p.inflight with
  | Some pending -> pending
  | None ->
      let pending =
        Lwt.finalize
          (fun () -> do_refresh p)
          (fun () ->
            p.inflight <- None;
            Lwt.return_unit)
      in
      (* do_refresh may complete synchronously, in which case finalize already ran. *)
      if Lwt.is_sleeping pending then p.inflight <- Some pending;
      pending

let stale_bound p = float_of_int (min p.cfg.jwks_cache_seconds 3600)

(* Current usable keys, refreshing when expired. *)
let current_keys p ~force =
  let now = p.now () in
  let ttl = float_of_int p.cfg.jwks_cache_seconds in
  let fresh = match p.fetched_at with Some t -> now -. t < ttl | None -> false in
  let usable_stale =
    match p.fetched_at with Some t -> now -. t < ttl +. stale_bound p | None -> false
  in
  let recently_failed =
    match p.last_failure with Some t -> now -. t < failed_retry_interval | None -> false
  in
  if fresh && not force then Lwt.return_ok p.keys
  else if recently_failed && not force then
    if usable_stale then Lwt.return_ok p.keys
    else Lwt.return_error "the last key refresh failed"
  else
    let* r = refresh p in
    match r with
    | Ok _ -> Lwt.return_ok p.keys
    | Error e -> if usable_stale then Lwt.return_ok p.keys else Lwt.return_error e

let verify p tok =
  let* keys = current_keys p ~force:false in
  match keys with
  | Error e -> Lwt.return_error (Jwt.Keys_unavailable e)
  | Ok keys -> (
      match Oidc.verify ?groups:p.groups p.cfg ~keys ~now:(p.now ()) tok with
      | Error (Jwt.Unknown_kid _) as first ->
          let now = p.now () in
          if now -. p.last_forced < forced_refresh_interval then Lwt.return first
          else begin
            p.last_forced <- now;
            let* keys = current_keys p ~force:true in
            match keys with
            | Error _ -> Lwt.return first
            | Ok keys ->
                Lwt.return (Oidc.verify ?groups:p.groups p.cfg ~keys ~now:(p.now ()) tok)
          end
      | r -> Lwt.return r)

(* ---- registry ---- *)

type registry = {
  fetch : fetch option;
  now : (unit -> float) option;
  providers : provider list;
}

let groups_for group_policies (c : Config.oidc_provider) =
  List.assoc_opt c.oidc_name group_policies

let registry ?fetch ?now ?(group_policies = []) cfgs =
  {
    fetch;
    now;
    providers =
      List.map
        (fun c -> provider ?fetch ?now ?groups:(groups_for group_policies c) c)
        cfgs;
  }

let update ?(group_policies = []) r cfgs =
  {
    r with
    providers =
      List.map
        (fun c ->
          let groups = groups_for group_policies c in
          match List.find_opt (fun p -> p.cfg = c) r.providers with
          | Some p ->
              p.groups <- groups;
              p
          | None -> provider ?fetch:r.fetch ?now:r.now ?groups c)
        cfgs;
  }

let providers r = r.providers
let is_empty r = r.providers = []

let authenticate r tok =
  if r.providers = [] || not (Jwt.looks_like_jwt tok) then Lwt.return `Not_applicable
  else
    match Jwt.unverified_issuer tok with
    | None -> Lwt.return `Not_applicable
    | Some iss -> (
        match List.filter (fun p -> p.cfg.issuer = iss) r.providers with
        | [] -> Lwt.return `Not_applicable
        | candidates ->
            let rec go first = function
              | [] -> (
                  match first with
                  | Some e -> Lwt.return (`Rejected e)
                  | None -> Lwt.return (`Rejected Jwt.Wrong_issuer))
              | p :: rest -> (
                  let* v = verify p tok in
                  match v with
                  | Ok id -> Lwt.return (`Verified id)
                  | Error e -> go (if first = None then Some e else first) rest)
            in
            go None candidates)
