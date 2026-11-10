(* GET /api/v1/me, GET /api/v1/access/roles, GET /api/v1/integrations. *)

open Lwt.Syntax
module C = Console_config

let environment_json (c : C.t) =
  `Assoc
    [
      ("org", `String c.environment.org);
      ("name", `String c.environment.env_name);
      ("region", Api.opt_string c.environment.region);
    ]

let me (ctx : Ctx.t) (p : Ctx.principal) _r =
  Api.json
    (`Assoc
       [
         ( "user",
           `Assoc
             [
               ("id", `String p.id);
               ("name", `String p.name);
               ("auth", `String p.auth);
               ("groups", Api.strings p.groups);
             ] );
         ("roles", `List (List.map (fun r -> `String (Rbac.role_to_string r)) p.roles));
         ("role", `String (Rbac.role_to_string p.role));
         ("role_label", `String (Rbac.role_label p.role));
         ("permissions", Rbac.permissions_json_union p.roles);
         ("environment", environment_json ctx.config);
       ])

(* The sessions safeguard holds for every sign-in only when OIDC is the sole method and
   every token must carry auth_time. *)
let sessions_verified (a : C.auth) =
  a.oidc <> [] && a.proxy = None && a.tokens = [] && a.dev = None && a.require_auth_time

(* Roles, the matrix and the safeguards are visible to everyone; the group-to-role
   [mapping] only to callers with [manage_access] (the field is omitted otherwise). *)
let roles (ctx : Ctx.t) (p : Ctx.principal) _r =
  let a = ctx.config.auth in
  let mapping =
    if Rbac.grant_union p.roles Rbac.Manage_access = Rbac.Yes then
      [
        ( "mapping",
          `Assoc
            (List.map (fun (r, gs) -> (Rbac.role_to_string r, Api.strings gs)) a.roles) );
      ]
    else []
  in
  Api.json
    (`Assoc
       ([
          ( "roles",
            `List
              (List.map
                 (fun r ->
                   `Assoc
                     [
                       ("id", `String (Rbac.role_to_string r));
                       ("label", `String (Rbac.role_label r));
                     ])
                 Rbac.all_roles) );
          ("permissions", Rbac.matrix_json ());
        ]
       @ mapping
       @ [
           ( "safeguards",
             `List
               [
                 `Assoc
                   [
                     ("id", `String "two_person_rule");
                     ("title", `String "Two-person rule");
                     ( "detail",
                       `String
                         "Policy changes need two owners, never the requester. Expected \
                          to be enforced by branch protection on the policy repository; \
                          not verified by the console." );
                     ("verified", `Bool false);
                   ];
                 `Assoc
                   [
                     ("id", `String "sessions");
                     ("title", `String "Sessions");
                     ( "detail",
                       `String
                         (Printf.sprintf
                            "OIDC sign-ins older than %d hours are rejected (by \
                             auth_time, else iat)%s; proxy and service-token sessions \
                             are not limited by the console."
                            a.session_hours
                            (if a.require_auth_time then
                               "; tokens without auth_time are rejected"
                             else
                               "; tokens with neither claim are accepted until they \
                                expire")) );
                     ("verified", `Bool (sessions_verified a));
                   ];
               ] );
           ("dev_mode", `Bool (a.dev <> None));
         ]))

let item ?error ~id ~name ~detail state =
  `Assoc
    [
      ("id", `String id);
      ("name", `String name);
      ("detail", `String detail);
      ("state", `String state);
      ("error", Api.opt_string error);
    ]

let integrations_member name (c : C.t) = Api.member name c.integrations

(* ---- live checks ---- *)

(** How JWKS reachability is fetched; tests replace it. *)
let jwks_fetch : Haltsql_auth.Oidc_client.fetch option ref = ref None

let jwks_cache_seconds = 300.

(* provider -> (checked at, result), per console. Cached so the page never hammers the
   identity provider. *)
type jwks_state = {
  results : (string, float * (int, string) result) Hashtbl.t;
  pending : (string, (int, string) result Lwt.t) Hashtbl.t;
      (** checks in flight: concurrent callers share one fetch per provider *)
}

let jwks_key : jwks_state Ctx.Key.t = Ctx.Key.create "access.jwks"

let jwks_state ctx =
  match Ctx.get ctx jwks_key with
  | Some h -> h
  | None ->
      let h = { results = Hashtbl.create 4; pending = Hashtbl.create 4 } in
      Ctx.set ctx jwks_key h;
      h

let jwks_check (ctx : Ctx.t) (o : C.oidc) =
  let st = jwks_state ctx in
  let key = o.provider.oidc_name in
  let now = Ctx.now () in
  match Hashtbl.find_opt st.results key with
  | Some (at, r) when now -. at < jwks_cache_seconds -> Lwt.return r
  | _ -> (
      match Hashtbl.find_opt st.pending key with
      | Some p -> Lwt.protected p
      | None ->
          let fetch =
            match !jwks_fetch with
            | Some f -> f
            | None -> Haltsql_auth.Oidc_client.http_fetch ~timeout:5. ()
          in
          let p = Haltsql_auth.Oidc_client.provider ~fetch o.provider in
          let check =
            Lwt.finalize
              (fun () ->
                let* r =
                  Lwt.catch
                    (fun () -> Haltsql_auth.Oidc_client.refresh p)
                    (fun e -> Lwt.return_error (Printexc.to_string e))
                in
                Hashtbl.replace st.results key (Ctx.now (), r);
                Lwt.return r)
              (fun () ->
                Hashtbl.remove st.pending key;
                Lwt.return_unit)
          in
          (* The check may have finished already (no yield): only record it in flight
             while it is. *)
          if Lwt.state check = Lwt.Sleep then Hashtbl.replace st.pending key check;
          Lwt.protected check)

let oidc_item ctx (o : C.oidc) =
  let+ r = jwks_check ctx o in
  let id = "oidc:" ^ o.provider.oidc_name and name = o.provider.oidc_name in
  let detail = "OIDC issuer " ^ o.provider.issuer in
  match r with
  | Ok n when n > 0 ->
      item ~id ~name ~detail:(Printf.sprintf "%s, %d signing keys" detail n) "connected"
  | Ok _ -> item ~id ~name ~detail ~error:"JWKS has no usable signing keys" "degraded"
  | Error e -> item ~id ~name ~detail ~error:("JWKS unreachable: " ^ e) "error"

(* Strips credentials, query and fragment from anything URL-like. *)
let redact s =
  match Uri.of_string s with
  | u when Uri.scheme u <> None && Uri.host u <> None ->
      Uri.to_string
        (Uri.with_fragment (Uri.with_query (Uri.with_userinfo u None) []) None)
  | _ -> s

let jstr k j = match Api.member k j with Some (`String s) -> Some s | _ -> None
let jlist k j = match Api.member k j with Some (`List l) -> l | _ -> []

let fleet_bundles (ctx : Ctx.t) =
  match Fleet.snapshot ctx with
  | None -> []
  | Some f ->
      List.map
        (fun b ->
          let source = redact (Option.value (jstr "source" b) ~default:"bundle source") in
          let version = Option.value (jstr "version" b) ~default:"unknown version" in
          let in_sync =
            match Api.member "in_sync" b with Some (`Bool x) -> x | _ -> true
          in
          let detail =
            Printf.sprintf "%s on %s verifiers" version
              (match Api.member "verifiers" b with
              | Some (`Int n) -> string_of_int n
              | _ -> "?")
          in
          if in_sync then item ~id:("bundle:" ^ source) ~name:source ~detail "connected"
          else
            item ~id:("bundle:" ^ source) ~name:source ~detail
              ~error:"verifiers serve different bundle versions" "degraded")
        (jlist "bundles" f)

let fleet_sinks (ctx : Ctx.t) =
  match Fleet.snapshot ctx with
  | None -> []
  | Some f ->
      List.map
        (fun s ->
          let ty = Option.value (jstr "type" s) ~default:"sink" in
          let target = redact (Option.value (jstr "target" s) ~default:"") in
          let state = Option.value (jstr "state" s) ~default:"healthy" in
          let id = "sink:" ^ ty ^ ":" ^ target in
          let name = "Audit sink (" ^ ty ^ ")" in
          if state = "healthy" then item ~id ~name ~detail:target "connected"
          else item ~id ~name ~detail:target ~error:("sink is " ^ state) "degraded")
        (jlist "sinks" f)

(* The ingest status entry matching an audit source, by any of the usual keys:
   [`Error e] when its last read failed, [`Ok] when it was read, [`Unknown] when
   ingestion has not reported on it yet (so it is only "configured"). *)
let ingest_state (ctx : Ctx.t) detail =
  match Ingest.status ctx with
  | `List l -> (
      match
        List.find_map
          (fun s ->
            let names =
              List.filter_map
                (fun k -> jstr k s)
                [ "source"; "name"; "id"; "location"; "uri"; "path" ]
            in
            if List.mem detail names then
              match (jstr "error" s, jstr "state" s) with
              | Some e, _ when e <> "" -> Some (`Error e)
              | _, Some (("error" | "failing") as st) -> Some (`Error st)
              | _ -> if jstr "last_read" s <> None then Some `Ok else Some `Unknown
            else None)
          l
      with
      | Some r -> r
      | None -> `Unknown)
  | _ -> `Unknown

let catalog_items (ctx : Ctx.t) =
  let c = ctx.config in
  if Data.loaded ctx then
    List.map
      (fun (s : Data.source) ->
        let id = "catalog:" ^ s.label in
        let detail =
          if s.authoritative || s.error <> None then s.detail
          else s.detail ^ " (non-authoritative, flags only)"
        in
        match s.error with
        | Some e -> item ~id ~name:s.label ~detail ~error:e "error"
        | None -> item ~id ~name:s.label ~detail "connected")
      (Data.sources ctx)
  else
    List.map
      (fun (k : C.catalog) ->
        let label = Option.value k.c_label ~default:k.c_kind in
        item ~id:("catalog:" ^ label) ~name:label ~detail:"not loaded yet" "configured")
      c.catalogs

(* Derived from configuration plus cheap live checks: OIDC JWKS reachability (cached 5
   minutes), catalog load errors, bundle sources and audit sinks from the fleet snapshot,
   audit sources from ingestion. Credentials are never returned. *)
let integrations (ctx : Ctx.t) _p _r =
  let c = ctx.config in
  let group name items = `Assoc [ ("name", `String name); ("items", `List items) ] in
  let* oidc = Lwt_list.map_p (oidc_item ctx) c.auth.oidc in
  let identity =
    oidc
    @
    match c.auth.proxy with
    | Some p ->
        [
          item ~id:"proxy" ~name:p.proxy_label ~detail:"Identity-aware proxy headers"
            "configured";
        ]
    | None -> []
  in
  let opa =
    match c.opa with
    | None -> []
    | Some o ->
        let path =
          match Api.member "decision" o with Some (`String s) -> s | _ -> "configured"
        in
        [ item ~id:"opa" ~name:"Open Policy Agent" ~detail:path "configured" ]
  in
  let alert key name =
    match integrations_member key c with
    | Some (`Assoc _) -> [ item ~id:key ~name ~detail:"" "configured" ]
    | _ -> [ item ~id:key ~name ~detail:"" "not_set_up" ]
  in
  let sources =
    List.map
      (fun (v, s) ->
        let d =
          match s with
          | C.Src_file f -> f
          | C.Src_s3 { uri; _ } -> uri
          | C.Src_gcs { uri } -> uri
        in
        let id = "audit:" ^ d and name = "Audit records (" ^ v ^ ")" in
        match ingest_state ctx d with
        | `Error e -> item ~id ~name ~detail:d ~error:e "error"
        | `Ok -> item ~id ~name ~detail:d "connected"
        | `Unknown -> item ~id ~name ~detail:d "configured")
      c.audit.sources
  in
  Api.json
    (`Assoc
       [
         ( "groups",
           `List
             [
               group "Caller identity" identity;
               group "Policy source" (alert "github" "GitHub" @ fleet_bundles ctx);
               group "External policy" opa;
               group "Data catalogs" (catalog_items ctx);
               group "Audit and SIEM" (sources @ fleet_sinks ctx);
               group "Alerts and tickets"
                 (alert "slack" "Slack" @ alert "pagerduty" "PagerDuty"
                @ alert "jira" "Jira");
             ] );
       ])

let routes =
  [
    Router.get "/api/v1/me" me;
    Router.get "/api/v1/access/roles" roles;
    Router.get "/api/v1/integrations" integrations;
  ]
