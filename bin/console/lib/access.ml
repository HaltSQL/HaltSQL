(* GET /api/v1/me, GET /api/v1/access/roles, GET /api/v1/integrations. *)

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

(* Derived from configuration only, so items are "configured" or "not_set_up". The
   "configured" and "error" states are reserved for live checks, which the features that
   own each integration add later (fleet for bundles and sinks, data for catalogs). *)
let integrations (ctx : Ctx.t) _p _r =
  let c = ctx.config in
  let group name items = `Assoc [ ("name", `String name); ("items", `List items) ] in
  let identity =
    List.map
      (fun (o : C.oidc) ->
        item
          ~id:("oidc:" ^ o.provider.oidc_name)
          ~name:o.provider.oidc_name
          ~detail:("OIDC issuer " ^ o.provider.issuer)
          "configured")
      c.auth.oidc
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
  let catalogs =
    List.map
      (fun (k : C.catalog) ->
        item ~id:("catalog:" ^ k.c_kind) ~name:k.c_kind
          ~detail:(Option.value k.c_label ~default:"")
          "configured")
      c.catalogs
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
        item ~id:("audit:" ^ d) ~name:("Audit records (" ^ v ^ ")") ~detail:d "configured")
      c.audit.sources
  in
  Api.json
    (`Assoc
       [
         ( "groups",
           `List
             [
               group "Caller identity" identity;
               group "Policy source" (alert "github" "GitHub");
               group "External policy" opa;
               group "Data catalogs" catalogs;
               group "Audit and SIEM" sources;
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
