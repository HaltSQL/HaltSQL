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
         ("role", `String (Rbac.role_to_string p.role));
         ("role_label", `String (Rbac.role_label p.role));
         ("permissions", Rbac.permissions_json p.role);
         ("environment", environment_json ctx.config);
       ])

let roles (ctx : Ctx.t) _p _r =
  let a = ctx.config.auth in
  Api.json
    (`Assoc
       [
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
         ( "mapping",
           `Assoc
             (List.map (fun (r, gs) -> (Rbac.role_to_string r, Api.strings gs)) a.roles)
         );
         ( "safeguards",
           `List
             [
               `Assoc
                 [
                   ("id", `String "two_person_rule");
                   ("title", `String "Two-person rule");
                   ( "detail",
                     `String
                       "Policy changes need two owners, never the requester. Enforced by \
                        branch protection on the policy repository." );
                 ];
               `Assoc
                 [
                   ("id", `String "sessions");
                   ("title", `String "Sessions");
                   ("detail", `String (Printf.sprintf "%d hours." a.session_hours));
                 ];
             ] );
         ("dev_mode", `Bool (a.dev <> None));
       ])

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

(* Derived from configuration. Live health checks are added by the features that own
   each integration (fleet for bundles and sinks, data for catalogs). *)
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
          "connected")
      c.auth.oidc
    @
    match c.auth.proxy with
    | Some p ->
        [
          item ~id:"proxy" ~name:p.proxy_label ~detail:"Identity-aware proxy headers"
            "connected";
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
        [ item ~id:"opa" ~name:"Open Policy Agent" ~detail:path "connected" ]
  in
  let catalogs =
    List.map
      (fun (k : C.catalog) ->
        item ~id:("catalog:" ^ k.c_kind) ~name:k.c_kind
          ~detail:(Option.value k.c_label ~default:"")
          "connected")
      c.catalogs
  in
  let alert key name =
    match integrations_member key c with
    | Some (`Assoc _) -> [ item ~id:key ~name ~detail:"" "connected" ]
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
        item ~id:("audit:" ^ d) ~name:("Audit records (" ^ v ^ ")") ~detail:d "connected")
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
