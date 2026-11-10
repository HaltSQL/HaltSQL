(* Authenticates a console request (docs/console/api.md#authentication):
   OIDC bearer JWT, trusted auth-proxy headers, static service token, or dev mode.
   Groups map to roles through auth.roles; the most privileged mapped role wins. *)

open Lwt.Syntax
module C = Console_config

type t = { cfg : C.auth; registry : (C.oidc * Haltsql_auth.Oidc_client.provider) list }

let create ?fetch (cfg : C.auth) =
  {
    cfg;
    registry =
      List.map
        (fun (o : C.oidc) -> (o, Haltsql_auth.Oidc_client.provider ?fetch o.provider))
        cfg.oidc;
  }

let role_of_groups (cfg : C.auth) groups =
  List.fold_left
    (fun best (role, mapped) ->
      if List.exists (fun g -> List.mem g groups) mapped then
        match best with
        | Some b when Rbac.precedence b >= Rbac.precedence role -> best
        | _ -> Some role
      else best)
    None cfg.roles

let bearer req =
  match Cohttp.Header.get (Cohttp.Request.headers req) "authorization" with
  | Some h
    when String.length h > 7 && String.lowercase_ascii (String.sub h 0 7) = "bearer " ->
      Some (String.trim (String.sub h 7 (String.length h - 7)))
  | _ -> None

let claim_strings claims name =
  match Haltsql_auth.Oidc.lookup_claim claims name with
  | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
  | Some (`String s) ->
      String.split_on_char ',' s |> List.map String.trim |> List.filter (( <> ) "")
  | _ -> []

let claim_string claims name =
  match Haltsql_auth.Oidc.lookup_claim claims name with
  | Some (`String s) -> Some s
  | _ -> None

type outcome = Ok of Ctx.principal | Unauthenticated of string

let no_role who =
  Unauthenticated (Printf.sprintf "%s is not in any group mapped to a console role" who)

let oidc t token =
  match Haltsql_auth.Jwt.unverified_issuer token with
  | None -> Lwt.return_none
  | Some iss -> (
      match
        List.find_opt (fun ((o : C.oidc), _) -> o.provider.issuer = iss) t.registry
      with
      | None -> Lwt.return_none
      | Some (o, provider) -> (
          let* r = Haltsql_auth.Oidc_client.verify provider token in
          match r with
          | Error e ->
              Lwt.return_some
                (Unauthenticated ("token rejected: " ^ Haltsql_auth.Jwt.error_code e))
          | Ok identity -> (
              (* Signature and claims are verified; read the remaining claims. *)
              match Haltsql_auth.Jwt.decode token with
              | Error _ -> Lwt.return_some (Unauthenticated "token rejected")
              | Ok tok ->
                  let claims = tok.claims in
                  let groups =
                    List.map
                      (fun g -> o.group_prefix ^ g)
                      (claim_strings claims o.groups_claim)
                  in
                  let id =
                    match claim_string claims "email" with
                    | Some e -> e
                    | None -> Option.value identity.subject ~default:"(unknown)"
                  in
                  let name = Option.value (claim_string claims "name") ~default:id in
                  Lwt.return_some
                    (match role_of_groups t.cfg groups with
                    | None -> no_role id
                    | Some role ->
                        Ok
                          {
                            Ctx.id;
                            name;
                            auth = "oidc:" ^ o.provider.oidc_name;
                            groups;
                            role;
                          }))))

let token t tok =
  let h = Haltsql.sha256_hex tok in
  List.find_map
    (fun (s : C.service_token) ->
      if Eqaf.equal s.token_sha256 h then
        Some
          (Ok
             {
               Ctx.id = "token:" ^ s.token_name;
               name = s.token_name;
               auth = "token:" ^ s.token_name;
               groups = [];
               role = s.token_role;
             })
      else None)
    t.cfg.tokens

let proxy t req =
  match t.cfg.proxy with
  | None -> None
  | Some p -> (
      let hdr name = Cohttp.Header.get (Cohttp.Request.headers req) name in
      match hdr p.user_header with
      | None | Some "" -> None
      | Some user ->
          let groups =
            match Option.bind p.groups_header hdr with
            | None -> []
            | Some g ->
                String.split_on_char ',' g |> List.map String.trim
                |> List.filter (( <> ) "")
          in
          let name = Option.value (Option.bind p.name_header hdr) ~default:user in
          Some
            (match role_of_groups t.cfg groups with
            | None -> no_role user
            | Some role ->
                Ok { Ctx.id = user; name; auth = "proxy:" ^ p.proxy_label; groups; role })
      )

let authenticate t (req : Cohttp.Request.t) : outcome Lwt.t =
  let* from_bearer =
    match bearer req with
    | None -> Lwt.return_none
    | Some tok -> (
        let* o =
          if Haltsql_auth.Jwt.looks_like_jwt tok then oidc t tok else Lwt.return_none
        in
        match o with
        | Some _ -> Lwt.return o
        | None -> (
            match token t tok with
            | Some r -> Lwt.return_some r
            | None -> Lwt.return_some (Unauthenticated "unknown bearer token")))
  in
  match from_bearer with
  | Some r -> Lwt.return r
  | None -> (
      match proxy t req with
      | Some r -> Lwt.return r
      | None -> (
          match t.cfg.dev with
          | Some d ->
              Lwt.return
                (Ok
                   {
                     Ctx.id = d.dev_user;
                     name = d.dev_user;
                     auth = "dev";
                     groups = [];
                     role = d.dev_role;
                   })
          | None -> Lwt.return (Unauthenticated "authentication required")))
