(* Authenticates a console request (docs/console/api.md#authentication):
   OIDC bearer JWT, trusted auth-proxy headers, static service token, or dev mode.
   Groups map to roles through auth.roles; a principal holds every mapped role (its
   permissions are their union) and the most privileged one is its primary role. *)

open Lwt.Syntax
module C = Console_config

type t = {
  cfg : C.auth;
  registry : (C.oidc * Haltsql_auth.Oidc_client.provider) list;
  now : unit -> float;
}

let create ?fetch ?(now = Unix.gettimeofday) (cfg : C.auth) =
  {
    cfg;
    registry =
      List.map
        (fun (o : C.oidc) ->
          (o, Haltsql_auth.Oidc_client.provider ?fetch ~now o.provider))
        cfg.oidc;
    now;
  }

(** Every role at least one of [groups] maps to, most privileged first. *)
let roles_of_groups (cfg : C.auth) groups =
  List.filter
    (fun r ->
      List.exists
        (fun (role, mapped) ->
          role = r && List.exists (fun g -> List.mem g groups) mapped)
        cfg.roles)
    Rbac.all_roles
  |> List.stable_sort (fun a b -> compare (Rbac.precedence b) (Rbac.precedence a))

(** [true] when the sign-in is recent enough: now - (auth_time, else iat) is at most
    [session_hours]. With [require_auth_time] a token without [auth_time] is refused;
    otherwise a token with neither claim is accepted (its exp still applies). *)
let session_fresh ?(require_auth_time = false) ~now ~session_hours claims =
  let num name =
    match Haltsql_auth.Jwt.number_claim name claims with Ok v -> v | Error _ -> None
  in
  match num "auth_time" with
  | None when require_auth_time -> false
  | auth_time -> (
      match match auth_time with Some t -> Some t | None -> num "iat" with
      | None -> true
      | Some t -> now -. t <= float_of_int session_hours *. 3600.)

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

type outcome = Authenticated of Ctx.principal | Unauthenticated of string

let no_role who =
  Unauthenticated (Printf.sprintf "%s is not in any group mapped to a console role" who)

let of_groups (cfg : C.auth) ~id ~name ~auth groups =
  match roles_of_groups cfg groups with
  | [] -> no_role id
  | role :: _ as roles -> Authenticated { Ctx.id; name; auth; groups; roles; role }

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
                  if
                    not
                      (session_fresh ~require_auth_time:t.cfg.require_auth_time
                         ~now:(t.now ()) ~session_hours:t.cfg.session_hours claims)
                  then Lwt.return_some (Unauthenticated "session expired; sign in again")
                  else
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
                      (of_groups t.cfg ~id ~name
                         ~auth:("oidc:" ^ o.provider.oidc_name)
                         groups))))

let token t tok =
  let h = Haltsql.sha256_hex tok in
  List.find_map
    (fun (s : C.service_token) ->
      if Eqaf.equal s.token_sha256 h then
        Some
          (Authenticated
             {
               Ctx.id = "token:" ^ s.token_name;
               name = s.token_name;
               auth = "token:" ^ s.token_name;
               groups = [];
               roles = [ s.token_role ];
               role = s.token_role;
             })
      else None)
    t.cfg.tokens

(* The request came from the configured proxy: the TCP peer is in trusted_proxies (when
   set) and the shared-secret header hashes to secret_sha256 (when set). *)
let from_trusted_proxy (p : C.proxy_auth) ?peer hdr =
  let peer_ok =
    p.trusted_proxies = []
    ||
    match Option.bind peer C.parse_ip with
    | Some ip -> C.ip_in_prefixes ip p.trusted_proxies
    | None -> false
  in
  let secret_ok =
    match (p.secret_header, p.secret_sha256) with
    | Some h, Some digest -> (
        match hdr h with
        | Some v -> Eqaf.equal digest (Haltsql.sha256_hex v)
        | None -> false)
    | _ -> true
  in
  peer_ok && secret_ok

let proxy t ?peer req =
  match t.cfg.proxy with
  | None -> None
  | Some p -> (
      let hdr name = Cohttp.Header.get (Cohttp.Request.headers req) name in
      match hdr p.user_header with
      | None | Some "" -> None
      | Some _ when not (from_trusted_proxy p ?peer hdr) ->
          Some (Unauthenticated "proxy identity headers from an untrusted source")
      | Some user ->
          let groups =
            match Option.bind p.groups_header hdr with
            | None -> []
            | Some g ->
                String.split_on_char ',' g |> List.map String.trim
                |> List.filter (( <> ) "")
                |> List.map (fun g -> p.proxy_group_prefix ^ g)
          in
          let name = Option.value (Option.bind p.name_header hdr) ~default:user in
          Some (of_groups t.cfg ~id:user ~name ~auth:("proxy:" ^ p.proxy_label) groups))

let authenticate t ?peer (req : Cohttp.Request.t) : outcome Lwt.t =
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
      match proxy t ?peer req with
      | Some r -> Lwt.return r
      | None -> (
          match t.cfg with
          (* Config validation makes dev the only method; never fall back to it when
             another method is configured. *)
          | { dev = Some d; oidc = []; proxy = None; tokens = []; _ } ->
              Lwt.return
                (Authenticated
                   {
                     Ctx.id = d.dev_user;
                     name = d.dev_user;
                     auth = "dev";
                     groups = [];
                     roles = [ d.dev_role ];
                     role = d.dev_role;
                   })
          | _ -> Lwt.return (Unauthenticated "authentication required")))
