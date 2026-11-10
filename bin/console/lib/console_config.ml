(* haltsql-console configuration (YAML or JSON). See docs/console/config.md.

   Secret placeholders (${env:NAME}, ${vault:...}, ${aws-sm:...}, ${gcp-sm:...}) are
   allowed in any string value; providers are configured by a [secrets] section with the
   same shape as the server's. Unknown top-level keys are errors so typos are caught. *)

type environment = { org : string; env_name : string; region : string option }

type oidc = {
  provider : Haltsql.Config.oidc_provider;
  groups_claim : string;  (** default ["groups"] *)
  group_prefix : string;  (** prepended to group names for role mapping, default [""] *)
}

type proxy_auth = {
  user_header : string;  (** e.g. [x-auth-request-email] *)
  name_header : string option;
  groups_header : string option;  (** comma-separated groups *)
  proxy_label : string;  (** shown as the auth method, e.g. ["oauth2-proxy"] *)
}

type service_token = {
  token_name : string;
  token_sha256 : string;
  token_role : Rbac.role;
}

type dev = { dev_user : string; dev_role : Rbac.role }

type auth = {
  oidc : oidc list;
  proxy : proxy_auth option;
  tokens : service_token list;
  dev : dev option;
  roles : (Rbac.role * string list) list;  (** role -> groups *)
  session_hours : int;
}

type verifier_kind = Server | Proxy | Mcp

let verifier_kind_to_string = function
  | Server -> "server"
  | Proxy -> "proxy"
  | Mcp -> "mcp"

type verifier = {
  v_name : string;
  v_url : string;  (** base URL of the verifier's HTTP API (admin endpoints) *)
  v_kind : verifier_kind;
  v_location : string option;
  v_token : string option;  (** admin bearer token, resolved *)
  v_metrics_url : string option;  (** default [v_url ^ "/metrics"] *)
  v_workload : string option;  (** Kubernetes workload, e.g. [deployment/haltsql] *)
}

type kubernetes = {
  k_namespace : string;
  k_api : string;  (** default in-cluster [https://kubernetes.default.svc] *)
  k_token_file : string;
  k_ca_file : string;
}

type audit_source =
  | Src_file of string
      (** a file, a directory (every *.jsonl / *.log inside) or a glob *)
  | Src_s3 of { uri : string; region : string option; endpoint : string option }
  | Src_gcs of { uri : string }

type audit = {
  sources : (string * audit_source) list;  (** verifier name (or ["auto"]), source *)
  retention_hours : int;  (** default 168 *)
  max_records : int;  (** default 2_000_000 *)
  poll_seconds : int;  (** default 5 *)
}

type policies = {
  server_config : string option;  (** a haltsql-server config whose policies to load *)
  policy_files : string list;  (** extra policy files or directories *)
}

type catalog = {
  c_kind : string;  (** dbt | datahub | unity | openmetadata | file *)
  c_label : string option;
  c_options : Yojson.Safe.t;  (** the whole entry, interpreted by the Data module *)
}

type agent = {
  a_name : string;
  a_team : string option;
  a_via : string;  (** sidecar | proxy | mcp | in_process *)
  a_stack : string option;
  a_callers : string list;  (** audit [caller] values that belong to this agent *)
  a_identity : string option;
  a_policy : string option;
}

type exception_ = {
  e_column : string;  (** schema.table.column *)
  e_policy : string option;
  e_owner : string;
  e_ticket : string option;
  e_expires : string option;
}

type t = {
  file : string option;
  listen : string;
  environment : environment;
  state_dir : string;
  frontend_dir : string option;
  auth : auth;
  verifiers : verifier list;
  fleet_poll_seconds : int;
  kubernetes : kubernetes option;
  audit : audit;
  policies : policies;
  opa : Yojson.Safe.t option;  (** same shape as the server's [opa] block *)
  catalogs : catalog list;
  exceptions : exception_ list;
  agents : agent list;
  integrations : Yojson.Safe.t;  (** github, slack, pagerduty, jira; read by features *)
  signals : Yojson.Safe.t;  (** detector thresholds; read by Signals *)
  raw : Yojson.Safe.t;  (** the resolved document, for feature-specific keys *)
}

exception Invalid of string

let invalid fmt = Printf.ksprintf (fun m -> raise (Invalid m)) fmt

(* ---- decoding helpers ---- *)

let field_opt name j = match j with `Assoc l -> List.assoc_opt name l | _ -> None

let string_opt ctx name j =
  match field_opt name j with
  | None | Some `Null -> None
  | Some (`String s) -> Some s
  | Some _ -> invalid "%s.%s must be a string" ctx name

let string_req ctx name j =
  match string_opt ctx name j with
  | Some s -> s
  | None -> invalid "%s.%s is required" ctx name

let int_opt ctx name j ~default =
  match field_opt name j with
  | None | Some `Null -> default
  | Some (`Int i) -> i
  | Some _ -> invalid "%s.%s must be an integer" ctx name

let bool_opt ctx name j ~default =
  match field_opt name j with
  | None | Some `Null -> default
  | Some (`Bool b) -> b
  | Some _ -> invalid "%s.%s must be a boolean" ctx name

let list_opt ctx name j =
  match field_opt name j with
  | None | Some `Null -> []
  | Some (`List l) -> l
  | Some _ -> invalid "%s.%s must be a list" ctx name

let strings_opt ctx name j =
  List.map
    (function `String s -> s | _ -> invalid "%s.%s must be a list of strings" ctx name)
    (list_opt ctx name j)

let check_keys ctx allowed j =
  match j with
  | `Assoc l ->
      List.iter
        (fun (k, _) ->
          if not (List.mem k allowed) then invalid "%s: unknown key %S" ctx k)
        l
  | `Null -> ()
  | _ -> invalid "%s must be a mapping" ctx

let role_req ctx name j =
  let s = string_req ctx name j in
  match Rbac.role_of_string s with
  | Some r -> r
  | None -> invalid "%s.%s must be one of dev, analyst, owner, audit, admin" ctx name

(* ---- sections ---- *)

let environment j =
  check_keys "environment" [ "org"; "name"; "region" ] j;
  {
    org = Option.value (string_opt "environment" "org" j) ~default:"HaltSQL";
    env_name = Option.value (string_opt "environment" "name" j) ~default:"Default";
    region = string_opt "environment" "region" j;
  }

let oidc_entry i j =
  let ctx = Printf.sprintf "auth.oidc[%d]" i in
  check_keys ctx
    [
      "name";
      "issuer";
      "audience";
      "audiences";
      "jwks_uri";
      "groups_claim";
      "group_prefix";
      "allow_insecure_http";
      "leeway_seconds";
    ]
    j;
  let audiences =
    match (string_opt ctx "audience" j, strings_opt ctx "audiences" j) with
    | Some a, l -> a :: l
    | None, [] -> invalid "%s.audience is required" ctx
    | None, l -> l
  in
  let name = string_req ctx "name" j in
  {
    provider =
      {
        Haltsql.Config.oidc_name = name;
        issuer = string_req ctx "issuer" j;
        audiences;
        jwks_uri = string_opt ctx "jwks_uri" j;
        algorithms = [ Haltsql.Config.RS256; ES256; PS256; EdDSA ];
        leeway_seconds = int_opt ctx "leeway_seconds" j ~default:60;
        jwks_cache_seconds = 300;
        oidc_policy = Oidc_pinned "console";
        context_claims = [];
        required_claims = [];
        oidc_request_context_fields = [];
        allow_insecure_http = bool_opt ctx "allow_insecure_http" j ~default:false;
      };
    groups_claim = Option.value (string_opt ctx "groups_claim" j) ~default:"groups";
    group_prefix = Option.value (string_opt ctx "group_prefix" j) ~default:(name ^ ":");
  }

let auth j =
  check_keys "auth" [ "oidc"; "proxy"; "tokens"; "dev"; "roles"; "session_hours" ] j;
  let proxy =
    match field_opt "proxy" j with
    | None | Some `Null -> None
    | Some p ->
        check_keys "auth.proxy"
          [ "user_header"; "name_header"; "groups_header"; "label" ]
          p;
        Some
          {
            user_header = String.lowercase_ascii (string_req "auth.proxy" "user_header" p);
            name_header =
              Option.map String.lowercase_ascii (string_opt "auth.proxy" "name_header" p);
            groups_header =
              Option.map String.lowercase_ascii
                (string_opt "auth.proxy" "groups_header" p);
            proxy_label =
              Option.value (string_opt "auth.proxy" "label" p) ~default:"proxy";
          }
  in
  let tokens =
    List.mapi
      (fun i t ->
        let ctx = Printf.sprintf "auth.tokens[%d]" i in
        check_keys ctx [ "name"; "sha256"; "role" ] t;
        let h = String.lowercase_ascii (string_req ctx "sha256" t) in
        if String.length h <> 64 then invalid "%s.sha256 must be 64 hex characters" ctx;
        {
          token_name = string_req ctx "name" t;
          token_sha256 = h;
          token_role = role_req ctx "role" t;
        })
      (list_opt "auth" "tokens" j)
  in
  let dev =
    match field_opt "dev" j with
    | None | Some `Null | Some (`Bool false) -> None
    | Some (`Bool true) ->
        Some { dev_user = "developer@localhost"; dev_role = Rbac.Admin }
    | Some d ->
        check_keys "auth.dev" [ "user"; "role" ] d;
        Some
          {
            dev_user =
              Option.value (string_opt "auth.dev" "user" d) ~default:"developer@localhost";
            dev_role =
              (match string_opt "auth.dev" "role" d with
              | None -> Rbac.Admin
              | Some _ -> role_req "auth.dev" "role" d);
          }
  in
  let roles =
    match field_opt "roles" j with
    | None | Some `Null -> []
    | Some (`Assoc l) ->
        List.map
          (fun (k, v) ->
            match Rbac.role_of_string k with
            | None -> invalid "auth.roles: unknown role %S" k
            | Some r ->
                ( r,
                  match v with
                  | `List l ->
                      List.map
                        (function
                          | `String s -> s
                          | _ -> invalid "auth.roles.%s must list strings" k)
                        l
                  | _ -> invalid "auth.roles.%s must be a list" k ))
          l
    | Some _ -> invalid "auth.roles must be a mapping"
  in
  {
    oidc = List.mapi oidc_entry (list_opt "auth" "oidc" j);
    proxy;
    tokens;
    dev;
    roles;
    session_hours = int_opt "auth" "session_hours" j ~default:8;
  }

let verifier i j =
  let ctx = Printf.sprintf "verifiers[%d]" i in
  check_keys ctx
    [ "name"; "url"; "kind"; "location"; "token"; "metrics_url"; "workload" ]
    j;
  let kind =
    match string_opt ctx "kind" j with
    | None | Some "server" -> Server
    | Some "proxy" -> Proxy
    | Some "mcp" -> Mcp
    | Some k -> invalid "%s.kind must be server, proxy or mcp (got %S)" ctx k
  in
  let url = string_req ctx "url" j in
  let url =
    if String.ends_with ~suffix:"/" url then String.sub url 0 (String.length url - 1)
    else url
  in
  {
    v_name = string_req ctx "name" j;
    v_url = url;
    v_kind = kind;
    v_location = string_opt ctx "location" j;
    v_token = string_opt ctx "token" j;
    v_metrics_url = string_opt ctx "metrics_url" j;
    v_workload = string_opt ctx "workload" j;
  }

let audit_source i j =
  let ctx = Printf.sprintf "audit.sources[%d]" i in
  check_keys ctx [ "verifier"; "file"; "path"; "s3"; "gcs"; "region"; "endpoint" ] j;
  let verifier = Option.value (string_opt ctx "verifier" j) ~default:"auto" in
  let file =
    match string_opt ctx "file" j with
    | Some f -> Some f
    | None -> string_opt ctx "path" j
  in
  match (file, string_opt ctx "s3" j, string_opt ctx "gcs" j) with
  | Some f, None, None -> (verifier, Src_file f)
  | None, Some u, None ->
      ( verifier,
        Src_s3
          {
            uri = u;
            region = string_opt ctx "region" j;
            endpoint = string_opt ctx "endpoint" j;
          } )
  | None, None, Some u -> (verifier, Src_gcs { uri = u })
  | _ -> invalid "%s needs exactly one of file, s3 or gcs" ctx

let audit j =
  check_keys "audit" [ "sources"; "retention_hours"; "max_records"; "poll_seconds" ] j;
  {
    sources = List.mapi audit_source (list_opt "audit" "sources" j);
    retention_hours = int_opt "audit" "retention_hours" j ~default:168;
    max_records = int_opt "audit" "max_records" j ~default:2_000_000;
    poll_seconds = int_opt "audit" "poll_seconds" j ~default:5;
  }

let policies j =
  check_keys "policies" [ "server_config"; "files" ] j;
  {
    server_config = string_opt "policies" "server_config" j;
    policy_files = strings_opt "policies" "files" j;
  }

let catalog i j =
  let ctx = Printf.sprintf "catalogs[%d]" i in
  { c_kind = string_req ctx "kind" j; c_label = string_opt ctx "label" j; c_options = j }

let agent i j =
  let ctx = Printf.sprintf "agents[%d]" i in
  check_keys ctx [ "name"; "team"; "via"; "stack"; "callers"; "identity"; "policy" ] j;
  let via = Option.value (string_opt ctx "via" j) ~default:"sidecar" in
  if not (List.mem via [ "sidecar"; "proxy"; "mcp"; "in_process" ]) then
    invalid "%s.via must be sidecar, proxy, mcp or in_process" ctx;
  {
    a_name = string_req ctx "name" j;
    a_team = string_opt ctx "team" j;
    a_via = via;
    a_stack = string_opt ctx "stack" j;
    a_callers = strings_opt ctx "callers" j;
    a_identity = string_opt ctx "identity" j;
    a_policy = string_opt ctx "policy" j;
  }

let exception_entry i j =
  let ctx = Printf.sprintf "data.exceptions[%d]" i in
  check_keys ctx [ "column"; "policy"; "owner"; "ticket"; "expires" ] j;
  {
    e_column = string_req ctx "column" j;
    e_policy = string_opt ctx "policy" j;
    e_owner = string_req ctx "owner" j;
    e_ticket = string_opt ctx "ticket" j;
    e_expires = string_opt ctx "expires" j;
  }

let kubernetes j =
  check_keys "fleet.kubernetes" [ "namespace"; "api"; "token_file"; "ca_file" ] j;
  {
    k_namespace = string_req "fleet.kubernetes" "namespace" j;
    k_api =
      Option.value
        (string_opt "fleet.kubernetes" "api" j)
        ~default:"https://kubernetes.default.svc";
    k_token_file =
      Option.value
        (string_opt "fleet.kubernetes" "token_file" j)
        ~default:"/var/run/secrets/kubernetes.io/serviceaccount/token";
    k_ca_file =
      Option.value
        (string_opt "fleet.kubernetes" "ca_file" j)
        ~default:"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
  }

let top_level_keys =
  [
    "listen";
    "environment";
    "state_dir";
    "frontend_dir";
    "auth";
    "verifiers";
    "fleet";
    "audit";
    "policies";
    "opa";
    "catalogs";
    "data";
    "agents";
    "integrations";
    "signals";
    "secrets";
  ]

let of_json ?file (j : Yojson.Safe.t) : t =
  check_keys "config" top_level_keys j;
  let sub name = Option.value (field_opt name j) ~default:`Null in
  let fleet = sub "fleet" in
  check_keys "fleet" [ "poll_seconds"; "kubernetes" ] fleet;
  let data = sub "data" in
  check_keys "data" [ "exceptions" ] data;
  let cfg =
    {
      file;
      listen = Option.value (string_opt "config" "listen" j) ~default:"127.0.0.1:8090";
      environment = environment (sub "environment");
      state_dir =
        Option.value (string_opt "config" "state_dir" j) ~default:"./console-state";
      frontend_dir = string_opt "config" "frontend_dir" j;
      auth = auth (sub "auth");
      verifiers = List.mapi verifier (list_opt "config" "verifiers" j);
      fleet_poll_seconds = int_opt "fleet" "poll_seconds" fleet ~default:30;
      kubernetes =
        (match field_opt "kubernetes" fleet with
        | None | Some `Null -> None
        | Some k -> Some (kubernetes k));
      audit = audit (sub "audit");
      policies = policies (sub "policies");
      opa = (match field_opt "opa" j with None | Some `Null -> None | Some o -> Some o);
      catalogs = List.mapi catalog (list_opt "config" "catalogs" j);
      exceptions = List.mapi exception_entry (list_opt "data" "exceptions" data);
      agents = List.mapi agent (list_opt "config" "agents" j);
      integrations = sub "integrations";
      signals = sub "signals";
      raw = j;
    }
  in
  let names = List.map (fun v -> v.v_name) cfg.verifiers in
  List.iter
    (fun n ->
      if List.length (List.filter (( = ) n) names) > 1 then
        invalid "verifiers: duplicate name %S" n)
    names;
  if
    cfg.auth.oidc = [] && cfg.auth.proxy = None && cfg.auth.tokens = []
    && cfg.auth.dev = None
  then invalid "auth: configure at least one of oidc, proxy, tokens or dev";
  cfg

(* ---- placeholders ---- *)

(* Replaces ${env:NAME} and provider placeholders in every string leaf. *)
let substitute ~(resolve : scheme:string -> reference:string -> (string, string) result) j
    =
  let re_sub s =
    let b = Buffer.create (String.length s) in
    let n = String.length s in
    let rec go i =
      if i >= n then ()
      else if i + 2 < n && s.[i] = '$' && s.[i + 1] = '$' && s.[i + 2] = '{' then (
        Buffer.add_string b "${";
        go (i + 3))
      else if i + 1 < n && s.[i] = '$' && s.[i + 1] = '{' then
        match String.index_from_opt s (i + 2) '}' with
        | None -> Buffer.add_string b (String.sub s i (n - i))
        | Some j -> (
            let inner = String.sub s (i + 2) (j - i - 2) in
            match String.index_opt inner ':' with
            | None ->
                invalid
                  "placeholder ${%s} needs a scheme (env:, vault:, aws-sm:, gcp-sm:)"
                  inner
            | Some k -> (
                let scheme = String.sub inner 0 k
                and reference = String.sub inner (k + 1) (String.length inner - k - 1) in
                match resolve ~scheme ~reference with
                | Ok v ->
                    Buffer.add_string b v;
                    go (j + 1)
                | Error m -> invalid "cannot resolve ${%s:%s}: %s" scheme reference m))
      else (
        Buffer.add_char b s.[i];
        go (i + 1))
    in
    go 0;
    Buffer.contents b
  in
  let rec walk = function
    | `String s when String.contains s '$' -> `String (re_sub s)
    | `Assoc l -> `Assoc (List.map (fun (k, v) -> (k, walk v)) l)
    | `List l -> `List (List.map walk l)
    | x -> x
  in
  walk j

let env_resolver ?(env = Sys.getenv_opt) () ~scheme ~reference =
  match scheme with
  | "env" -> (
      match env reference with
      | Some v -> Ok v
      | None -> Error "environment variable is not set")
  | s -> Error (Printf.sprintf "secret provider %s is not configured in secrets" s)

(** Loads a file. Provider placeholders are resolved through the [secrets] section with
    {!Haltsql_cloud.Secrets} (concurrently, inside Lwt). *)
let load ?(env = Sys.getenv_opt) file : (t, string) result Lwt.t =
  let open Lwt.Syntax in
  match Haltsql.Docload.of_file file with
  | Error errs ->
      Lwt.return (Error (String.concat "; " (List.map Haltsql.Load_error.to_string errs)))
  | Ok doc -> (
      let text = Yojson.Safe.to_string doc in
      let provider_refs =
        List.filter
          (fun (s, _) -> s <> "env")
          (Haltsql_cloud.Secrets.scan_placeholders text)
      in
      let* resolver =
        if provider_refs = [] then Lwt.return (env_resolver ~env ())
        else
          match Haltsql.Config.secrets_of_json ~file ~env doc with
          | Error errs ->
              Lwt.fail
                (Invalid (String.concat "; " (List.map Haltsql.Load_error.to_string errs)))
          | Ok secrets ->
              let s = Haltsql_cloud.Secrets.create ~env secrets in
              let* () = Haltsql_cloud.Secrets.prefetch s provider_refs in
              let cached = Haltsql_cloud.Secrets.cached_resolver s in
              Lwt.return (fun ~scheme ~reference ->
                  if scheme = "env" then env_resolver ~env () ~scheme ~reference
                  else cached ~scheme ~reference)
      in
      try Lwt.return (Ok (of_json ~file (substitute ~resolve:resolver doc)))
      with Invalid m -> Lwt.return (Error m))
