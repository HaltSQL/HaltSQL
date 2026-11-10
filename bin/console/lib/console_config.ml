(* haltsql-console configuration (YAML or JSON). See docs/console/config.md.

   Secret placeholders (${env:NAME}, ${vault:...}, ${aws-sm:...}, ${gcp-sm:...}) are
   allowed in any string value; providers are configured by a [secrets] section with the
   same shape as the server's. Unknown top-level keys are errors so typos are caught.

   Placeholders in the typed sections read at startup (auth, verifiers, fleet, audit,
   policies, catalogs, data, agents, ...) are substituted at load. Placeholders in [opa],
   [integrations] and [signals] are only checked (syntax, scheme, provider configured)
   and stay unresolved in [t]; features call {!resolve} when they need the value, so the
   secret is not kept in memory and rotation is picked up without a restart. *)

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
  trusted_proxies : Ipaddr.Prefix.t list;
      (** TCP peers allowed to send identity headers (empty = not checked) *)
  secret_header : string option;
      (** header carrying a shared secret the proxy injects (lowercase) *)
  secret_sha256 : string option;  (** hex SHA-256 of that secret *)
  proxy_group_prefix : string;  (** prepended to proxy group names, default [""] *)
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
  require_auth_time : bool;
      (** refuse OIDC tokens without an [auth_time] claim (default false) *)
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
  v_token_ref : string option;
      (** the token as written when it holds a secret placeholder: Fleet re-resolves it
          with {!resolve} on every poll, so a rotated token is picked up *)
  v_ca_file : string option;  (** PEM CA bundle that verifies an [https] [v_url] *)
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

type origin = { o_scheme : string; o_host : string; o_port : int }
(** A browser origin: lowercase scheme and host (IPv6 in brackets) and an explicit port.
*)

type t = {
  file : string option;
  listen : string;
  public_url : string option;  (** e.g. [https://console.example.com] *)
  allowed_origins : origin list;
      (** [public_url]'s origin plus [allowed_origins]; when non-empty, a mutating
          request's [Origin] must be one of these (and [Host] is not compared) *)
  environment : environment;
  state_dir : string;
  frontend_dir : string option;
  auth : auth;
  verifiers : verifier list;
  fleet_poll_seconds : int;
  fleet_probe_timeout : float;  (** seconds, per probe request *)
  fleet_history_size : int;  (** metric samples kept per verifier *)
  fleet_max_concurrent : int;  (** verifiers probed at the same time *)
  kubernetes : kubernetes option;
  audit : audit;
  policies : policies;
  opa : Yojson.Safe.t option;  (** same shape as the server's [opa] block *)
  catalogs : catalog list;
  exceptions : exception_ list;
  agents : agent list;
  integrations : Yojson.Safe.t;
      (** github, slack, pagerduty, jira; read by features. Placeholders are NOT resolved:
          call {!resolve} on a string when the secret is needed. *)
  signals : Yojson.Safe.t;  (** detector thresholds; read by Signals (unresolved) *)
  raw : Yojson.Safe.t;
      (** the document as written, placeholders unresolved, for feature-specific keys *)
  resolver : secret_resolver;  (** used by {!resolve}; do not call directly *)
}

and secret_resolver = scheme:string -> reference:string -> (string, string) result Lwt.t

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

let int_range ctx name j ~default ~min ~max =
  let v =
    match field_opt name j with
    | None | Some `Null -> default
    | Some (`Int i) -> i
    | Some _ -> invalid "%s.%s must be an integer" ctx name
  in
  if v < min || v > max then invalid "%s.%s must be between %d and %d" ctx name min max;
  v

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

let is_hex s =
  String.for_all (function '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true | _ -> false) s

let strip_brackets s =
  let n = String.length s in
  if n >= 2 && s.[0] = '[' && s.[n - 1] = ']' then String.sub s 1 (n - 2) else s

(** An IP address or CIDR (IPv4 or IPv6); a bare address is a /32 or /128. *)
let parse_prefix s =
  let s = strip_brackets (String.trim s) in
  if String.contains s '/' then Result.to_option (Ipaddr.Prefix.of_string s)
  else Option.map Ipaddr.Prefix.of_addr (Result.to_option (Ipaddr.of_string s))

(** Parses a peer address (as text) into an IP, mapping IPv4-mapped IPv6 to IPv4. *)
let parse_ip s =
  match Ipaddr.of_string (strip_brackets (String.trim s)) with
  | Error _ -> None
  | Ok (Ipaddr.V6 _ as ip) -> (
      match Ipaddr.to_v4 ip with Some v4 -> Some (Ipaddr.V4 v4) | None -> Some ip)
  | Ok ip -> Some ip

let ip_in_prefixes ip prefixes =
  List.exists
    (fun pfx ->
      Ipaddr.Prefix.mem ip pfx
      ||
      (* an IPv4 peer also matches ::ffff:a.b.c.d/n written as IPv6 *)
      match ip with
      | Ipaddr.V4 v4 -> Ipaddr.Prefix.mem (Ipaddr.V6 (Ipaddr.v6_of_v4 v4)) pfx
      | Ipaddr.V6 _ -> false)
    prefixes

(** [host:port] like [Console_server.parse_listen]: empty host or [*] is [0.0.0.0], an
    IPv6 host is in brackets. Returns the host. *)
let listen_host s =
  match String.rindex_opt s ':' with
  | None -> Error (Printf.sprintf "invalid listen address %S (expected host:port)" s)
  | Some i ->
      let host = String.sub s 0 i in
      let host = if host = "" || host = "*" then "0.0.0.0" else host in
      Ok (strip_brackets host)

let is_loopback_host host =
  let host = strip_brackets host in
  String.lowercase_ascii host = "localhost"
  ||
  match Ipaddr.of_string host with
  | Ok (Ipaddr.V4 v4) -> Ipaddr.V4.Prefix.(mem v4 loopback)
  | Ok (Ipaddr.V6 v6) -> Ipaddr.V6.compare v6 Ipaddr.V6.localhost = 0
  | Error _ -> false

(** Parses an origin ([scheme://host[:port]], http or https, no path, query or userinfo).
    A missing port is the scheme's default. *)
let parse_origin s =
  let u = Uri.of_string (String.trim s) in
  match (Option.map String.lowercase_ascii (Uri.scheme u), Uri.host u) with
  | Some (("http" | "https") as scheme), Some h
    when h <> ""
         && (Uri.path u = "" || Uri.path u = "/")
         && Uri.query u = []
         && Uri.fragment u = None
         && Uri.userinfo u = None ->
      let h = String.lowercase_ascii h in
      let h = if String.contains h ':' && h.[0] <> '[' then "[" ^ h ^ "]" else h in
      let default_port = if scheme = "https" then 443 else 80 in
      Some
        {
          o_scheme = scheme;
          o_host = h;
          o_port = Option.value (Uri.port u) ~default:default_port;
        }
  | _ -> None

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
  check_keys "auth"
    [ "oidc"; "proxy"; "tokens"; "dev"; "roles"; "session_hours"; "require_auth_time" ]
    j;
  let proxy =
    match field_opt "proxy" j with
    | None | Some `Null -> None
    | Some p ->
        let ctx = "auth.proxy" in
        check_keys ctx
          [
            "user_header";
            "name_header";
            "groups_header";
            "label";
            "trusted_proxies";
            "secret_header";
            "secret_sha256";
            "group_prefix";
          ]
          p;
        let trusted_proxies =
          List.map
            (fun s ->
              match parse_prefix s with
              | Some pfx -> pfx
              | None ->
                  invalid "%s.trusted_proxies: %S is not an IP address or CIDR" ctx s)
            (strings_opt ctx "trusted_proxies" p)
        in
        let secret_header, secret_sha256 =
          match (string_opt ctx "secret_header" p, string_opt ctx "secret_sha256" p) with
          | None, None -> (None, None)
          | Some h, Some d ->
              let d = String.lowercase_ascii d in
              if String.length d <> 64 || not (is_hex d) then
                invalid "%s.secret_sha256 must be 64 hex characters" ctx;
              (Some (String.lowercase_ascii h), Some d)
          | _ -> invalid "%s.secret_header and secret_sha256 go together" ctx
        in
        if trusted_proxies = [] && secret_header = None then
          invalid
            "%s needs trusted_proxies and/or secret_header + secret_sha256, so identity \
             headers are only accepted from the proxy"
            ctx;
        Some
          {
            user_header = String.lowercase_ascii (string_req ctx "user_header" p);
            name_header =
              Option.map String.lowercase_ascii (string_opt ctx "name_header" p);
            groups_header =
              Option.map String.lowercase_ascii (string_opt ctx "groups_header" p);
            proxy_label = Option.value (string_opt ctx "label" p) ~default:"proxy";
            trusted_proxies;
            secret_header;
            secret_sha256;
            proxy_group_prefix =
              Option.value (string_opt ctx "group_prefix" p) ~default:"";
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
    | Some (`Bool true) -> Some { dev_user = "developer@localhost"; dev_role = Rbac.Dev }
    | Some d ->
        check_keys "auth.dev" [ "user"; "role" ] d;
        Some
          {
            dev_user =
              Option.value (string_opt "auth.dev" "user" d) ~default:"developer@localhost";
            dev_role =
              (match string_opt "auth.dev" "role" d with
              | None -> Rbac.Dev
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
    session_hours = int_range "auth" "session_hours" j ~default:8 ~min:1 ~max:720;
    require_auth_time = bool_opt "auth" "require_auth_time" j ~default:false;
  }

let verifier i j =
  let ctx = Printf.sprintf "verifiers[%d]" i in
  check_keys ctx
    [
      "name";
      "url";
      "kind";
      "location";
      "token";
      "metrics_url";
      "workload";
      "ca_file";
      "allow_insecure_http";
    ]
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
  let token = string_opt ctx "token" j in
  (* The admin token is a bearer credential: it only goes over https, or over http to a
     loopback host (tests, a local sidecar), like every other credential the console
     sends. *)
  let secure_url u =
    let u = Uri.of_string u in
    match (Option.map String.lowercase_ascii (Uri.scheme u), Uri.host u) with
    | Some "https", _ -> true
    | Some "http", Some h -> is_loopback_host h
    | _ -> false
  in
  let is_http u =
    match Option.map String.lowercase_ascii (Uri.scheme (Uri.of_string u)) with
    | Some ("http" | "https") -> true
    | _ -> false
  in
  if
    token <> None && is_http url
    && (not (secure_url url))
    && not (bool_opt ctx "allow_insecure_http" j ~default:false)
  then
    invalid
      "%s.url must be https:// (or http:// on a loopback host) when token is set: the \
       admin token would be sent in cleartext (use ca_file for a private CA, or set \
       allow_insecure_http: true for a trusted in-cluster network)"
      ctx;
  let workload = string_opt ctx "workload" j in
  (match workload with
  | Some w when K8s_names.parse_workload w = None ->
      invalid "%s.workload must be deployment/<name> or statefulset/<name> (got %S)" ctx w
  | _ -> ());
  {
    v_name = string_req ctx "name" j;
    v_url = url;
    v_kind = kind;
    v_location = string_opt ctx "location" j;
    v_token = token;
    v_token_ref = None;
    v_ca_file = string_opt ctx "ca_file" j;
    v_metrics_url = string_opt ctx "metrics_url" j;
    v_workload = workload;
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
  let k =
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
  in
  (* Misconfiguration is reported now, not on the first restart during an incident. *)
  if not (K8s_names.valid_dns_name k.k_namespace) then
    invalid "fleet.kubernetes.namespace %S is not a valid namespace name" k.k_namespace;
  let api = Uri.of_string k.k_api in
  let https =
    match (Option.map String.lowercase_ascii (Uri.scheme api), Uri.host api) with
    | Some "https", Some h when h <> "" -> true
    | Some "http", Some h when is_loopback_host h -> false
    | _ ->
        invalid
          "fleet.kubernetes.api must be https:// (or http:// on a loopback host, e.g. \
           kubectl proxy): the service-account token would be sent in cleartext"
  in
  if not (Sys.file_exists k.k_token_file) then
    invalid "fleet.kubernetes.token_file %s does not exist" k.k_token_file;
  if https && not (Sys.file_exists k.k_ca_file) then
    invalid "fleet.kubernetes.ca_file %s does not exist" k.k_ca_file;
  k

let top_level_keys =
  [
    "listen";
    "public_url";
    "allowed_origins";
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

(* ---- placeholders ---- *)

type segment = Lit of string | Placeholder of string * string  (** scheme, reference *)

let known_schemes = [ "env"; "vault"; "aws-sm"; "gcp-sm" ]

(* Splits a string into literal text and ${scheme:reference} placeholders; [$${] is a
   literal [${] and an unterminated [${] is kept as text. *)
let parse_template s : (segment list, string) result =
  let n = String.length s in
  let b = Buffer.create n in
  let acc = ref [] in
  let flush () =
    if Buffer.length b > 0 then (
      acc := Lit (Buffer.contents b) :: !acc;
      Buffer.clear b)
  in
  let rec go i =
    if i >= n then Ok ()
    else if i + 2 < n && s.[i] = '$' && s.[i + 1] = '$' && s.[i + 2] = '{' then (
      Buffer.add_string b "${";
      go (i + 3))
    else if i + 1 < n && s.[i] = '$' && s.[i + 1] = '{' then
      match String.index_from_opt s (i + 2) '}' with
      | None ->
          Buffer.add_string b (String.sub s i (n - i));
          Ok ()
      | Some j -> (
          let inner = String.sub s (i + 2) (j - i - 2) in
          match String.index_opt inner ':' with
          | None ->
              Error
                (Printf.sprintf
                   "placeholder ${%s} needs a scheme (env:, vault:, aws-sm:, gcp-sm:)"
                   inner)
          | Some k ->
              flush ();
              acc :=
                Placeholder
                  ( String.sub inner 0 k,
                    String.sub inner (k + 1) (String.length inner - k - 1) )
                :: !acc;
              go (j + 1))
    else (
      Buffer.add_char b s.[i];
      go (i + 1))
  in
  match go 0 with
  | Error m -> Error m
  | Ok () ->
      flush ();
      Ok (List.rev !acc)

let rec map_strings f = function
  | `String s when String.contains s '$' -> `String (f s)
  | `Assoc l -> `Assoc (List.map (fun (k, v) -> (k, map_strings f v)) l)
  | `List l -> `List (List.map (map_strings f) l)
  | x -> x

let rec iter_strings f = function
  | `String s when String.contains s '$' -> f s
  | `Assoc l -> List.iter (fun (_, v) -> iter_strings f v) l
  | `List l -> List.iter (iter_strings f) l
  | _ -> ()

(** Replaces [${env:NAME}] and provider placeholders in every string leaf of [j]. *)
let substitute ~(resolve : scheme:string -> reference:string -> (string, string) result) j
    =
  map_strings
    (fun s ->
      match parse_template s with
      | Error m -> raise (Invalid m)
      | Ok segs ->
          String.concat ""
            (List.map
               (function
                 | Lit l -> l
                 | Placeholder (scheme, reference) -> (
                     match resolve ~scheme ~reference with
                     | Ok v -> v
                     | Error m -> invalid "cannot resolve ${%s:%s}: %s" scheme reference m
                     ))
               segs))
    j

(** Checks every placeholder in [j] without resolving it: syntax, a known scheme, and
    [check ~scheme ~reference] (e.g. the provider is configured). *)
let check_placeholders ?(check = fun ~scheme:_ ~reference:_ -> Ok ()) ctx j =
  iter_strings
    (fun s ->
      match parse_template s with
      | Error m -> invalid "%s: %s" ctx m
      | Ok segs ->
          List.iter
            (function
              | Lit _ -> ()
              | Placeholder (scheme, reference) -> (
                  if not (List.mem scheme known_schemes) then
                    invalid "%s: unknown secret scheme in ${%s:%s}" ctx scheme reference;
                  match check ~scheme ~reference with
                  | Ok () -> ()
                  | Error m -> invalid "%s: ${%s:%s}: %s" ctx scheme reference m))
            segs)
    j

(** Top-level sections whose placeholders are resolved on demand ({!resolve}), not at
    load. [secrets] is read by the secrets provider itself. *)
let lazy_sections = [ "opa"; "integrations"; "signals" ]

let env_resolver ?(env = Sys.getenv_opt) () ~scheme ~reference =
  match scheme with
  | "env" -> (
      match env reference with
      | Some v -> Ok v
      | None -> Error "environment variable is not set")
  | s -> Error (Printf.sprintf "secret provider %s is not configured in secrets" s)

let env_only_resolver ?env () : secret_resolver =
 fun ~scheme ~reference -> Lwt.return (env_resolver ?env () ~scheme ~reference)

(** Expands the placeholders in [s] (typically a string from [opa], [integrations] or
    [signals]) through the configured providers. Provider values are cached for at most
    five minutes, so a rotated secret is picked up without a restart. Errors name the
    placeholder, never a secret value. *)
let resolve (t : t) s : (string, string) result Lwt.t =
  let open Lwt.Syntax in
  match parse_template s with
  | Error m -> Lwt.return (Error m)
  | Ok segs ->
      let rec go acc = function
        | [] -> Lwt.return (Ok (String.concat "" (List.rev acc)))
        | Lit l :: rest -> go (l :: acc) rest
        | Placeholder (scheme, reference) :: rest -> (
            let* r = t.resolver ~scheme ~reference in
            match r with
            | Ok v -> go (v :: acc) rest
            | Error m ->
                Lwt.return
                  (Error (Printf.sprintf "cannot resolve ${%s:%s}: %s" scheme reference m))
            )
      in
      go [] segs

(** {!resolve} applied to every string in [j] (e.g. the whole [opa] block before it is
    handed to a library that expects plain values). The first failure is returned. *)
let resolve_json (t : t) (j : Yojson.Safe.t) : (Yojson.Safe.t, string) result Lwt.t =
  let open Lwt.Syntax in
  let rec go (j : Yojson.Safe.t) : (Yojson.Safe.t, string) result Lwt.t =
    match j with
    | `String s -> (
        let+ r = resolve t s in
        match r with Ok v -> Ok (`String v) | Error m -> Error m)
    | `List l ->
        let+ r = all l in
        Result.map (fun l -> `List l) r
    | `Assoc kv ->
        let+ r = all (List.map snd kv) in
        Result.map (fun vs -> `Assoc (List.combine (List.map fst kv) vs)) r
    | j -> Lwt.return (Ok j)
  and all l =
    match l with
    | [] -> Lwt.return (Ok [])
    | x :: rest -> (
        let* x = go x in
        match x with
        | Error m -> Lwt.return (Error m)
        | Ok x ->
            let+ rest = all rest in
            Result.map (fun rest -> x :: rest) rest)
  in
  go j

(** Checks that dev mode is safe for this configuration: dev must be the only auth method
    and [listen] must be a loopback address (127.0.0.0/8, ::1, localhost). Called by
    [of_json] and again by the server after command-line overrides. *)
let validate_dev (c : t) : (unit, string) result =
  match c.auth.dev with
  | None -> Ok ()
  | Some _ -> (
      if c.auth.oidc <> [] || Option.is_some c.auth.proxy || c.auth.tokens <> [] then
        Error
          "auth.dev cannot be combined with oidc, proxy or tokens (dev mode signs every \
           request in as the dev user)"
      else
        match listen_host c.listen with
        | Error m -> Error m
        | Ok h when is_loopback_host h -> Ok ()
        | Ok h ->
            Error
              (Printf.sprintf
                 "auth.dev requires a loopback listen address (127.0.0.1, ::1 or \
                  localhost), not %S"
                 h))

(** Builds a configuration from a document whose typed sections are already substituted.
    [raw] (default [j]) is the document as written; [resolver] serves {!resolve} (default:
    [${env:...}] only). *)
let of_json ?file ?raw ?(resolver = env_only_resolver ()) (j : Yojson.Safe.t) : t =
  check_keys "config" top_level_keys j;
  let sub name = Option.value (field_opt name j) ~default:`Null in
  List.iter (fun k -> check_placeholders k (sub k)) lazy_sections;
  let fleet = sub "fleet" in
  check_keys "fleet"
    [
      "poll_seconds";
      "kubernetes";
      "probe_timeout_seconds";
      "history_size";
      "max_concurrent_probes";
    ]
    fleet;
  let data = sub "data" in
  check_keys "data" [ "exceptions" ] data;
  let public_url = string_opt "config" "public_url" j in
  let origin_of ctx s =
    match parse_origin s with
    | Some o -> o
    | None -> invalid "%s: %S is not an origin (http(s)://host[:port], no path)" ctx s
  in
  let allowed_origins =
    Option.to_list (Option.map (origin_of "public_url") public_url)
    @ List.map (origin_of "allowed_origins") (strings_opt "config" "allowed_origins" j)
  in
  let cfg =
    {
      file;
      listen = Option.value (string_opt "config" "listen" j) ~default:"127.0.0.1:8090";
      public_url;
      allowed_origins;
      environment = environment (sub "environment");
      state_dir =
        Option.value (string_opt "config" "state_dir" j) ~default:"./console-state";
      frontend_dir = string_opt "config" "frontend_dir" j;
      auth = auth (sub "auth");
      verifiers =
        (* tokens written with a placeholder keep the template, re-resolved per poll *)
        (let refs =
           List.map
             (fun v ->
               match field_opt "token" v with
               | Some (`String s) -> (
                   match parse_template s with
                   | Ok segs
                     when List.exists (function Placeholder _ -> true | _ -> false) segs
                     ->
                       Some s
                   | _ -> None)
               | _ -> None)
             (try list_opt "config" "verifiers" (Option.value raw ~default:j)
              with Invalid _ -> [])
         in
         List.mapi
           (fun i v ->
             let v = verifier i v in
             match List.nth_opt refs i with
             | Some (Some r) when v.v_token <> None -> { v with v_token_ref = Some r }
             | _ -> v)
           (list_opt "config" "verifiers" j));
      fleet_poll_seconds = int_opt "fleet" "poll_seconds" fleet ~default:30;
      fleet_probe_timeout =
        float_of_int
          (int_range "fleet" "probe_timeout_seconds" fleet ~default:5 ~min:1 ~max:60);
      fleet_history_size =
        int_range "fleet" "history_size" fleet ~default:120 ~min:2 ~max:10_000;
      fleet_max_concurrent =
        int_range "fleet" "max_concurrent_probes" fleet ~default:16 ~min:1 ~max:1024;
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
      raw = Option.value raw ~default:j;
      resolver;
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
  (match validate_dev cfg with Ok () -> () | Error m -> raise (Invalid m));
  cfg

(** How long provider values fetched by {!resolve} are cached. *)
let secret_ttl_seconds = 300.

(* A resolver for {!resolve}: env directly; providers through a Secrets.t that is
   replaced every [ttl] seconds, so rotated secrets are picked up. *)
let lazy_resolver ~env ?(ttl = secret_ttl_seconds) ?(now = Unix.gettimeofday) secrets :
    secret_resolver =
  let current = ref None in
  fun ~scheme ~reference ->
    if scheme = "env" then Lwt.return (env_resolver ~env () ~scheme ~reference)
    else
      let s =
        match !current with
        | Some (at, s) when now () -. at < ttl -> s
        | _ ->
            let s = Haltsql_cloud.Secrets.create ~env secrets in
            current := Some (now (), s);
            s
      in
      Haltsql_cloud.Secrets.resolve s ~scheme ~reference

(** Loads a file. Placeholders in the typed sections are resolved now (providers through
    the [secrets] section with {!Haltsql_cloud.Secrets}, concurrently, inside Lwt);
    placeholders in [opa], [integrations] and [signals] are validated (syntax, scheme,
    provider configured, env variable set) and left for {!resolve}. *)
let load ?(env = Sys.getenv_opt) file : (t, string) result Lwt.t =
  let open Lwt.Syntax in
  match Haltsql.Docload.of_file file with
  | Error errs ->
      Lwt.return (Error (String.concat "; " (List.map Haltsql.Load_error.to_string errs)))
  | Ok doc ->
      let is_eager k = not (List.mem k ("secrets" :: lazy_sections)) in
      let eager_doc =
        match doc with
        | `Assoc l -> `Assoc (List.filter (fun (k, _) -> is_eager k) l)
        | d -> d
      in
      let provider_refs text =
        List.filter
          (fun (s, _) -> s <> "env")
          (Haltsql_cloud.Secrets.scan_placeholders text)
      in
      let eager_refs = provider_refs (Yojson.Safe.to_string eager_doc) in
      let all_refs = provider_refs (Yojson.Safe.to_string doc) in
      Lwt.catch
        (fun () ->
          let secrets =
            if all_refs = [] then Haltsql.Config.no_secrets
            else
              match Haltsql.Config.secrets_of_json ~file ~env doc with
              | Error errs ->
                  raise
                    (Invalid
                       (String.concat "; " (List.map Haltsql.Load_error.to_string errs)))
              | Ok s -> s
          in
          (* Eager values come from a short-lived cache, dropped after load. *)
          let* eager =
            if eager_refs = [] then Lwt.return (env_resolver ~env ())
            else
              let s = Haltsql_cloud.Secrets.create ~env secrets in
              let* () = Haltsql_cloud.Secrets.prefetch s eager_refs in
              let cached = Haltsql_cloud.Secrets.cached_resolver s in
              Lwt.return (fun ~scheme ~reference ->
                  if scheme = "env" then env_resolver ~env () ~scheme ~reference
                  else cached ~scheme ~reference)
          in
          let check ~scheme ~reference =
            match scheme with
            | "env" ->
                if Option.is_some (env reference) then Ok ()
                else Error "environment variable is not set"
            | "vault" when secrets.vault = None -> Error "secrets.vault is not configured"
            | "aws-sm" when secrets.aws = None -> Error "secrets.aws is not configured"
            | _ -> Ok ()
          in
          let substituted =
            match doc with
            | `Assoc l ->
                `Assoc
                  (List.map
                     (fun (k, v) ->
                       if is_eager k then (k, substitute ~resolve:eager v)
                       else (
                         if k <> "secrets" then check_placeholders ~check k v;
                         (k, v)))
                     l)
            | d -> d
          in
          Lwt.return
            (Ok
               (of_json ~file ~raw:doc ~resolver:(lazy_resolver ~env secrets) substituted)))
        (function Invalid m -> Lwt.return (Error m) | e -> Lwt.fail e)
