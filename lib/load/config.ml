(* Runtime configuration documents ([kind: Config]); see config.mli and
   PLAN.md §6.6. *)

open Haltsql_core

type token = { token_name : string; token_sha256 : string; token_policy : string }
type audit_sink = Audit_stdout | Audit_file of string
type pem = Pem_path of string | Pem_inline of string
type client_auth = Client_auth_none | Client_auth_optional | Client_auth_required
type tls_version = Tls_1_2 | Tls_1_3

type tls = {
  cert : pem;
  key : pem;
  client_ca : pem option;
  client_auth : client_auth;
  min_version : tls_version;
}

type jwt_alg = RS256 | RS384 | RS512 | PS256 | ES256 | ES384 | EdDSA

let jwt_algs =
  [
    ("RS256", RS256);
    ("RS384", RS384);
    ("RS512", RS512);
    ("PS256", PS256);
    ("ES256", ES256);
    ("ES384", ES384);
    ("EdDSA", EdDSA);
  ]

let string_of_jwt_alg a = fst (List.find (fun (_, b) -> b = a) jwt_algs)

type oidc_policy =
  | Oidc_pinned of string
  | Oidc_from_claim of { claim : string; allowed : string list }

type claim_match = Claim_one of string | Claim_all of string list

type oidc_provider = {
  oidc_name : string;
  issuer : string;
  audiences : string list;
  jwks_uri : string option;
  algorithms : jwt_alg list;
  leeway_seconds : int;
  jwks_cache_seconds : int;
  oidc_policy : oidc_policy;
  context_claims : (string * string) list;
  required_claims : (string * claim_match) list;
  oidc_request_context_fields : string list;
  allow_insecure_http : bool;
}

type mtls_match = Spiffe_id of string | Subject_cn of string

type mtls_identity = {
  mtls_match : mtls_match;
  mtls_policy : string;
  mtls_context : Context.t;
  mtls_request_context_fields : string list;
}

type otlp = {
  otlp_endpoint : string;
  otlp_headers : (string * string) list;
  service_name : string;
  otlp_traces : bool;
  otlp_metrics : bool;
  export_interval_seconds : int;
  timeout_seconds : int;
}

type on_error = Fail_closed | Buffer
type batch = { max_records : int; max_seconds : int }
type object_lock_mode = Governance | Compliance
type object_lock = { lock_mode : object_lock_mode; retain_days : int }

type s3_credentials =
  | S3_env
  | S3_static of {
      access_key_id : string;
      secret_access_key : string;
      session_token : string option;
    }
  | S3_web_identity
  | S3_instance

type s3_sink = {
  s3_bucket : string;
  s3_prefix : string;
  s3_region : string;
  s3_endpoint : string option;
  s3_object_lock : object_lock option;
  s3_batch : batch;
  s3_credentials : s3_credentials;
  s3_spool_dir : string option;
}

type gcs_credentials = Gcs_metadata | Gcs_service_account_file of string

type gcs_sink = {
  gcs_bucket : string;
  gcs_prefix : string;
  gcs_batch : batch;
  gcs_credentials : gcs_credentials;
  gcs_spool_dir : string option;
}

type sink_kind =
  | Sink_stdout
  | Sink_file of string
  | Sink_s3 of s3_sink
  | Sink_gcs of gcs_sink

type sink = { sink : sink_kind; on_error : on_error }

type vault_auth =
  | Vault_token of string
  | Vault_kubernetes of { role : string; jwt_path : string; mount : string }
  | Vault_approle of { role_id : string; secret_id : string; mount : string }

type vault = {
  vault_address : string;
  vault_namespace : string option;
  vault_auth : vault_auth;
  vault_ca_file : string option;
}

type aws_secrets = { aws_region : string; aws_endpoint : string option }
type gcp_secrets = { gcp_project : string option; gcp_endpoint : string option }

type secrets = {
  vault : vault option;
  aws : aws_secrets option;
  gcp : gcp_secrets option;
}

let no_secrets = { vault = None; aws = None; gcp = None }

type public_key = Key_path of string | Key_pem of string | Key_base64 of string

type bundle_ref = {
  bundle_path : string;
  public_keys : public_key list;
  name_prefix : string option;
}

type t = {
  listen : string;
  tls_cert : string option;
  tls_key : string option;
  tokens : token list;
  allow_unauthenticated : bool;
  policies : (string * Policy.t) list;
  policy_files : string list;
  default_policy : string option;
  reload_watch : bool;
  audit_sinks : audit_sink list;
  log_raw_sql : bool;
  log_level : string;
  log_format : string;
  metrics : bool;
  max_request_bytes : int;
  tls : tls option;
  oidc : oidc_provider list;
  mtls : mtls_identity list;
  otlp : otlp option;
  sinks : sink list;
  secrets : secrets;
  policy_bundles : bundle_ref list;
}

let default =
  {
    listen = "127.0.0.1:8080";
    tls_cert = None;
    tls_key = None;
    tokens = [];
    allow_unauthenticated = false;
    policies = [];
    policy_files = [];
    default_policy = None;
    reload_watch = false;
    audit_sinks = [ Audit_stdout ];
    log_raw_sql = false;
    log_level = "info";
    log_format = "json";
    metrics = true;
    max_request_bytes = 1_048_576;
    tls = None;
    oidc = [];
    mtls = [];
    otlp = None;
    sinks = [ { sink = Sink_stdout; on_error = Fail_closed } ];
    secrets = no_secrets;
    policy_bundles = [];
  }

type resolver = scheme:string -> reference:string -> (string, string) result

let max_secret_file_bytes = 1024 * 1024
let log_levels = [ "debug"; "info"; "warn"; "error" ]
let log_formats = [ "json"; "text" ]
let default_audit_prefix = "haltsql/audit/"
let default_k8s_jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"

(* ---------------------------------------------------------------------- *)
(* Placeholders. "$${" is a literal "${".                                 *)

let valid_env_name s =
  s <> ""
  && (match s.[0] with 'A' .. 'Z' | 'a' .. 'z' | '_' -> true | _ -> false)
  && String.for_all (fun c -> Policy_impl.is_word_char c) s

let trim_newline s =
  let n = String.length s in
  if n >= 2 && String.sub s (n - 2) 2 = "\r\n" then String.sub s 0 (n - 2)
  else if n >= 1 && s.[n - 1] = '\n' then String.sub s 0 (n - 1)
  else s

let has_ws_or_ctl s = String.exists (fun c -> c <= ' ' || c = '\127') s

(* Where provider placeholders ([vault], [aws-sm], [gcp-sm]) may be used. *)
type provider =
  | In_secrets  (** inside the secrets section: forbidden *)
  | No_resolver
  | Resolver of resolver

let provider_schemes = [ "vault"; "aws-sm"; "gcp-sm" ]

(* Validates the reference syntax of a provider placeholder. *)
let check_reference scheme r =
  let split = String.index_opt r '#' in
  let id, field =
    match split with
    | None -> (r, None)
    | Some i -> (String.sub r 0 i, Some (String.sub r (i + 1) (String.length r - i - 1)))
  in
  let expected =
    if scheme = "vault" then "${vault:<path>#<field>}"
    else Printf.sprintf "${%s:<secret>[#<json-key>]}" scheme
  in
  let bad =
    id = "" || has_ws_or_ctl r
    || (match field with Some f -> f = "" || String.contains f '#' | None -> false)
    || (scheme = "vault" && field = None)
  in
  if bad then
    Error (Printf.sprintf "invalid ${%s:%s} reference (expected %s)" scheme r expected)
  else Ok ()

let resolve_string ctx path ~env ~base_dir ~provider s =
  let n = String.length s in
  let b = Buffer.create n in
  let ok = ref true in
  let fail m =
    Dec.error ctx path m;
    ok := false
  in
  let rec go i =
    if i >= n then ()
    else if i + 2 < n && s.[i] = '$' && s.[i + 1] = '$' && s.[i + 2] = '{' then begin
      Buffer.add_string b "${";
      go (i + 3)
    end
    else if i + 1 < n && s.[i] = '$' && s.[i + 1] = '{' then (
      match String.index_from_opt s (i + 2) '}' with
      | None -> fail "unterminated placeholder (missing '}')"
      | Some j ->
          let inner = String.sub s (i + 2) (j - i - 2) in
          let scheme, rest =
            match String.index_opt inner ':' with
            | Some k ->
                ( String.sub inner 0 k,
                  String.sub inner (k + 1) (String.length inner - k - 1) )
            | None -> ("", inner)
          in
          (match scheme with
          | "env" -> (
              let name = rest in
              if not (valid_env_name name) then
                fail (Printf.sprintf "invalid environment variable name %S" name)
              else
                match env name with
                | Some v -> Buffer.add_string b v
                | None -> fail (Printf.sprintf "environment variable %s is not set" name))
          | "file" -> (
              let f = rest in
              if f = "" then fail "empty file path in ${file:...}"
              else
                let abs = Dec.absolute ?base_dir f in
                match Docpos.read_file ~limit:max_secret_file_bytes abs with
                | Ok contents -> Buffer.add_string b (trim_newline contents)
                | Error errs ->
                    let m =
                      match errs with
                      | e :: _ -> e.Load_error.message
                      | [] -> "cannot read file"
                    in
                    fail (Printf.sprintf "${file:%s}: %s" f m))
          | sc when List.mem sc provider_schemes -> (
              match check_reference sc rest with
              | Error m -> fail m
              | Ok () -> (
                  match provider with
                  | In_secrets ->
                      fail
                        (Printf.sprintf
                           "${%s:...} cannot be used inside the secrets section (it \
                            configures the secret providers); use ${env:NAME} or \
                            ${file:/path}"
                           sc)
                  | No_resolver ->
                      fail
                        (Printf.sprintf
                           "secret provider not configured: ${%s:%s} needs a secret \
                            resolver"
                           sc rest)
                  | Resolver r -> (
                      match r ~scheme:sc ~reference:rest with
                      | Ok v -> Buffer.add_string b v
                      | Error m -> fail (Printf.sprintf "${%s:%s}: %s" sc rest m))))
          | _ ->
              fail
                (Printf.sprintf
                   "unknown placeholder ${%s} (Config supports ${env:NAME}, \
                    ${file:/path}, ${vault:path#field}, ${aws-sm:id[#key]} and \
                    ${gcp-sm:name[#key]})"
                   inner));
          go (j + 1))
    else begin
      Buffer.add_char b s.[i];
      go (i + 1)
    end
  in
  go 0;
  if !ok then Buffer.contents b else s

(* Resolve placeholders everywhere except inside inline policies, which must
   not use them (the policy decoder reports them). The secrets section is
   resolved without provider placeholders. *)
let resolve_tree ctx ~env ~base_dir ~provider (j : Yojson.Safe.t) =
  let rec walk path rel provider (j : Yojson.Safe.t) : Yojson.Safe.t =
    match j with
    | `String s -> `String (resolve_string ctx path ~env ~base_dir ~provider s)
    | `List l ->
        `List
          (List.mapi
             (fun i x -> walk (Lpath.idx path i) (Lpath.Idx i :: rel) provider x)
             l)
    | `Assoc kvs ->
        `Assoc
          (List.map
             (fun (k, v) ->
               match (k, rel) with
               | "inline", [ Lpath.Idx _; Lpath.Key "policies" ] -> (k, v)
               | "secrets", [] -> (k, walk (Lpath.key path k) [ Lpath.Key k ] In_secrets v)
               | _ -> (k, walk (Lpath.key path k) (Lpath.Key k :: rel) provider v))
             kvs)
    | j -> j
  in
  walk Lpath.root [] provider j

(* ---------------------------------------------------------------------- *)
(* Validation helpers                                                     *)

let valid_listen s =
  let host, port =
    if String.length s > 0 && s.[0] = '[' then
      match String.index_opt s ']' with
      | Some i when i + 1 < String.length s && s.[i + 1] = ':' ->
          (String.sub s 1 (i - 1), String.sub s (i + 2) (String.length s - i - 2))
      | _ -> ("", "")
    else
      match String.rindex_opt s ':' with
      | Some i -> (String.sub s 0 i, String.sub s (i + 1) (String.length s - i - 1))
      | None -> ("", "")
  in
  host <> ""
  && (not (String.contains host ' '))
  && ((String.length s > 0 && s.[0] = '[') || not (String.contains host ':'))
  && port <> ""
  && String.for_all Docpos.is_digit port
  && String.length port <= 5
  &&
  let p = int_of_string port in
  p >= 1 && p <= 65535

let is_sha256_hex s =
  String.length s = 64
  && String.for_all (fun c -> Docpos.is_digit c || (c >= 'a' && c <= 'f')) s

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let contains_sub s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

type url = { scheme : string; host : string; query_or_fragment : bool }

let is_alnum c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')

let parse_url s : (url, string) result =
  let expected = "expected an absolute http:// or https:// URL" in
  let n = String.length s in
  if s = "" then Error "must not be empty"
  else if has_ws_or_ctl s then Error "must not contain whitespace or control characters"
  else
    match String.index_opt s ':' with
    | None -> Error expected
    | Some i when not (i + 3 <= n && String.sub s i 3 = "://") -> Error expected
    | Some i -> (
        let scheme = String.sub s 0 i in
        let rest = String.sub s (i + 3) (n - i - 3) in
        let rn = String.length rest in
        let rec auth_end k =
          if k >= rn then k
          else match rest.[k] with '/' | '?' | '#' -> k | _ -> auth_end (k + 1)
        in
        let ae = auth_end 0 in
        let auth = String.sub rest 0 ae in
        let tail = String.sub rest ae (rn - ae) in
        if scheme <> "http" && scheme <> "https" then Error expected
        else if String.contains auth '@' then
          Error "must not contain credentials (user@host)"
        else
          let host, port =
            if String.length auth > 0 && auth.[0] = '[' then
              match String.index_opt auth ']' with
              | None -> (None, None)
              | Some j ->
                  let h = String.sub auth 1 (j - 1) in
                  let after = String.sub auth (j + 1) (String.length auth - j - 1) in
                  if after = "" then (Some h, None)
                  else if after.[0] = ':' then
                    (Some h, Some (String.sub after 1 (String.length after - 1)))
                  else (None, None)
            else
              match String.split_on_char ':' auth with
              | [ h ] -> (Some h, None)
              | [ h; p ] -> (Some h, Some p)
              | _ -> (None, None)
          in
          let host_ok h =
            h <> ""
            && String.for_all
                 (fun c -> is_alnum c || c = '.' || c = '-' || c = '_' || c = ':')
                 h
          in
          let port_ok = function
            | None -> true
            | Some p ->
                p <> ""
                && String.length p <= 5
                && String.for_all Docpos.is_digit p
                &&
                let v = int_of_string p in
                v >= 1 && v <= 65535
          in
          match host with
          | Some h when host_ok h && port_ok port ->
              Ok
                {
                  scheme;
                  host = String.lowercase_ascii h;
                  query_or_fragment = String.contains tail '?' || String.contains tail '#';
                }
          | _ -> Error "invalid host or port in URL")

let is_loopback host =
  host = "localhost" || host = "::1" || starts_with ~prefix:"127." host

(* [http]: what to do with plain http. *)
let url_j ?(no_query = false) ctx ~(http : [ `Allow | `Loopback_only | `Deny of string ])
    path v =
  match Dec.string ctx path v with
  | None -> None
  | Some s -> (
      match parse_url s with
      | Error m ->
          Dec.error ctx path (Printf.sprintf "invalid URL %S: %s" s m);
          None
      | Ok u ->
          let http_ok =
            u.scheme = "https"
            ||
            match http with
            | `Allow -> true
            | `Loopback_only -> is_loopback u.host
            | `Deny _ -> false
          in
          if not http_ok then begin
            Dec.error ctx path
              (match http with
              | `Deny hint -> Printf.sprintf "must use https (got %S); %s" s hint
              | _ ->
                  Printf.sprintf
                    "must use https (got %S); plain http is only allowed for loopback \
                     addresses"
                    s);
            None
          end
          else if no_query && u.query_or_fragment then begin
            Dec.error ctx path "must not contain a query or fragment";
            None
          end
          else Some s)

let valid_ident s =
  s <> ""
  && String.length s <= 128
  && (match s.[0] with 'a' .. 'z' | 'A' .. 'Z' | '_' -> true | _ -> false)
  && String.for_all Policy_impl.is_word_char s

let ident_j ctx path v =
  match Dec.string ctx path v with
  | Some s when valid_ident s -> Some s
  | Some s ->
      Dec.error ctx path
        (Printf.sprintf
           "invalid context field %S (letters, digits and '_', not starting with a digit)"
           s);
      None
  | None -> None

let check_ident_key ctx path k =
  if valid_ident k then true
  else begin
    Dec.error ctx (Lpath.key path k)
      (Printf.sprintf
         "invalid context field %S (letters, digits and '_', not starting with a digit)" k);
    false
  end

let valid_claim_path s =
  s <> ""
  && String.length s <= 512
  && (not (has_ws_or_ctl s))
  && s.[0] <> '.'
  && s.[String.length s - 1] <> '.'
  && not (contains_sub s "..")

let claim_j ctx path v =
  match Dec.string ctx path v with
  | Some s when valid_claim_path s -> Some s
  | Some s ->
      Dec.error ctx path
        (Printf.sprintf
           "invalid claim path %S (non-empty, no whitespace, no empty '.' segments)" s);
      None
  | None -> None

let check_claim_key ctx path k =
  if valid_claim_path k then true
  else begin
    Dec.error ctx (Lpath.key path k)
      (Printf.sprintf "invalid claim name %S (non-empty, no whitespace)" k);
    false
  end

(* A list of unique strings; duplicates are reported at their index. *)
let unique_list ctx ~what f path v =
  match Dec.list ctx path v with
  | None -> None
  | Some l ->
      let seen = Hashtbl.create 8 in
      Some
        (List.filter_map Fun.id
           (List.mapi
              (fun i x ->
                let p = Lpath.idx path i in
                match f p x with
                | Some s when Hashtbl.mem seen s ->
                    Dec.error ctx p (Printf.sprintf "duplicate %s %S" what s);
                    None
                | Some s ->
                    Hashtbl.add seen s ();
                    Some s
                | None -> None)
              l))

let non_empty_list ctx path = function
  | Some [] ->
      Dec.error ctx path "must not be empty";
      None
  | x -> x

let policy_name_j ctx path v =
  match Dec.non_empty_string ctx path v with
  | Some s when Policy_impl.valid_name s -> Some s
  | Some s ->
      Dec.error ctx path
        (Printf.sprintf
           "invalid policy name %S (1-128 characters: letters, digits, '.', '_', '-')" s);
      None
  | None -> None

let pem_of ?base_dir s =
  if starts_with ~prefix:"-----BEGIN" s then Pem_inline s
  else Pem_path (Dec.absolute ?base_dir s)

(* ---------------------------------------------------------------------- *)
(* Decoders                                                               *)

let listen_j ctx path j =
  match Dec.string ctx path j with
  | Some s when valid_listen s -> Some s
  | Some s ->
      Dec.error ctx path
        (Printf.sprintf
           "invalid listen address %S (expected host:port, e.g. 127.0.0.1:8080)" s);
      None
  | None -> None

let token_j ctx path j =
  match Dec.obj ctx path ~keys:[ "name"; "token_sha256"; "policy" ] j with
  | None -> None
  | Some kvs -> (
      let name = Dec.req ctx kvs path "name" (Dec.non_empty_string ctx) in
      let hash =
        Dec.req ctx kvs path "token_sha256" (fun p v ->
            match Dec.string ctx p v with
            | Some h when is_sha256_hex h -> Some h
            | Some _ ->
                Dec.error ctx p
                  "must be the SHA-256 of the token as 64 lower-case hex characters";
                None
            | None -> None)
      in
      let policy = Dec.req ctx kvs path "policy" (Dec.non_empty_string ctx) in
      match (name, hash, policy) with
      | Some token_name, Some token_sha256, Some token_policy ->
          Some { token_name; token_sha256; token_policy }
      | _ -> None)

(* server.tls -> (legacy cert, legacy key, typed tls) *)
let tls_j ctx ~base_dir p v =
  match
    Dec.obj ctx p ~keys:[ "cert"; "key"; "client_ca"; "client_auth"; "min_version" ] v
  with
  | None -> None
  | Some t ->
      let cert = Dec.opt t p "cert" (Dec.non_empty_string ctx) in
      let key = Dec.opt t p "key" (Dec.non_empty_string ctx) in
      let client_ca = Dec.opt t p "client_ca" (Dec.non_empty_string ctx) in
      let client_auth =
        Dec.opt t p "client_auth"
          (Dec.enum ctx
             ~values:
               [
                 ("none", Client_auth_none);
                 ("optional", Client_auth_optional);
                 ("required", Client_auth_required);
               ])
      in
      let min_version =
        Dec.opt t p "min_version" (fun p -> function
          | `String "1.2" | `Float 1.2 -> Some Tls_1_2
          | `String "1.3" | `Float 1.3 -> Some Tls_1_3
          | j ->
              Dec.error ctx p
                (Printf.sprintf "invalid value %s (expected one of: \"1.2\", \"1.3\")"
                   (Yojson.Safe.to_string j));
              None)
      in
      (match (cert, key) with
      | Some _, None -> Dec.error ctx (Lpath.key p "key") "required when tls.cert is set"
      | None, Some _ -> Dec.error ctx (Lpath.key p "cert") "required when tls.key is set"
      | None, None ->
          if
            Dec.field t "client_ca" <> None
            || Dec.field t "client_auth" <> None
            || Dec.field t "min_version" <> None
          then
            Dec.error ctx (Lpath.key p "cert")
              "required (with tls.key) when other server.tls options are set"
      | Some _, Some _ -> ());
      (match (client_auth, client_ca) with
      | Some (Client_auth_optional | Client_auth_required), None ->
          Dec.error ctx (Lpath.key p "client_auth")
            "client_auth optional/required needs server.tls.client_ca"
      | _ -> ());
      let typed =
        match (cert, key) with
        | Some c, Some k ->
            Some
              {
                cert = pem_of ?base_dir c;
                key = pem_of ?base_dir k;
                client_ca = Option.map (pem_of ?base_dir) client_ca;
                client_auth = Option.value ~default:Client_auth_none client_auth;
                min_version = Option.value ~default:Tls_1_2 min_version;
              }
        | _ -> None
      in
      Some (cert, key, typed)

let oidc_keys =
  [
    "name";
    "issuer";
    "audiences";
    "jwks_uri";
    "algorithms";
    "leeway_seconds";
    "jwks_cache_seconds";
    "policy";
    "policy_claim";
    "allowed_policies";
    "context_claims";
    "required_claims";
    "request_context_fields";
    "allow_insecure_http";
  ]

let alg_j ctx p v =
  match v with
  | `String s when List.mem_assoc s jwt_algs -> Some (List.assoc s jwt_algs)
  | `String s when String.lowercase_ascii s = "none" ->
      Dec.error ctx p "algorithm \"none\" (unsigned tokens) is never accepted";
      None
  | `String s
    when String.length s >= 2 && String.uppercase_ascii (String.sub s 0 2) = "HS" ->
      Dec.error ctx p
        (Printf.sprintf
           "algorithm %S is not accepted: symmetric HMAC algorithms let anyone holding \
            the key mint tokens"
           s);
      None
  | `String s ->
      Dec.error ctx p
        (Printf.sprintf "invalid algorithm %S (expected one of: %s)" s
           (String.concat ", " (List.map fst jwt_algs)));
      None
  | j ->
      Dec.type_error ctx p "a string" j;
      None

(* Checks [fields] (request_context_fields) against [taken] keys; reports at
   each colliding index. *)
let check_collisions ctx path ~what fields taken =
  List.iteri
    (fun i f ->
      if List.mem f taken then
        Dec.error ctx (Lpath.idx path i)
          (Printf.sprintf "context field %S is already set by %s" f what))
    fields

let oidc_j ctx p v =
  match Dec.obj ctx p ~keys:oidc_keys v with
  | None -> None
  | Some o -> (
      let insecure =
        Option.value ~default:false (Dec.opt o p "allow_insecure_http" (Dec.bool ctx))
      in
      let http = `Deny "set allow_insecure_http: true only for local tests" in
      let http = if insecure then `Allow else http in
      let name = Dec.req ctx o p "name" (Dec.non_empty_string ctx) in
      let issuer = Dec.req ctx o p "issuer" (url_j ~no_query:true ctx ~http) in
      let audiences =
        non_empty_list ctx (Lpath.key p "audiences")
          (Dec.req ctx o p "audiences"
             (unique_list ctx ~what:"audience" (Dec.non_empty_string ctx)))
      in
      let jwks_uri = Dec.opt o p "jwks_uri" (url_j ctx ~http) in
      let algorithms =
        match
          Dec.opt o p "algorithms" (fun p v ->
              non_empty_list ctx p (Dec.list_of ctx p (alg_j ctx) v))
        with
        | Some l -> Some (Dec.dedup l)
        | None -> if Dec.field o "algorithms" = None then Some [ RS256; ES256 ] else None
      in
      let leeway =
        Option.value ~default:60
          (Dec.opt o p "leeway_seconds" (fun p v -> Dec.int ctx p ~min:0 ~max:300 v))
      in
      let cache =
        Option.value ~default:300
          (Dec.opt o p "jwks_cache_seconds" (fun p v ->
               Dec.int ctx p ~min:10 ~max:86400 v))
      in
      let pinned = Dec.opt o p "policy" (policy_name_j ctx) in
      let claim = Dec.opt o p "policy_claim" (claim_j ctx) in
      let allowed =
        Dec.opt o p "allowed_policies" (fun p v ->
            non_empty_list ctx p (unique_list ctx ~what:"policy" (policy_name_j ctx) p v))
      in
      let binding =
        match (Dec.field o "policy", Dec.field o "policy_claim") with
        | Some _, Some _ ->
            Dec.error ctx p "use either policy or policy_claim, not both";
            None
        | None, None ->
            Dec.error ctx p "needs policy (pinned) or policy_claim + allowed_policies";
            None
        | Some _, None ->
            if Dec.field o "allowed_policies" <> None then
              Dec.error ctx
                (Lpath.key p "allowed_policies")
                "only allowed with policy_claim";
            Option.map (fun n -> Oidc_pinned n) pinned
        | None, Some _ -> (
            if Dec.field o "allowed_policies" = None then
              Dec.error ctx
                (Lpath.key p "allowed_policies")
                "required when policy_claim is set";
            match (claim, allowed) with
            | Some claim, Some allowed -> Some (Oidc_from_claim { claim; allowed })
            | _ -> None)
      in
      let context_claims =
        Option.value ~default:[]
          (Dec.opt o p "context_claims" (fun p v ->
               Option.map
                 (List.filter_map (fun (k, cv) ->
                      if check_ident_key ctx p k then
                        Option.map (fun c -> (k, c)) (claim_j ctx (Lpath.key p k) cv)
                      else None))
                 (Dec.map ctx p v)))
      in
      let required_claims =
        Option.value ~default:[]
          (Dec.opt o p "required_claims" (fun p v ->
               Option.map
                 (List.filter_map (fun (k, cv) ->
                      if check_claim_key ctx p k then (
                        let kp = Lpath.key p k in
                        match cv with
                        | `List _ ->
                            Option.map
                              (fun l -> (k, Claim_all l))
                              (non_empty_list ctx kp
                                 (unique_list ctx ~what:"value" (Dec.non_empty_string ctx)
                                    kp cv))
                        | `String _ ->
                            Option.map
                              (fun s -> (k, Claim_one s))
                              (Dec.non_empty_string ctx kp cv)
                        | j ->
                            Dec.type_error ctx kp "a string or a list of strings" j;
                            None)
                      else None))
                 (Dec.map ctx p v)))
      in
      let rcf_path = Lpath.key p "request_context_fields" in
      let rcf =
        Option.value ~default:[]
          (Dec.opt o p "request_context_fields"
             (unique_list ctx ~what:"context field" (ident_j ctx)))
      in
      check_collisions ctx rcf_path ~what:"context_claims" rcf
        (List.map fst context_claims);
      match (name, issuer, audiences, algorithms, binding) with
      | Some oidc_name, Some issuer, Some audiences, Some algorithms, Some oidc_policy ->
          Some
            {
              oidc_name;
              issuer;
              audiences;
              jwks_uri;
              algorithms;
              leeway_seconds = leeway;
              jwks_cache_seconds = cache;
              oidc_policy;
              context_claims;
              required_claims;
              oidc_request_context_fields = rcf;
              allow_insecure_http = insecure;
            }
      | _ -> None)

let valid_spiffe_id s =
  let pre = "spiffe://" in
  starts_with ~prefix:pre s
  &&
  let rest = String.sub s (String.length pre) (String.length s - String.length pre) in
  let td, path =
    match String.index_opt rest '/' with
    | None -> (rest, "")
    | Some i -> (String.sub rest 0 i, String.sub rest i (String.length rest - i))
  in
  td <> ""
  && String.length s <= 2048
  && String.for_all
       (fun c ->
         (c >= 'a' && c <= 'z') || Docpos.is_digit c || c = '.' || c = '-' || c = '_')
       td
  && (path = ""
     ||
     let segs = List.tl (String.split_on_char '/' path) in
     List.for_all
       (fun seg ->
         seg <> "" && seg <> "." && seg <> ".."
         && String.for_all (fun c -> is_alnum c || c = '.' || c = '-' || c = '_') seg)
       segs)

let context_value_j ctx p (v : Yojson.Safe.t) : Context.value option =
  let scalar p = function
    | `String s -> Some s
    | `Int i -> Some (string_of_int i)
    | j ->
        Dec.type_error ctx p "a string or an integer" j;
        None
  in
  match v with
  | `List l ->
      let items = List.mapi (fun i x -> scalar (Lpath.idx p i) x) l in
      if List.mem None items then None
      else if items = [] then begin
        Dec.error ctx p "must not be empty";
        None
      end
      else Some (Context.Many (List.filter_map Fun.id items))
  | v -> Option.map (fun s -> Context.One s) (scalar p v)

let mtls_identity_j ctx p v =
  match
    Dec.obj ctx p
      ~keys:[ "spiffe_id"; "subject_cn"; "policy"; "context"; "request_context_fields" ]
      v
  with
  | None -> None
  | Some o -> (
      let m =
        match (Dec.field o "spiffe_id", Dec.field o "subject_cn") with
        | Some _, Some _ ->
            Dec.error ctx p "use either spiffe_id or subject_cn, not both";
            None
        | None, None ->
            Dec.error ctx p "needs spiffe_id or subject_cn";
            None
        | Some _, None ->
            Dec.opt o p "spiffe_id" (fun p v ->
                match Dec.string ctx p v with
                | Some s when valid_spiffe_id s -> Some (Spiffe_id s)
                | Some s ->
                    Dec.error ctx p
                      (Printf.sprintf
                         "invalid SPIFFE ID %S (expected spiffe://trust-domain/path, \
                          lower-case trust domain)"
                         s);
                    None
                | None -> None)
        | None, Some _ ->
            Dec.opt o p "subject_cn" (fun p v ->
                match Dec.non_empty_string ctx p v with
                | Some s when String.exists (fun c -> c < ' ' || c = '\127') s ->
                    Dec.error ctx p "must not contain control characters";
                    None
                | Some s -> Some (Subject_cn s)
                | None -> None)
      in
      let policy = Dec.req ctx o p "policy" (policy_name_j ctx) in
      let context =
        Option.value ~default:[]
          (Dec.opt o p "context" (fun p v ->
               Option.map
                 (List.filter_map (fun (k, cv) ->
                      if check_ident_key ctx p k then
                        Option.map
                          (fun x -> (k, x))
                          (context_value_j ctx (Lpath.key p k) cv)
                      else None))
                 (Dec.map ctx p v)))
      in
      let rcf =
        Option.value ~default:[]
          (Dec.opt o p "request_context_fields"
             (unique_list ctx ~what:"context field" (ident_j ctx)))
      in
      check_collisions ctx
        (Lpath.key p "request_context_fields")
        ~what:"the static context" rcf (List.map fst context);
      match (m, policy) with
      | Some mtls_match, Some mtls_policy ->
          Some
            {
              mtls_match;
              mtls_policy;
              mtls_context = Context.make context;
              mtls_request_context_fields = rcf;
            }
      | _ -> None)

(* RFC 7230 token characters for header names. *)
let valid_header_name s =
  s <> "" && String.for_all (fun c -> is_alnum c || String.contains "!#$%&'*+-.^_`|~" c) s

let otlp_j ctx p v =
  match
    Dec.obj ctx p
      ~keys:
        [
          "endpoint";
          "headers";
          "service_name";
          "traces";
          "metrics";
          "export_interval_seconds";
          "timeout_seconds";
        ]
      v
  with
  | None -> None
  | Some o -> (
      let endpoint = Dec.req ctx o p "endpoint" (url_j ctx ~http:`Allow) in
      let headers =
        Option.value ~default:[]
          (Dec.opt o p "headers" (fun p v ->
               Option.map
                 (List.filter_map (fun (k, hv) ->
                      let kp = Lpath.key p k in
                      if not (valid_header_name k) then begin
                        Dec.error ctx kp (Printf.sprintf "invalid HTTP header name %S" k);
                        None
                      end
                      else
                        match Dec.string ctx kp hv with
                        | Some s
                          when String.exists
                                 (fun c -> c = '\r' || c = '\n' || c = '\000')
                                 s ->
                            Dec.error ctx kp
                              "header value must not contain CR, LF or NUL characters";
                            None
                        | Some s -> Some (k, s)
                        | None -> None))
                 (Dec.map ctx p v)))
      in
      let service_name =
        Option.value ~default:"haltsql"
          (Dec.opt o p "service_name" (Dec.non_empty_string ctx))
      in
      let traces = Option.value ~default:true (Dec.opt o p "traces" (Dec.bool ctx)) in
      let metrics = Option.value ~default:true (Dec.opt o p "metrics" (Dec.bool ctx)) in
      let interval =
        Option.value ~default:15
          (Dec.opt o p "export_interval_seconds" (fun p v ->
               Dec.int ctx p ~min:1 ~max:3600 v))
      in
      let timeout =
        Option.value ~default:5
          (Dec.opt o p "timeout_seconds" (fun p v -> Dec.int ctx p ~min:1 ~max:300 v))
      in
      match endpoint with
      | Some otlp_endpoint ->
          Some
            {
              otlp_endpoint;
              otlp_headers = headers;
              service_name;
              otlp_traces = traces;
              otlp_metrics = metrics;
              export_interval_seconds = interval;
              timeout_seconds = timeout;
            }
      | None -> None)

let default_otlp endpoint =
  {
    otlp_endpoint = endpoint;
    otlp_headers = [];
    service_name = "haltsql";
    otlp_traces = true;
    otlp_metrics = true;
    export_interval_seconds = 15;
    timeout_seconds = 5;
  }

let batch_j ctx p v =
  match Dec.obj ctx p ~keys:[ "max_records"; "max_seconds" ] v with
  | None -> None
  | Some b ->
      let r =
        Dec.opt b p "max_records" (fun p v -> Dec.int ctx p ~min:1 ~max:100_000 v)
      in
      let s = Dec.opt b p "max_seconds" (fun p v -> Dec.int ctx p ~min:1 ~max:3600 v) in
      Some
        {
          max_records = Option.value ~default:500 r;
          max_seconds = Option.value ~default:10 s;
        }

let default_batch = { max_records = 500; max_seconds = 10 }

(* S3 bucket names: 3-63 of [a-z0-9.-], starting and ending alphanumeric.
   GCS additionally allows '_'. *)
let bucket_j ctx ~gcs p v =
  match Dec.string ctx p v with
  | None -> None
  | Some s ->
      let n = String.length s in
      let ok_char c =
        (c >= 'a' && c <= 'z')
        || Docpos.is_digit c || c = '.' || c = '-'
        || (gcs && c = '_')
      in
      let edge c = (c >= 'a' && c <= 'z') || Docpos.is_digit c in
      if n >= 3 && n <= 63 && String.for_all ok_char s && edge s.[0] && edge s.[n - 1]
      then Some s
      else begin
        Dec.error ctx p
          (Printf.sprintf
             "invalid bucket name %S (3-63 characters: lower-case letters, digits, '.', \
              '-'%s; starting and ending with a letter or digit)"
             s
             (if gcs then ", '_'" else ""));
        None
      end

let prefix_j ctx p v =
  match Dec.string ctx p v with
  | Some s when String.length s > 512 ->
      Dec.error ctx p "must be at most 512 characters";
      None
  | Some s when s <> "" && s.[0] = '/' ->
      Dec.error ctx p "must not start with '/'";
      None
  | Some s when String.exists (fun c -> c < ' ' || c = '\127') s ->
      Dec.error ctx p "must not contain control characters";
      None
  | Some s when List.mem ".." (String.split_on_char '/' s) ->
      Dec.error ctx p "must not contain '..' segments";
      None
  | x -> x

let object_lock_j ctx p v =
  match Dec.obj ctx p ~keys:[ "mode"; "retain_days" ] v with
  | None -> None
  | Some o -> (
      let mode =
        Dec.req ctx o p "mode"
          (Dec.enum ctx
             ~values:[ ("GOVERNANCE", Governance); ("COMPLIANCE", Compliance) ])
      in
      let days =
        Dec.req ctx o p "retain_days" (fun p v -> Dec.int ctx p ~min:1 ~max:36500 v)
      in
      match (mode, days) with
      | Some lock_mode, Some retain_days -> Some { lock_mode; retain_days }
      | _ -> None)

(* Reports each of [keys] that is present, with [msg]. *)
let forbid ctx o p keys ~msg =
  List.iter
    (fun k -> if Dec.field o k <> None then Dec.error ctx (Lpath.key p k) msg)
    keys

let s3_credentials_j ctx p v =
  match
    Dec.obj ctx p
      ~keys:[ "source"; "access_key_id"; "secret_access_key"; "session_token" ]
      v
  with
  | None -> None
  | Some o -> (
      let source =
        match Dec.field o "source" with
        | None -> Some `Env
        | Some _ ->
            Dec.opt o p "source"
              (Dec.enum ctx
                 ~values:
                   [
                     ("env", `Env);
                     ("static", `Static);
                     ("web_identity", `Web_identity);
                     ("instance", `Instance);
                   ])
      in
      let static_keys = [ "access_key_id"; "secret_access_key"; "session_token" ] in
      match source with
      | None -> None
      | Some `Static -> (
          let ak = Dec.req ctx o p "access_key_id" (Dec.non_empty_string ctx) in
          let sk = Dec.req ctx o p "secret_access_key" (Dec.non_empty_string ctx) in
          let st = Dec.opt o p "session_token" (Dec.non_empty_string ctx) in
          match (ak, sk) with
          | Some access_key_id, Some secret_access_key ->
              Some (S3_static { access_key_id; secret_access_key; session_token = st })
          | _ -> None)
      | Some other ->
          forbid ctx o p static_keys ~msg:"only allowed when source is static";
          Some
            (match other with
            | `Env -> S3_env
            | `Web_identity -> S3_web_identity
            | `Instance | `Static -> S3_instance))

let gcs_credentials_j ctx ~base_dir p v =
  match Dec.obj ctx p ~keys:[ "source"; "file" ] v with
  | None -> None
  | Some o -> (
      let source =
        match Dec.field o "source" with
        | None -> Some `Metadata
        | Some _ ->
            Dec.opt o p "source"
              (Dec.enum ctx
                 ~values:[ ("metadata", `Metadata); ("service_account_file", `File) ])
      in
      match source with
      | None -> None
      | Some `Metadata ->
          forbid ctx o p [ "file" ]
            ~msg:"only allowed when source is service_account_file";
          Some Gcs_metadata
      | Some `File ->
          Option.map
            (fun f -> Gcs_service_account_file (Dec.absolute ?base_dir f))
            (Dec.req ctx o p "file" (Dec.non_empty_string ctx)))

let sink_types = [ ("stdout", `Stdout); ("file", `File); ("s3", `S3); ("gcs", `Gcs) ]

let sink_j ctx ~base_dir path j =
  match j with
  | `Assoc kvs -> (
      let ty = Dec.req ctx kvs path "type" (Dec.enum ctx ~values:sink_types) in
      let keys =
        match ty with
        | Some `Stdout -> [ "type"; "path"; "on_error" ]
        | Some `File -> [ "type"; "path"; "on_error" ]
        | Some `S3 ->
            [
              "type";
              "bucket";
              "prefix";
              "region";
              "endpoint";
              "object_lock";
              "batch";
              "credentials";
              "spool_dir";
              "on_error";
            ]
        | Some `Gcs ->
            [
              "type"; "bucket"; "prefix"; "batch"; "credentials"; "spool_dir"; "on_error";
            ]
        | None -> [ "type"; "path"; "on_error" ]
      in
      ignore (Dec.obj ctx path ~keys j);
      let on_error =
        match Dec.field kvs "on_error" with
        | None -> Some Fail_closed
        | Some _ ->
            Dec.opt kvs path "on_error"
              (Dec.enum ctx ~values:[ ("fail_closed", Fail_closed); ("buffer", Buffer) ])
      in
      let kind =
        match ty with
        | None -> None
        | Some `Stdout ->
            if Dec.field kvs "path" <> None then
              Dec.error ctx (Lpath.key path "path") "only allowed for sinks of type file";
            Some Sink_stdout
        | Some `File ->
            Option.map
              (fun f -> Sink_file (Dec.absolute ?base_dir f))
              (Dec.req ctx kvs path "path" (Dec.non_empty_string ctx))
        | Some `S3 -> (
            let bucket = Dec.req ctx kvs path "bucket" (bucket_j ctx ~gcs:false) in
            let prefix = Dec.opt kvs path "prefix" (prefix_j ctx) in
            let region =
              Dec.req ctx kvs path "region" (fun p v ->
                  match Dec.non_empty_string ctx p v with
                  | Some r
                    when String.for_all
                           (fun c ->
                             (c >= 'a' && c <= 'z') || Docpos.is_digit c || c = '-')
                           r ->
                      Some r
                  | Some r ->
                      Dec.error ctx p
                        (Printf.sprintf "invalid region %S (e.g. us-east-1)" r);
                      None
                  | None -> None)
            in
            let endpoint = Dec.opt kvs path "endpoint" (url_j ctx ~http:`Allow) in
            let lock = Dec.opt kvs path "object_lock" (object_lock_j ctx) in
            let batch = Dec.opt kvs path "batch" (batch_j ctx) in
            let creds =
              match Dec.field kvs "credentials" with
              | None -> Some S3_env
              | Some _ -> Dec.opt kvs path "credentials" (s3_credentials_j ctx)
            in
            let lock_ok = Dec.field kvs "object_lock" = None || lock <> None in
            let batch_ok = Dec.field kvs "batch" = None || batch <> None in
            let spool = Dec.opt kvs path "spool_dir" (Dec.non_empty_string ctx) in
            let spool_ok = Dec.field kvs "spool_dir" = None || spool <> None in
            match (bucket, region, creds) with
            | Some s3_bucket, Some s3_region, Some s3_credentials
              when lock_ok && batch_ok && spool_ok ->
                Some
                  (Sink_s3
                     {
                       s3_bucket;
                       s3_prefix = Option.value ~default:default_audit_prefix prefix;
                       s3_region;
                       s3_endpoint = endpoint;
                       s3_object_lock = lock;
                       s3_batch = Option.value ~default:default_batch batch;
                       s3_credentials;
                       s3_spool_dir = Option.map (Dec.absolute ?base_dir) spool;
                     })
            | _ -> None)
        | Some `Gcs -> (
            let bucket = Dec.req ctx kvs path "bucket" (bucket_j ctx ~gcs:true) in
            let prefix = Dec.opt kvs path "prefix" (prefix_j ctx) in
            let batch = Dec.opt kvs path "batch" (batch_j ctx) in
            let creds =
              match Dec.field kvs "credentials" with
              | None -> Some Gcs_metadata
              | Some _ -> Dec.opt kvs path "credentials" (gcs_credentials_j ctx ~base_dir)
            in
            let batch_ok = Dec.field kvs "batch" = None || batch <> None in
            let spool = Dec.opt kvs path "spool_dir" (Dec.non_empty_string ctx) in
            let spool_ok = Dec.field kvs "spool_dir" = None || spool <> None in
            match (bucket, creds) with
            | Some gcs_bucket, Some gcs_credentials when batch_ok && spool_ok ->
                Some
                  (Sink_gcs
                     {
                       gcs_bucket;
                       gcs_prefix = Option.value ~default:default_audit_prefix prefix;
                       gcs_batch = Option.value ~default:default_batch batch;
                       gcs_credentials;
                       gcs_spool_dir = Option.map (Dec.absolute ?base_dir) spool;
                     })
            | _ -> None)
      in
      match (kind, on_error) with
      | Some sink, Some on_error -> Some { sink; on_error }
      | _ -> None)
  | j ->
      Dec.type_error ctx path "a mapping" j;
      None

(* secrets *)

let vault_auth_methods =
  [ ("token", `Token); ("kubernetes", `Kubernetes); ("approle", `Approle) ]

let vault_auth_j ctx ~base_dir p v =
  match
    Dec.obj ctx p
      ~keys:[ "method"; "token"; "role"; "role_id"; "secret_id"; "jwt_path"; "mount" ]
      v
  with
  | None -> None
  | Some o -> (
      let mount_j p v =
        match Dec.non_empty_string ctx p v with
        | Some m
          when String.for_all (fun c -> is_alnum c || c = '-' || c = '_' || c = '/') m
               && m.[0] <> '/' ->
            Some m
        | Some m ->
            Dec.error ctx p (Printf.sprintf "invalid auth mount %S" m);
            None
        | None -> None
      in
      let only m keys =
        forbid ctx o p keys ~msg:(Printf.sprintf "not used by method %s" m)
      in
      match Dec.req ctx o p "method" (Dec.enum ctx ~values:vault_auth_methods) with
      | None -> None
      | Some `Token ->
          only "token" [ "role"; "role_id"; "secret_id"; "jwt_path"; "mount" ];
          Option.map
            (fun t -> Vault_token t)
            (Dec.req ctx o p "token" (Dec.non_empty_string ctx))
      | Some `Kubernetes -> (
          only "kubernetes" [ "token"; "role_id"; "secret_id" ];
          let role = Dec.req ctx o p "role" (Dec.non_empty_string ctx) in
          let jwt_path =
            match Dec.opt o p "jwt_path" (Dec.non_empty_string ctx) with
            | Some j -> Some (Dec.absolute ?base_dir j)
            | None ->
                if Dec.field o "jwt_path" = None then Some default_k8s_jwt_path else None
          in
          let mount =
            match Dec.opt o p "mount" mount_j with
            | Some m -> Some m
            | None -> if Dec.field o "mount" = None then Some "kubernetes" else None
          in
          match (role, jwt_path, mount) with
          | Some role, Some jwt_path, Some mount ->
              Some (Vault_kubernetes { role; jwt_path; mount })
          | _ -> None)
      | Some `Approle -> (
          only "approle" [ "token"; "role"; "jwt_path" ];
          let role_id = Dec.req ctx o p "role_id" (Dec.non_empty_string ctx) in
          let secret_id = Dec.req ctx o p "secret_id" (Dec.non_empty_string ctx) in
          let mount =
            match Dec.opt o p "mount" mount_j with
            | Some m -> Some m
            | None -> if Dec.field o "mount" = None then Some "approle" else None
          in
          match (role_id, secret_id, mount) with
          | Some role_id, Some secret_id, Some mount ->
              Some (Vault_approle { role_id; secret_id; mount })
          | _ -> None))

let vault_j ctx ~base_dir p v =
  match Dec.obj ctx p ~keys:[ "address"; "namespace"; "auth"; "ca_file" ] v with
  | None -> None
  | Some o -> (
      let address =
        Dec.req ctx o p "address" (url_j ~no_query:true ctx ~http:`Loopback_only)
      in
      let ns = Dec.opt o p "namespace" (Dec.non_empty_string ctx) in
      let auth = Dec.req ctx o p "auth" (vault_auth_j ctx ~base_dir) in
      let ca =
        Option.map (Dec.absolute ?base_dir)
          (Dec.opt o p "ca_file" (Dec.non_empty_string ctx))
      in
      let ns_ok = Dec.field o "namespace" = None || ns <> None in
      let ca_ok = Dec.field o "ca_file" = None || ca <> None in
      match (address, auth) with
      | Some vault_address, Some vault_auth when ns_ok && ca_ok ->
          Some { vault_address; vault_namespace = ns; vault_auth; vault_ca_file = ca }
      | _ -> None)

let secrets_j ctx ~base_dir p v =
  match Dec.obj ctx p ~keys:[ "vault"; "aws"; "gcp" ] v with
  | None -> None
  | Some o ->
      let vault = Dec.opt o p "vault" (vault_j ctx ~base_dir) in
      let aws =
        Dec.opt o p "aws" (fun p v ->
            match Dec.obj ctx p ~keys:[ "region"; "endpoint" ] v with
            | None -> None
            | Some a -> (
                let region = Dec.req ctx a p "region" (Dec.non_empty_string ctx) in
                let endpoint = Dec.opt a p "endpoint" (url_j ctx ~http:`Allow) in
                match region with
                | Some aws_region -> Some { aws_region; aws_endpoint = endpoint }
                | None -> None))
      in
      let gcp =
        Dec.opt o p "gcp" (fun p v ->
            match Dec.obj ctx p ~keys:[ "project"; "endpoint" ] v with
            | None -> None
            | Some g ->
                let project = Dec.opt g p "project" (Dec.non_empty_string ctx) in
                let endpoint = Dec.opt g p "endpoint" (url_j ctx ~http:`Allow) in
                Some { gcp_project = project; gcp_endpoint = endpoint })
      in
      Some { vault; aws; gcp }

(* policies *)

type policy_entry = {
  pname : string;
  pol : Policy.t;
  pfile : string option;
  ppath : Lpath.t;
}

type entry = Plain of policy_entry | Bundle of bundle_ref * Lpath.t

let is_b64_char c = is_alnum c || c = '+' || c = '/'

(* base64 of exactly 32 bytes: 43 alphabet characters and one '='. *)
let is_ed25519_b64 s =
  String.length s = 44
  && s.[43] = '='
  && String.for_all is_b64_char (String.sub s 0 43)
  &&
  (* the last data character carries 2 padding bits that must be zero *)
  String.contains "AEIMQUYcgkosw048" s.[42]

let public_key_j ctx ~base_dir p v =
  match Dec.non_empty_string ctx p v with
  | None -> None
  | Some s when starts_with ~prefix:"-----BEGIN" s ->
      if
        contains_sub s "-----BEGIN PUBLIC KEY-----"
        && contains_sub s "-----END PUBLIC KEY-----"
      then Some (Key_pem s)
      else begin
        Dec.error ctx p
          "inline PEM must be a public key (-----BEGIN PUBLIC KEY----- ... -----END \
           PUBLIC KEY-----)";
        None
      end
  | Some s when is_ed25519_b64 s -> Some (Key_base64 s)
  | Some s -> Some (Key_path (Dec.absolute ?base_dir s))

let policy_entry_j ctx ~base_dir path j =
  match
    Dec.obj ctx path ~keys:[ "path"; "inline"; "bundle"; "public_keys"; "name_prefix" ] j
  with
  | None -> None
  | Some kvs -> (
      let has k = Dec.field kvs k <> None in
      if not (has "bundle") then
        forbid ctx kvs path
          [ "public_keys"; "name_prefix" ]
          ~msg:"only allowed with bundle";
      match (Dec.field kvs "path", Dec.field kvs "inline", Dec.field kvs "bundle") with
      | Some _, Some _, None ->
          Dec.error ctx path "use either path or inline, not both";
          None
      | _, _, Some _ when has "path" || has "inline" ->
          Dec.error ctx path "use only one of path, inline or bundle";
          None
      | None, None, None ->
          Dec.error ctx path "a policy entry needs path or inline (or bundle)";
          None
      | None, None, Some bv -> (
          let bp = Lpath.key path "bundle" in
          let bundle =
            Option.map (Dec.absolute ?base_dir) (Dec.non_empty_string ctx bp bv)
          in
          let keys =
            non_empty_list ctx
              (Lpath.key path "public_keys")
              (Dec.req ctx kvs path "public_keys" (fun p v ->
                   Dec.list_of ctx p (public_key_j ctx ~base_dir) v))
          in
          let prefix =
            Dec.opt kvs path "name_prefix" (fun p v ->
                match Dec.non_empty_string ctx p v with
                | Some s
                  when String.length s <= 64
                       && is_alnum s.[0]
                       && String.for_all
                            (fun c -> Policy_impl.is_word_char c || c = '-' || c = '.')
                            s ->
                    Some s
                | Some s ->
                    Dec.error ctx p
                      (Printf.sprintf
                         "invalid name_prefix %S (1-64 characters: letters, digits, '.', \
                          '_', '-'; starting with a letter or digit)"
                         s);
                    None
                | None -> None)
          in
          let prefix_ok = Dec.field kvs "name_prefix" = None || prefix <> None in
          let n_keys =
            match Dec.field kvs "public_keys" with
            | Some (`List l) -> List.length l
            | _ -> 0
          in
          match (bundle, keys) with
          | Some bundle_path, Some public_keys
            when prefix_ok && List.length public_keys = n_keys ->
              Some (Bundle ({ bundle_path; public_keys; name_prefix = prefix }, path))
          | _ -> None)
      | Some pv, None, None -> (
          let pp = Lpath.key path "path" in
          match Dec.non_empty_string ctx pp pv with
          | None -> None
          | Some f -> (
              let abs = Dec.absolute ?base_dir f in
              match Policy_impl.of_file abs with
              | Ok pol ->
                  Some (Plain { pname = pol.name; pol; pfile = Some abs; ppath = path })
              | Error errs ->
                  Dec.error ctx pp (Printf.sprintf "cannot load policy %S" abs);
                  Dec.add_errors ctx errs;
                  None))
      | None, Some iv, None ->
          Option.map
            (fun (pol : Policy.t) ->
              Plain { pname = pol.name; pol; pfile = None; ppath = path })
            (Policy_impl.decode ctx ?base_dir ~inline:true (Lpath.key path "inline") iv)
      | _ -> None)

let top_keys =
  [
    "apiVersion";
    "kind";
    "server";
    "policies";
    "default_policy";
    "reload";
    "audit";
    "telemetry";
    "logging";
    "limits";
    "secrets";
  ]

let parse_bool_env s =
  match String.lowercase_ascii (String.trim s) with
  | "1" | "true" | "yes" | "on" -> Some true
  | "0" | "false" | "no" | "off" -> Some false
  | _ -> None

let legacy_sink = function
  | { sink = Sink_stdout; _ } -> Some Audit_stdout
  | { sink = Sink_file f; _ } -> Some (Audit_file f)
  | _ -> None

let decode ctx ~base_dir ~env (j : Yojson.Safe.t) : t option =
  match Dec.obj ctx Lpath.root ~keys:top_keys j with
  | None -> None
  | Some kvs ->
      let root = Lpath.root in
      Dec.header ctx kvs root ~kind:"Config";
      let c = ref default in
      let mtls_path = Lpath.key (Lpath.key (Lpath.key root "server") "auth") "mtls" in
      (* server *)
      ignore
        (Dec.opt kvs root "server" (fun p v ->
             match Dec.obj ctx p ~keys:[ "listen"; "tls"; "auth" ] v with
             | None -> None
             | Some s ->
                 Option.iter
                   (fun l -> c := { !c with listen = l })
                   (Dec.opt s p "listen" (listen_j ctx));
                 Option.iter
                   (fun (cert, key, tls) ->
                     c := { !c with tls_cert = cert; tls_key = key; tls })
                   (Dec.opt s p "tls" (tls_j ctx ~base_dir));
                 ignore
                   (Dec.opt s p "auth" (fun p v ->
                        match
                          Dec.obj ctx p
                            ~keys:[ "tokens"; "allow_unauthenticated"; "oidc"; "mtls" ]
                            v
                        with
                        | None -> None
                        | Some a ->
                            Option.iter
                              (fun tokens -> c := { !c with tokens })
                              (Dec.opt a p "tokens" (fun p v ->
                                   Dec.list_of ctx p (token_j ctx) v));
                            Option.iter
                              (fun b -> c := { !c with allow_unauthenticated = b })
                              (Dec.opt a p "allow_unauthenticated" (Dec.bool ctx));
                            Option.iter
                              (fun oidc -> c := { !c with oidc })
                              (Dec.opt a p "oidc" (fun p v ->
                                   Dec.list_of ctx p (oidc_j ctx) v));
                            Option.iter
                              (fun mtls -> c := { !c with mtls })
                              (Dec.opt a p "mtls" (fun p v ->
                                   match Dec.obj ctx p ~keys:[ "identities" ] v with
                                   | None -> None
                                   | Some m ->
                                       Some
                                         (Option.value ~default:[]
                                            (Dec.opt m p "identities" (fun p v ->
                                                 Dec.list_of ctx p (mtls_identity_j ctx) v)))));
                            Some ()));
                 Some ()));
      (* policies *)
      let entries =
        Option.value ~default:[]
          (Dec.opt kvs root "policies" (fun p v ->
               Dec.list_of ctx p (policy_entry_j ctx ~base_dir) v))
      in
      let plain =
        List.filter_map (function Plain e -> Some e | Bundle _ -> None) entries
      in
      let bundles =
        List.filter_map
          (function Bundle (b, p) -> Some (b, p) | Plain _ -> None)
          entries
      in
      let policies_failed = Dec.has_errors ctx in
      let seen = Hashtbl.create 8 in
      List.iter
        (fun e ->
          if Hashtbl.mem seen e.pname then
            Dec.error ctx e.ppath (Printf.sprintf "duplicate policy name %S" e.pname)
          else Hashtbl.add seen e.pname ())
        plain;
      let seen_b = Hashtbl.create 4 in
      List.iter
        (fun (b, p) ->
          if Hashtbl.mem seen_b b.bundle_path then
            Dec.error ctx (Lpath.key p "bundle")
              (Printf.sprintf "duplicate bundle %S" b.bundle_path)
          else Hashtbl.add seen_b b.bundle_path ())
        bundles;
      c :=
        {
          !c with
          policies = List.map (fun e -> (e.pname, e.pol)) plain;
          policy_files = List.filter_map (fun e -> e.pfile) plain;
          policy_bundles = List.map fst bundles;
        };
      Option.iter
        (fun d -> c := { !c with default_policy = Some d })
        (Dec.opt kvs root "default_policy" (Dec.non_empty_string ctx));
      ignore
        (Dec.opt kvs root "reload" (fun p v ->
             match Dec.obj ctx p ~keys:[ "watch" ] v with
             | None -> None
             | Some r ->
                 Option.iter
                   (fun w -> c := { !c with reload_watch = w })
                   (Dec.opt r p "watch" (Dec.bool ctx));
                 Some ()));
      ignore
        (Dec.opt kvs root "audit" (fun p v ->
             match Dec.obj ctx p ~keys:[ "sinks"; "log_raw_sql" ] v with
             | None -> None
             | Some a ->
                 Option.iter
                   (fun s ->
                     c :=
                       { !c with sinks = s; audit_sinks = List.filter_map legacy_sink s })
                   (Dec.opt a p "sinks" (fun p v ->
                        Dec.list_of ctx p (sink_j ctx ~base_dir) v));
                 Option.iter
                   (fun b -> c := { !c with log_raw_sql = b })
                   (Dec.opt a p "log_raw_sql" (Dec.bool ctx));
                 Some ()));
      ignore
        (Dec.opt kvs root "telemetry" (fun p v ->
             match Dec.obj ctx p ~keys:[ "metrics"; "otlp_endpoint"; "otlp" ] v with
             | None -> None
             | Some t ->
                 ignore
                   (Dec.opt t p "metrics" (fun p v ->
                        match Dec.obj ctx p ~keys:[ "prometheus" ] v with
                        | None -> None
                        | Some m ->
                            Option.iter
                              (fun b -> c := { !c with metrics = b })
                              (Dec.opt m p "prometheus" (Dec.bool ctx));
                            Some ()));
                 (match (Dec.field t "otlp", Dec.field t "otlp_endpoint") with
                 | Some _, Some _ ->
                     Dec.error ctx (Lpath.key p "otlp_endpoint")
                       "use either telemetry.otlp.endpoint or the legacy \
                        telemetry.otlp_endpoint, not both"
                 | Some _, None ->
                     Option.iter
                       (fun o -> c := { !c with otlp = Some o })
                       (Dec.opt t p "otlp" (otlp_j ctx))
                 | None, Some _ ->
                     Option.iter
                       (fun e -> c := { !c with otlp = Some (default_otlp e) })
                       (Dec.opt t p "otlp_endpoint" (url_j ctx ~http:`Allow))
                 | None, None -> ());
                 Some ()));
      ignore
        (Dec.opt kvs root "logging" (fun p v ->
             match Dec.obj ctx p ~keys:[ "level"; "format" ] v with
             | None -> None
             | Some l ->
                 Option.iter
                   (fun x -> c := { !c with log_level = x })
                   (Dec.opt l p "level"
                      (Dec.enum ctx ~values:(List.map (fun x -> (x, x)) log_levels)));
                 Option.iter
                   (fun x -> c := { !c with log_format = x })
                   (Dec.opt l p "format"
                      (Dec.enum ctx ~values:(List.map (fun x -> (x, x)) log_formats)));
                 Some ()));
      ignore
        (Dec.opt kvs root "limits" (fun p v ->
             match Dec.obj ctx p ~keys:[ "max_request_bytes" ] v with
             | None -> None
             | Some l ->
                 Option.iter
                   (fun x -> c := { !c with max_request_bytes = x })
                   (Dec.opt l p "max_request_bytes" (fun p v ->
                        Dec.int ctx p ~min:1024 ~max:(64 * 1024 * 1024) v));
                 Some ()));
      Option.iter
        (fun s -> c := { !c with secrets = s })
        (Dec.opt kvs root "secrets" (secrets_j ctx ~base_dir));
      (* HALTSQL_* environment overrides (env > file) *)
      let envp name = Lpath.key Lpath.root ("env:" ^ name) in
      let ov name f = match env name with Some v when v <> "" -> f v | _ -> () in
      ov "HALTSQL_LISTEN" (fun v ->
          if valid_listen v then c := { !c with listen = v }
          else
            Dec.error_unlocated ctx (envp "HALTSQL_LISTEN")
              (Printf.sprintf "invalid listen address %S" v));
      ov "HALTSQL_LOG_LEVEL" (fun v ->
          if List.mem v log_levels then c := { !c with log_level = v }
          else
            Dec.error_unlocated ctx (envp "HALTSQL_LOG_LEVEL")
              (Printf.sprintf "invalid log level %S (expected one of: %s)" v
                 (String.concat ", " log_levels)));
      ov "HALTSQL_LOG_FORMAT" (fun v ->
          if List.mem v log_formats then c := { !c with log_format = v }
          else
            Dec.error_unlocated ctx (envp "HALTSQL_LOG_FORMAT")
              (Printf.sprintf "invalid log format %S (expected one of: %s)" v
                 (String.concat ", " log_formats)));
      ov "HALTSQL_ALLOW_UNAUTHENTICATED" (fun v ->
          match parse_bool_env v with
          | Some b -> c := { !c with allow_unauthenticated = b }
          | None ->
              Dec.error_unlocated ctx
                (envp "HALTSQL_ALLOW_UNAUTHENTICATED")
                (Printf.sprintf "invalid boolean %S" v));
      ov "HALTSQL_DEFAULT_POLICY" (fun v -> c := { !c with default_policy = Some v });
      (* cross-checks *)
      let cfg = !c in
      let names = List.map fst cfg.policies in
      let prefixes = List.map (fun b -> b.name_prefix) cfg.policy_bundles in
      let check_ref path name =
        if policies_failed || List.mem name names then ()
        else if cfg.policy_bundles <> [] then
          (* Bundle policies are loaded later; the server re-validates. When
             every bundle has a name_prefix, the name must match one. *)
          begin if List.for_all Option.is_some prefixes then
            let ps = List.filter_map Fun.id prefixes in
            if not (List.exists (fun prefix -> starts_with ~prefix name) ps) then
              Dec.error ctx path
                (Printf.sprintf
                   "unknown policy %S (not loaded, and not matching any bundle \
                    name_prefix: %s)"
                   name (String.concat ", " ps))
          end
        else
          Dec.error ctx path
            (Printf.sprintf "unknown policy %S (loaded: %s)" name
               (if names = [] then "none" else String.concat ", " names))
      in
      let auth_path = Lpath.key (Lpath.key root "server") "auth" in
      let tokens_path i k = Lpath.key (Lpath.idx (Lpath.key auth_path "tokens") i) k in
      let seen_names = Hashtbl.create 8 and seen_hashes = Hashtbl.create 8 in
      List.iteri
        (fun i t ->
          if Hashtbl.mem seen_names t.token_name then
            Dec.error ctx (tokens_path i "name")
              (Printf.sprintf "duplicate token name %S" t.token_name)
          else Hashtbl.add seen_names t.token_name ();
          if Hashtbl.mem seen_hashes t.token_sha256 then
            Dec.error ctx
              (tokens_path i "token_sha256")
              "the same token hash is listed twice"
          else Hashtbl.add seen_hashes t.token_sha256 ();
          check_ref (tokens_path i "policy") t.token_policy)
        cfg.tokens;
      (match cfg.default_policy with
      | Some d -> check_ref (Lpath.key root "default_policy") d
      | None -> ());
      (* OIDC: unique names, policy references *)
      let oidc_path i k = Lpath.key (Lpath.idx (Lpath.key auth_path "oidc") i) k in
      let seen_providers = Hashtbl.create 4 in
      List.iteri
        (fun i o ->
          if Hashtbl.mem seen_providers o.oidc_name then
            Dec.error ctx (oidc_path i "name")
              (Printf.sprintf "duplicate OIDC provider name %S" o.oidc_name)
          else Hashtbl.add seen_providers o.oidc_name ();
          match o.oidc_policy with
          | Oidc_pinned n -> check_ref (oidc_path i "policy") n
          | Oidc_from_claim { allowed; _ } ->
              List.iteri
                (fun j n -> check_ref (Lpath.idx (oidc_path i "allowed_policies") j) n)
                allowed)
        cfg.oidc;
      (* mTLS: requires client certificates, unique identities, policy refs *)
      if cfg.mtls <> [] then
        begin match cfg.tls with
        | Some { client_ca = Some _; client_auth = Client_auth_none; _ } ->
            Dec.error ctx mtls_path
              "requires server.tls.client_auth optional or required (client certificates \
               are not requested with none)"
        | Some { client_ca = Some _; _ } -> ()
        | _ -> Dec.error ctx mtls_path "requires server.tls.client_ca (and tls.cert/key)"
        end;
      let ident_path i k = Lpath.key (Lpath.idx (Lpath.key mtls_path "identities") i) k in
      let seen_ids = Hashtbl.create 4 in
      List.iteri
        (fun i m ->
          let key, field, label =
            match m.mtls_match with
            | Spiffe_id s -> ("spiffe:" ^ s, "spiffe_id", s)
            | Subject_cn s -> ("cn:" ^ s, "subject_cn", s)
          in
          if Hashtbl.mem seen_ids key then
            Dec.error ctx (ident_path i field)
              (Printf.sprintf "duplicate mTLS identity %S" label)
          else Hashtbl.add seen_ids key ();
          check_ref (ident_path i "policy") m.mtls_policy)
        cfg.mtls;
      Some cfg

let of_json_pos ?file ?base_dir ?env ?resolve ?positions j =
  let env = match env with Some e -> e | None -> Sys.getenv_opt in
  let ctx = Dec.create ?file ?positions () in
  let base_dir = Dec.base_dir_of ?base_dir file in
  let provider =
    match resolve with
    | None -> No_resolver
    | Some r ->
        let cache = Hashtbl.create 8 in
        Resolver
          (fun ~scheme ~reference ->
            match Hashtbl.find_opt cache (scheme, reference) with
            | Some v -> v
            | None ->
                let v = r ~scheme ~reference in
                Hashtbl.add cache (scheme, reference) v;
                v)
  in
  let j = resolve_tree ctx ~env ~base_dir ~provider j in
  match decode ctx ~base_dir ~env j with
  | Some c when not (Dec.has_errors ctx) -> Ok c
  | _ -> Error (Dec.errors ctx)

let of_json ?file ?base_dir ?env ?resolve j = of_json_pos ?file ?base_dir ?env ?resolve j

let of_file ?env ?resolve file =
  match Docpos.parse_file file with
  | Error e -> Error e
  | Ok (j, positions) ->
      of_json_pos ~file ~base_dir:(Filename.dirname file) ?env ?resolve ~positions j

let secrets_of_json_pos ?file ?base_dir ?env ?positions (j : Yojson.Safe.t) =
  let env = match env with Some e -> e | None -> Sys.getenv_opt in
  let ctx = Dec.create ?file ?positions () in
  let base_dir = Dec.base_dir_of ?base_dir file in
  match j with
  | `Assoc kvs -> (
      match Dec.field kvs "secrets" with
      | None -> Ok no_secrets
      | Some sv -> (
          let resolved =
            resolve_tree ctx ~env ~base_dir ~provider:In_secrets
              (`Assoc [ ("secrets", sv) ])
          in
          let sv = match resolved with `Assoc [ (_, v) ] -> v | v -> v in
          match secrets_j ctx ~base_dir (Lpath.key Lpath.root "secrets") sv with
          | Some s when not (Dec.has_errors ctx) -> Ok s
          | _ -> Error (Dec.errors ctx)))
  | j ->
      Dec.type_error ctx Lpath.root "a mapping" j;
      Error (Dec.errors ctx)

let secrets_of_json ?file ?base_dir ?env j = secrets_of_json_pos ?file ?base_dir ?env j

let secrets_of_file ?env file =
  match Docpos.parse_file file with
  | Error e -> Error e
  | Ok (j, positions) ->
      secrets_of_json_pos ~file ~base_dir:(Filename.dirname file) ?env ~positions j

(* ---------------------------------------------------------------------- *)
(* Redacted rendering                                                     *)

let redacted = `String "<redacted>"
let opt_s = function Some s -> `String s | None -> `Null
let strs l = `List (List.map (fun s -> `String s) l)
let pem_json = function Pem_path p -> `String p | Pem_inline _ -> `String "<inline PEM>"

let tls_json c =
  match c.tls with
  | None ->
      `Assoc
        [
          ("cert", opt_s c.tls_cert);
          ("key", match c.tls_key with Some _ -> redacted | None -> `Null);
        ]
  | Some t ->
      `Assoc
        [
          ("cert", pem_json t.cert);
          ("key", redacted);
          ("client_ca", match t.client_ca with Some p -> pem_json p | None -> `Null);
          ( "client_auth",
            `String
              (match t.client_auth with
              | Client_auth_none -> "none"
              | Client_auth_optional -> "optional"
              | Client_auth_required -> "required") );
          ( "min_version",
            `String (match t.min_version with Tls_1_2 -> "1.2" | Tls_1_3 -> "1.3") );
        ]

let oidc_json o =
  `Assoc
    ([
       ("name", `String o.oidc_name);
       ("issuer", `String o.issuer);
       ("audiences", strs o.audiences);
       ("jwks_uri", opt_s o.jwks_uri);
       ("algorithms", strs (List.map string_of_jwt_alg o.algorithms));
       ("leeway_seconds", `Int o.leeway_seconds);
       ("jwks_cache_seconds", `Int o.jwks_cache_seconds);
     ]
    @ (match o.oidc_policy with
      | Oidc_pinned n -> [ ("policy", `String n) ]
      | Oidc_from_claim { claim; allowed } ->
          [ ("policy_claim", `String claim); ("allowed_policies", strs allowed) ])
    @ [
        ( "context_claims",
          `Assoc (List.map (fun (k, v) -> (k, `String v)) o.context_claims) );
        ( "required_claims",
          `Assoc
            (List.map
               (fun (k, m) ->
                 (k, match m with Claim_one s -> `String s | Claim_all l -> strs l))
               o.required_claims) );
        ("request_context_fields", strs o.oidc_request_context_fields);
        ("allow_insecure_http", `Bool o.allow_insecure_http);
      ])

let mtls_json m =
  `Assoc
    [
      (match m.mtls_match with
      | Spiffe_id s -> ("spiffe_id", `String s)
      | Subject_cn s -> ("subject_cn", `String s));
      ("policy", `String m.mtls_policy);
      ("context", Context.to_json m.mtls_context);
      ("request_context_fields", strs m.mtls_request_context_fields);
    ]

let batch_json b =
  `Assoc [ ("max_records", `Int b.max_records); ("max_seconds", `Int b.max_seconds) ]

let sink_json s =
  let body =
    match s.sink with
    | Sink_stdout -> [ ("type", `String "stdout") ]
    | Sink_file f -> [ ("type", `String "file"); ("path", `String f) ]
    | Sink_s3 x ->
        [
          ("type", `String "s3");
          ("bucket", `String x.s3_bucket);
          ("prefix", `String x.s3_prefix);
          ("region", `String x.s3_region);
          ("endpoint", opt_s x.s3_endpoint);
          ( "object_lock",
            match x.s3_object_lock with
            | None -> `Null
            | Some l ->
                `Assoc
                  [
                    ( "mode",
                      `String
                        (match l.lock_mode with
                        | Governance -> "GOVERNANCE"
                        | Compliance -> "COMPLIANCE") );
                    ("retain_days", `Int l.retain_days);
                  ] );
          ("batch", batch_json x.s3_batch);
          ( "credentials",
            match x.s3_credentials with
            | S3_env -> `Assoc [ ("source", `String "env") ]
            | S3_web_identity -> `Assoc [ ("source", `String "web_identity") ]
            | S3_instance -> `Assoc [ ("source", `String "instance") ]
            | S3_static { session_token; _ } ->
                `Assoc
                  ([
                     ("source", `String "static");
                     ("access_key_id", redacted);
                     ("secret_access_key", redacted);
                   ]
                  @
                  match session_token with
                  | Some _ -> [ ("session_token", redacted) ]
                  | None -> []) );
          ("spool_dir", opt_s x.s3_spool_dir);
        ]
    | Sink_gcs x ->
        [
          ("type", `String "gcs");
          ("bucket", `String x.gcs_bucket);
          ("prefix", `String x.gcs_prefix);
          ("batch", batch_json x.gcs_batch);
          ( "credentials",
            match x.gcs_credentials with
            | Gcs_metadata -> `Assoc [ ("source", `String "metadata") ]
            | Gcs_service_account_file f ->
                `Assoc [ ("source", `String "service_account_file"); ("file", `String f) ]
          );
          ("spool_dir", opt_s x.gcs_spool_dir);
        ]
  in
  `Assoc
    (body
    @ [
        ( "on_error",
          `String
            (match s.on_error with Fail_closed -> "fail_closed" | Buffer -> "buffer") );
      ])

let secrets_json s =
  let vault =
    match s.vault with
    | None -> `Null
    | Some v ->
        `Assoc
          [
            ("address", `String v.vault_address);
            ("namespace", opt_s v.vault_namespace);
            ( "auth",
              match v.vault_auth with
              | Vault_token _ ->
                  `Assoc [ ("method", `String "token"); ("token", redacted) ]
              | Vault_kubernetes { role; jwt_path; mount } ->
                  `Assoc
                    [
                      ("method", `String "kubernetes");
                      ("role", `String role);
                      ("jwt_path", `String jwt_path);
                      ("mount", `String mount);
                    ]
              | Vault_approle { mount; _ } ->
                  `Assoc
                    [
                      ("method", `String "approle");
                      ("role_id", redacted);
                      ("secret_id", redacted);
                      ("mount", `String mount);
                    ] );
            ("ca_file", opt_s v.vault_ca_file);
          ]
  in
  `Assoc
    [
      ("vault", vault);
      ( "aws",
        match s.aws with
        | None -> `Null
        | Some a ->
            `Assoc
              [ ("region", `String a.aws_region); ("endpoint", opt_s a.aws_endpoint) ] );
      ( "gcp",
        match s.gcp with
        | None -> `Null
        | Some g ->
            `Assoc
              [ ("project", opt_s g.gcp_project); ("endpoint", opt_s g.gcp_endpoint) ] );
    ]

let public_key_json = function
  | Key_path p -> `String p
  | Key_pem s -> `String s
  | Key_base64 s -> `String s

let to_json_redacted (c : t) : Yojson.Safe.t =
  `Assoc
    [
      ("apiVersion", `String "haltsql.dev/v1");
      ("kind", `String "Config");
      ( "server",
        `Assoc
          [
            ("listen", `String c.listen);
            ("tls", tls_json c);
            ( "auth",
              `Assoc
                [
                  ( "tokens",
                    `List
                      (List.map
                         (fun t ->
                           `Assoc
                             [
                               ("name", `String t.token_name);
                               ("token_sha256", redacted);
                               ("policy", `String t.token_policy);
                             ])
                         c.tokens) );
                  ("allow_unauthenticated", `Bool c.allow_unauthenticated);
                  ("oidc", `List (List.map oidc_json c.oidc));
                  ("mtls", `Assoc [ ("identities", `List (List.map mtls_json c.mtls)) ]);
                ] );
          ] );
      ( "policies",
        `List
          (List.map
             (fun (n, (p : Policy.t)) ->
               `Assoc
                 [
                   ("name", `String n);
                   ("version", `String p.version);
                   ( "mode",
                     `String
                       (match p.mode with Enforce -> "enforce" | Shadow -> "shadow") );
                 ])
             c.policies) );
      ("policy_files", `List (List.map (fun f -> `String f) c.policy_files));
      ( "policy_bundles",
        `List
          (List.map
             (fun b ->
               `Assoc
                 [
                   ("bundle", `String b.bundle_path);
                   ("public_keys", `List (List.map public_key_json b.public_keys));
                   ("name_prefix", opt_s b.name_prefix);
                 ])
             c.policy_bundles) );
      ("default_policy", opt_s c.default_policy);
      ("reload", `Assoc [ ("watch", `Bool c.reload_watch) ]);
      ( "audit",
        `Assoc
          [
            ("sinks", `List (List.map sink_json c.sinks));
            ("log_raw_sql", `Bool c.log_raw_sql);
          ] );
      ( "telemetry",
        `Assoc
          [
            ("metrics", `Assoc [ ("prometheus", `Bool c.metrics) ]);
            ( "otlp",
              match c.otlp with
              | None -> `Null
              | Some o ->
                  `Assoc
                    [
                      ("endpoint", `String o.otlp_endpoint);
                      ( "headers",
                        `Assoc (List.map (fun (k, _) -> (k, redacted)) o.otlp_headers) );
                      ("service_name", `String o.service_name);
                      ("traces", `Bool o.otlp_traces);
                      ("metrics", `Bool o.otlp_metrics);
                      ("export_interval_seconds", `Int o.export_interval_seconds);
                      ("timeout_seconds", `Int o.timeout_seconds);
                    ] );
          ] );
      ( "logging",
        `Assoc [ ("level", `String c.log_level); ("format", `String c.log_format) ] );
      ("limits", `Assoc [ ("max_request_bytes", `Int c.max_request_bytes) ]);
      ("secrets", secrets_json c.secrets);
    ]
