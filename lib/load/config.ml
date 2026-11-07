(* Runtime configuration documents ([kind: Config]); see config.mli and
   PLAN.md §6.6. *)

open Haltsql_core

type token = { token_name : string; token_sha256 : string; token_policy : string }
type audit_sink = Audit_stdout | Audit_file of string

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
  }

let max_secret_file_bytes = 1024 * 1024
let log_levels = [ "debug"; "info"; "warn"; "error" ]
let log_formats = [ "json"; "text" ]

(* ---------------------------------------------------------------------- *)
(* ${env:NAME} / ${file:/path} placeholders. "$${" is a literal "${".     *)

let valid_env_name s =
  s <> ""
  && (match s.[0] with 'A' .. 'Z' | 'a' .. 'z' | '_' -> true | _ -> false)
  && String.for_all (fun c -> Policy_impl.is_word_char c) s

let trim_newline s =
  let n = String.length s in
  if n >= 2 && String.sub s (n - 2) 2 = "\r\n" then String.sub s 0 (n - 2)
  else if n >= 1 && s.[n - 1] = '\n' then String.sub s 0 (n - 1)
  else s

let resolve_string ctx path ~env ~base_dir s =
  let n = String.length s in
  let b = Buffer.create n in
  let ok = ref true in
  let rec go i =
    if i >= n then ()
    else if i + 2 < n && s.[i] = '$' && s.[i + 1] = '$' && s.[i + 2] = '{' then begin
      Buffer.add_string b "${";
      go (i + 3)
    end
    else if i + 1 < n && s.[i] = '$' && s.[i + 1] = '{' then (
      match String.index_from_opt s (i + 2) '}' with
      | None ->
          Dec.error ctx path "unterminated placeholder (missing '}')";
          ok := false
      | Some j ->
          let inner = String.sub s (i + 2) (j - i - 2) in
          let starts p =
            String.length inner >= String.length p
            && String.sub inner 0 (String.length p) = p
          in
          let rest p =
            String.sub inner (String.length p) (String.length inner - String.length p)
          in
          if starts "env:" then begin
            let name = rest "env:" in
            if not (valid_env_name name) then begin
              Dec.error ctx path
                (Printf.sprintf "invalid environment variable name %S" name);
              ok := false
            end
            else
              match env name with
              | Some v -> Buffer.add_string b v
              | None ->
                  Dec.error ctx path
                    (Printf.sprintf "environment variable %s is not set" name);
                  ok := false
          end
          else if starts "file:" then begin
            let f = rest "file:" in
            if f = "" then begin
              Dec.error ctx path "empty file path in ${file:...}";
              ok := false
            end
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
                  Dec.error ctx path (Printf.sprintf "${file:%s}: %s" f m);
                  ok := false
          end
          else begin
            Dec.error ctx path
              (Printf.sprintf
                 "unknown placeholder ${%s} (Config supports ${env:NAME} and \
                  ${file:/path})"
                 inner);
            ok := false
          end;
          go (j + 1))
    else begin
      Buffer.add_char b s.[i];
      go (i + 1)
    end
  in
  go 0;
  if !ok then Buffer.contents b else s

(* Resolve placeholders everywhere except inside inline policies, which must
   not use them (the policy decoder reports them). *)
let resolve_tree ctx ~env ~base_dir (j : Yojson.Safe.t) =
  let rec walk path rel (j : Yojson.Safe.t) : Yojson.Safe.t =
    match j with
    | `String s -> `String (resolve_string ctx path ~env ~base_dir s)
    | `List l ->
        `List (List.mapi (fun i x -> walk (Lpath.idx path i) (Lpath.Idx i :: rel) x) l)
    | `Assoc kvs ->
        `Assoc
          (List.map
             (fun (k, v) ->
               match (k, rel) with
               | "inline", [ Lpath.Idx _; Lpath.Key "policies" ] -> (k, v)
               | _ -> (k, walk (Lpath.key path k) (Lpath.Key k :: rel) v))
             kvs)
    | j -> j
  in
  walk Lpath.root [] j

(* ---------------------------------------------------------------------- *)

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

let sink_j ctx ~base_dir path j =
  match Dec.obj ctx path ~keys:[ "type"; "path" ] j with
  | None -> None
  | Some kvs -> (
      match
        Dec.req ctx kvs path "type"
          (Dec.enum ctx ~values:[ ("stdout", `Stdout); ("file", `File) ])
      with
      | Some `Stdout ->
          if Dec.field kvs "path" <> None then
            Dec.error ctx (Lpath.key path "path") "only allowed for sinks of type file";
          Some Audit_stdout
      | Some `File ->
          Option.map
            (fun f -> Audit_file (Dec.absolute ?base_dir f))
            (Dec.req ctx kvs path "path" (Dec.non_empty_string ctx))
      | None -> None)

type policy_entry = {
  pname : string;
  pol : Policy.t;
  pfile : string option;
  ppath : Lpath.t;
}

let policy_entry_j ctx ~base_dir path j =
  match Dec.obj ctx path ~keys:[ "path"; "inline" ] j with
  | None -> None
  | Some kvs -> (
      match (Dec.field kvs "path", Dec.field kvs "inline") with
      | Some _, Some _ ->
          Dec.error ctx path "use either path or inline, not both";
          None
      | None, None ->
          Dec.error ctx path "a policy entry needs path or inline";
          None
      | Some pv, None -> (
          let pp = Lpath.key path "path" in
          match Dec.non_empty_string ctx pp pv with
          | None -> None
          | Some f -> (
              let abs = Dec.absolute ?base_dir f in
              match Policy_impl.of_file abs with
              | Ok pol -> Some { pname = pol.name; pol; pfile = Some abs; ppath = path }
              | Error errs ->
                  Dec.error ctx pp (Printf.sprintf "cannot load policy %S" abs);
                  Dec.add_errors ctx errs;
                  None))
      | None, Some iv ->
          Option.map
            (fun (pol : Policy.t) ->
              { pname = pol.name; pol; pfile = None; ppath = path })
            (Policy_impl.decode ctx ?base_dir ~inline:true (Lpath.key path "inline") iv))

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
  ]

let parse_bool_env s =
  match String.lowercase_ascii (String.trim s) with
  | "1" | "true" | "yes" | "on" -> Some true
  | "0" | "false" | "no" | "off" -> Some false
  | _ -> None

let decode ctx ~base_dir ~env (j : Yojson.Safe.t) : t option =
  match Dec.obj ctx Lpath.root ~keys:top_keys j with
  | None -> None
  | Some kvs ->
      let root = Lpath.root in
      Dec.header ctx kvs root ~kind:"Config";
      let c = ref default in
      (* server *)
      ignore
        (Dec.opt kvs root "server" (fun p v ->
             match Dec.obj ctx p ~keys:[ "listen"; "tls"; "auth" ] v with
             | None -> None
             | Some s ->
                 Option.iter
                   (fun l -> c := { !c with listen = l })
                   (Dec.opt s p "listen" (listen_j ctx));
                 ignore
                   (Dec.opt s p "tls" (fun p v ->
                        match Dec.obj ctx p ~keys:[ "cert"; "key" ] v with
                        | None -> None
                        | Some t ->
                            let cert = Dec.opt t p "cert" (Dec.non_empty_string ctx) in
                            let key = Dec.opt t p "key" (Dec.non_empty_string ctx) in
                            (match (cert, key) with
                            | Some _, None ->
                                Dec.error ctx (Lpath.key p "key")
                                  "required when tls.cert is set"
                            | None, Some _ ->
                                Dec.error ctx (Lpath.key p "cert")
                                  "required when tls.key is set"
                            | _ -> ());
                            c := { !c with tls_cert = cert; tls_key = key };
                            Some ()));
                 ignore
                   (Dec.opt s p "auth" (fun p v ->
                        match
                          Dec.obj ctx p ~keys:[ "tokens"; "allow_unauthenticated" ] v
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
                            Some ()));
                 Some ()));
      (* policies *)
      let entries =
        Option.value ~default:[]
          (Dec.opt kvs root "policies" (fun p v ->
               Dec.list_of ctx p (policy_entry_j ctx ~base_dir) v))
      in
      let policies_failed = Dec.has_errors ctx in
      let seen = Hashtbl.create 8 in
      List.iter
        (fun e ->
          if Hashtbl.mem seen e.pname then
            Dec.error ctx e.ppath (Printf.sprintf "duplicate policy name %S" e.pname)
          else Hashtbl.add seen e.pname ())
        entries;
      c :=
        {
          !c with
          policies = List.map (fun e -> (e.pname, e.pol)) entries;
          policy_files = List.filter_map (fun e -> e.pfile) entries;
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
                   (fun s -> c := { !c with audit_sinks = s })
                   (Dec.opt a p "sinks" (fun p v ->
                        Dec.list_of ctx p (sink_j ctx ~base_dir) v));
                 Option.iter
                   (fun b -> c := { !c with log_raw_sql = b })
                   (Dec.opt a p "log_raw_sql" (Dec.bool ctx));
                 Some ()));
      ignore
        (Dec.opt kvs root "telemetry" (fun p v ->
             match Dec.obj ctx p ~keys:[ "metrics"; "otlp_endpoint" ] v with
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
                 (* accepted for forward compatibility; not used by v1 *)
                 ignore (Dec.opt t p "otlp_endpoint" (Dec.string ctx));
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
      let tokens_path i k =
        Lpath.key
          (Lpath.idx (Lpath.key (Lpath.key (Lpath.key root "server") "auth") "tokens") i)
          k
      in
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
          if (not policies_failed) && not (List.mem t.token_policy names) then
            Dec.error ctx (tokens_path i "policy")
              (Printf.sprintf "unknown policy %S (loaded: %s)" t.token_policy
                 (if names = [] then "none" else String.concat ", " names)))
        cfg.tokens;
      (match cfg.default_policy with
      | Some d when (not policies_failed) && not (List.mem d names) ->
          Dec.error ctx
            (Lpath.key root "default_policy")
            (Printf.sprintf "unknown policy %S (loaded: %s)" d
               (if names = [] then "none" else String.concat ", " names))
      | _ -> ());
      Some cfg

let of_json_pos ?file ?base_dir ?env ?positions j =
  let env = match env with Some e -> e | None -> Sys.getenv_opt in
  let ctx = Dec.create ?file ?positions () in
  let base_dir = Dec.base_dir_of ?base_dir file in
  let j = resolve_tree ctx ~env ~base_dir j in
  match decode ctx ~base_dir ~env j with
  | Some c when not (Dec.has_errors ctx) -> Ok c
  | _ -> Error (Dec.errors ctx)

let of_json ?file ?base_dir ?env j = of_json_pos ?file ?base_dir ?env j

let of_file ?env file =
  match Docpos.parse_file file with
  | Error e -> Error e
  | Ok (j, positions) ->
      of_json_pos ~file ~base_dir:(Filename.dirname file) ?env ~positions j

let redacted = `String "<redacted>"

let to_json_redacted (c : t) : Yojson.Safe.t =
  let opt_s = function Some s -> `String s | None -> `Null in
  `Assoc
    [
      ("apiVersion", `String "haltsql.dev/v1");
      ("kind", `String "Config");
      ( "server",
        `Assoc
          [
            ("listen", `String c.listen);
            ( "tls",
              `Assoc
                [
                  ("cert", opt_s c.tls_cert);
                  ("key", match c.tls_key with Some _ -> redacted | None -> `Null);
                ] );
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
      ("default_policy", opt_s c.default_policy);
      ("reload", `Assoc [ ("watch", `Bool c.reload_watch) ]);
      ( "audit",
        `Assoc
          [
            ( "sinks",
              `List
                (List.map
                   (function
                     | Audit_stdout -> `Assoc [ ("type", `String "stdout") ]
                     | Audit_file f ->
                         `Assoc [ ("type", `String "file"); ("path", `String f) ])
                   c.audit_sinks) );
            ("log_raw_sql", `Bool c.log_raw_sql);
          ] );
      ("telemetry", `Assoc [ ("metrics", `Assoc [ ("prometheus", `Bool c.metrics) ]) ]);
      ( "logging",
        `Assoc [ ("level", `String c.log_level); ("format", `String c.log_format) ] );
      ("limits", `Assoc [ ("max_request_bytes", `Int c.max_request_bytes) ]);
    ]
