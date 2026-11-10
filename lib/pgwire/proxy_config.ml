(** ProxyConfig decoding; see proxy_config.mli. *)

open Haltsql

type client_auth = Client_cert_none | Client_cert_optional | Client_cert_require

type client_tls = {
  certificates : X509.Certificate.t list * X509.Private_key.t;
  client_ca : X509.Certificate.t list;
  client_auth : client_auth;
  tls_required : bool;
}

type upstream_tls_mode = Tls_disable | Tls_require | Tls_verify_full

type upstream = {
  host : string;
  port : int;
  database : string;
  user : string;
  password : string option;
  tls_mode : upstream_tls_mode;
  tls_ca : X509.Certificate.t list;
  connect_timeout : float;
}

type binding = { policy_name : string; policy : Policy.t; context : Context.t }
type user = { user_name : string; verifier : Scram.verifier; user_binding : binding }
type identity_match = Subject_cn of string | Spiffe_id of string
type identity = { id_match : identity_match; id_binding : binding }
type auth = Scram_users of user list | Cert_identities of identity list

type limits = {
  max_connections : int;
  max_message_bytes : int;
  idle_timeout : float;
  auth_timeout : float;
  worker_threads : int;
}

type audit_sink = Audit_stdout | Audit_file of string | Audit_none
type audit_on_error = Audit_fail_closed | Audit_buffer | Audit_drop

type audit_sink_spec = {
  sink : Config.sink_kind;
  sink_on_error : audit_on_error;
  max_buffer_records : int;
}

type reload = { watch : bool; poll_interval : float }

type t = {
  listen_host : string;
  listen_port : int;
  tls : client_tls option;
  upstream : upstream;
  policies : (string * Policy.t) list;
  auth : auth;
  limits : limits;
  deny_sqlstate : string;
  allow_transaction_control : bool;
  audit : audit_sink;
  audit_sinks : audit_sink_spec list;
  log_raw_sql : bool;
  log_level : string;
  shutdown_grace : float;
  reload : reload;
  source_files : string list;
}

let kind = "ProxyConfig"
let api_version = "haltsql.dev/v1"
let max_secret_file_bytes = 1024 * 1024

(* ------------------------------------------------------------------ *)
(* Error collection                                                     *)

type ctx = {
  file : string option;
  base_dir : string option;
  errors : Load_error.t list ref;
  files : string list ref;  (** every file read, for the reload watcher *)
}

let note_file ctx path =
  let path =
    if Filename.is_relative path then Filename.concat (Sys.getcwd ()) path else path
  in
  if not (List.mem path !(ctx.files)) then ctx.files := path :: !(ctx.files)

let error ctx path msg =
  ctx.errors := Load_error.make ?file:ctx.file ~path msg :: !(ctx.errors)

let key path k = if path = "" then k else path ^ "." ^ k
let idx path i = Printf.sprintf "%s[%d]" path i

let absolute ctx p =
  if Filename.is_relative p then
    match ctx.base_dir with Some d -> Filename.concat d p | None -> p
  else p

let read_file ctx path limit =
  note_file ctx path;
  match open_in_bin path with
  | exception Sys_error e -> Error e
  | ic ->
      Fun.protect
        ~finally:(fun () -> close_in_noerr ic)
        (fun () ->
          let n = in_channel_length ic in
          if n > limit then Error (Printf.sprintf "file larger than %d bytes" limit)
          else
            match really_input_string ic n with
            | s -> Ok s
            | exception End_of_file -> Error "file changed while it was being read")

(* ------------------------------------------------------------------ *)
(* ${env:NAME} / ${file:/path} placeholders                             *)

let valid_env_name s =
  s <> ""
  && (match s.[0] with 'A' .. 'Z' | 'a' .. 'z' | '_' -> true | _ -> false)
  && String.for_all
       (function 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' -> true | _ -> false)
       s

let trim_newline s =
  let n = String.length s in
  if n >= 2 && String.sub s (n - 2) 2 = "\r\n" then String.sub s 0 (n - 2)
  else if n >= 1 && s.[n - 1] = '\n' then String.sub s 0 (n - 1)
  else s

let resolve_string ctx path ~env s =
  let n = String.length s in
  let b = Buffer.create n in
  let rec go i =
    if i >= n then ()
    else if i + 2 < n && s.[i] = '$' && s.[i + 1] = '$' && s.[i + 2] = '{' then (
      Buffer.add_string b "${";
      go (i + 3))
    else if i + 1 < n && s.[i] = '$' && s.[i + 1] = '{' then (
      match String.index_from_opt s (i + 2) '}' with
      | None -> error ctx path "unterminated placeholder (missing '}')"
      | Some j ->
          let inner = String.sub s (i + 2) (j - i - 2) in
          let pre p =
            String.length inner >= String.length p
            && String.sub inner 0 (String.length p) = p
          in
          let rest p =
            String.sub inner (String.length p) (String.length inner - String.length p)
          in
          if pre "env:" then
            let name = rest "env:" in
            if not (valid_env_name name) then
              error ctx path (Printf.sprintf "invalid environment variable name %S" name)
            else
              match env name with
              | Some v -> Buffer.add_string b v
              | None ->
                  error ctx path
                    (Printf.sprintf "environment variable %s is not set" name)
          else if pre "file:" then
            let f = rest "file:" in
            if f = "" then error ctx path "empty file path in ${file:...}"
            else
              match read_file ctx (absolute ctx f) max_secret_file_bytes with
              | Ok c -> Buffer.add_string b (trim_newline c)
              | Error e -> error ctx path (Printf.sprintf "${file:%s}: %s" f e)
          else
            error ctx path
              (Printf.sprintf
                 "unknown placeholder ${%s} (ProxyConfig supports ${env:NAME} and \
                  ${file:/path})"
                 inner);
          go (j + 1))
    else (
      Buffer.add_char b s.[i];
      go (i + 1))
  in
  go 0;
  Buffer.contents b

let resolve_tree ctx ~env (j : Yojson.Safe.t) =
  let rec walk path (j : Yojson.Safe.t) : Yojson.Safe.t =
    match j with
    | `String s -> `String (resolve_string ctx path ~env s)
    | `List l -> `List (List.mapi (fun i x -> walk (idx path i) x) l)
    | `Assoc kvs -> `Assoc (List.map (fun (k, v) -> (k, walk (key path k) v)) kvs)
    | j -> j
  in
  (* policies[i].inline is left untouched: placeholders are not allowed in policies *)
  match j with
  | `Assoc kvs ->
      `Assoc
        (List.map
           (fun (k, v) ->
             if k = "policies" then
               match v with
               | `List l ->
                   ( k,
                     `List
                       (List.mapi
                          (fun i item ->
                            match item with
                            | `Assoc ikvs ->
                                `Assoc
                                  (List.map
                                     (fun (ik, iv) ->
                                       if ik = "inline" then (ik, iv)
                                       else (ik, walk (key (idx k i) ik) iv))
                                     ikvs)
                            | x -> x)
                          l) )
               | v -> (k, v)
             else (k, walk k v))
           kvs)
  | j -> j

(* ------------------------------------------------------------------ *)
(* Typed accessors                                                      *)

let type_name : Yojson.Safe.t -> string = function
  | `Null -> "null"
  | `Bool _ -> "a boolean"
  | `Int _ | `Intlit _ -> "an integer"
  | `Float _ -> "a number"
  | `String _ -> "a string"
  | `List _ -> "a list"
  | `Assoc _ -> "an object"

let obj ctx path ~keys (j : Yojson.Safe.t) =
  match j with
  | `Assoc kvs ->
      List.iter
        (fun (k, _) ->
          if not (List.mem k keys) then
            error ctx (key path k)
              (Printf.sprintf "unknown key (expected one of: %s)"
                 (String.concat ", " keys)))
        kvs;
      Some kvs
  | j ->
      error ctx path ("expected an object, got " ^ type_name j);
      None

let field kvs k = List.assoc_opt k kvs

let str ctx path = function
  | `String s ->
      if String.contains s '\000' then (
        error ctx path "string contains a NUL byte";
        None)
      else Some s
  | j ->
      error ctx path ("expected a string, got " ^ type_name j);
      None

let int ctx path ~min ~max = function
  | `Int i when i >= min && i <= max -> Some i
  | `Int i ->
      error ctx path (Printf.sprintf "%d is out of range [%d, %d]" i min max);
      None
  | j ->
      error ctx path ("expected an integer, got " ^ type_name j);
      None

let number ctx path ~min ~max = function
  | (`Int _ | `Float _) as j ->
      let f = match j with `Int i -> float_of_int i | `Float f -> f | _ -> 0. in
      if Float.is_nan f || f < min || f > max then (
        error ctx path (Printf.sprintf "%g is out of range [%g, %g]" f min max);
        None)
      else Some f
  | j ->
      error ctx path ("expected a number, got " ^ type_name j);
      None

let bool ctx path = function
  | `Bool b -> Some b
  | j ->
      error ctx path ("expected a boolean, got " ^ type_name j);
      None

let enum ctx path choices j =
  match str ctx path j with
  | None -> None
  | Some s -> (
      match List.assoc_opt s choices with
      | Some v -> Some v
      | None ->
          error ctx path
            (Printf.sprintf "invalid value %S (expected one of: %s)" s
               (String.concat ", " (List.map fst choices)));
          None)

let required ctx path kvs k f =
  match field kvs k with
  | None ->
      error ctx (key path k) "required";
      None
  | Some j -> f (key path k) j

let optional kvs k ~default path f =
  match field kvs k with None -> default | Some j -> f (key path k) j

let non_empty ctx path = function
  | Some "" ->
      error ctx path "must not be empty";
      None
  | x -> x

(* ------------------------------------------------------------------ *)
(* TLS material                                                         *)

(* A TLS value is either inline PEM (what a [${file:...}] or [${env:...}] placeholder
   expands to) or a path to a PEM file. *)
let is_inline_pem v =
  let marker = "-----BEGIN" in
  let n = String.length v and m = String.length marker in
  let rec go i = i + m <= n && (String.sub v i m = marker || go (i + 1)) in
  go 0

(* The reason part of a [read_file] error, without the path: the "path" may be key
   material that was mistakenly given where a path was expected. *)
let reason_only e =
  match String.rindex_opt e ':' with
  | Some i when i + 1 < String.length e ->
      String.trim (String.sub e (i + 1) (String.length e - i - 1))
  | _ -> "unreadable"

let pem_text ctx v =
  if is_inline_pem v then Ok v else read_file ctx (absolute ctx v) max_secret_file_bytes

let load_certs ctx path p =
  match pem_text ctx p with
  | Error e ->
      error ctx path ("cannot read certificate file: " ^ reason_only e);
      None
  | Ok pem -> (
      match X509.Certificate.decode_pem_multiple pem with
      | Ok (_ :: _ as cs) -> Some cs
      | Ok [] ->
          error ctx path "no certificate found";
          None
      | Error (`Msg _) ->
          error ctx path "invalid PEM certificate";
          None)

(* Never echo the value or the decoder's message: either may contain key bytes. *)
let load_key ctx path p =
  match pem_text ctx p with
  | Error e ->
      error ctx path
        ("cannot read private key file: " ^ reason_only e
       ^ " (give a path to a PEM file, or inline PEM via ${file:...})");
      None
  | Ok pem -> (
      match X509.Private_key.decode_pem pem with
      | Ok k -> Some k
      | Error (`Msg _) ->
          error ctx path "invalid PEM private key";
          None)

let client_tls_j ctx path j =
  match
    obj ctx path ~keys:[ "cert"; "key"; "client_ca"; "client_auth"; "required" ] j
  with
  | None -> None
  | Some kvs -> (
      let cert =
        required ctx path kvs "cert" (fun p j ->
            Option.bind (str ctx p j) (load_certs ctx p))
      in
      let key_ =
        required ctx path kvs "key" (fun p j ->
            Option.bind (str ctx p j) (load_key ctx p))
      in
      let client_ca =
        optional kvs "client_ca" ~default:[] path (fun p j ->
            match Option.bind (str ctx p j) (load_certs ctx p) with
            | Some c -> c
            | None -> [])
      in
      let client_auth =
        optional kvs "client_auth" ~default:(Some Client_cert_none) path (fun p j ->
            enum ctx p
              [
                ("none", Client_cert_none);
                ("optional", Client_cert_optional);
                ("require", Client_cert_require);
              ]
              j)
      in
      let tls_required =
        optional kvs "required" ~default:(Some true) path (fun p j -> bool ctx p j)
      in
      (match client_auth with
      | Some (Client_cert_optional | Client_cert_require) when client_ca = [] ->
          if field kvs "client_ca" = None then
            error ctx (key path "client_ca")
              "required when client_auth is optional or require"
      | _ -> ());
      match (cert, key_, client_auth, tls_required) with
      | Some c, Some k, Some ca_mode, Some r ->
          Some
            { certificates = (c, k); client_ca; client_auth = ca_mode; tls_required = r }
      | _ -> None)

let valid_host s =
  s <> ""
  && String.for_all
       (function
         | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '.' | '-' | '_' | ':' -> true
         | _ -> false)
       s

let verifiable_host h =
  Result.is_ok (Ipaddr.of_string h)
  || Result.is_ok (Result.bind (Domain_name.of_string h) Domain_name.host)

let upstream_j ctx path j =
  match
    obj ctx path
      ~keys:
        [
          "host"; "port"; "database"; "user"; "password"; "tls"; "connect_timeout_seconds";
        ]
      j
  with
  | None -> None
  | Some kvs -> (
      let host =
        required ctx path kvs "host" (fun p j ->
            match str ctx p j with
            | Some h when valid_host h -> Some h
            | Some h ->
                error ctx p (Printf.sprintf "invalid host %S" h);
                None
            | None -> None)
      in
      let port =
        optional kvs "port" ~default:(Some 5432) path (fun p j ->
            int ctx p ~min:1 ~max:65535 j)
      in
      let database =
        required ctx path kvs "database" (fun p j -> non_empty ctx p (str ctx p j))
      in
      let user =
        required ctx path kvs "user" (fun p j -> non_empty ctx p (str ctx p j))
      in
      let password =
        optional kvs "password" ~default:(Some None) path (fun p j ->
            Option.map Option.some (str ctx p j))
      in
      let connect_timeout =
        optional kvs "connect_timeout_seconds" ~default:(Some 10.) path (fun p j ->
            number ctx p ~min:0.1 ~max:300. j)
      in
      let verify_full = ref false in
      let tls =
        optional kvs "tls"
          ~default:(Some (Tls_disable, []))
          path
          (fun p j ->
            match obj ctx p ~keys:[ "mode"; "ca" ] j with
            | None -> None
            | Some tk -> (
                let mode =
                  required ctx p tk "mode" (fun p j ->
                      enum ctx p
                        [
                          ("disable", Tls_disable);
                          ("require", Tls_require);
                          ("verify-full", Tls_verify_full);
                        ]
                        j)
                in
                let ca =
                  optional tk "ca" ~default:[] p (fun p j ->
                      match Option.bind (str ctx p j) (load_certs ctx p) with
                      | Some c -> c
                      | None -> [])
                in
                if mode = Some Tls_verify_full then verify_full := true;
                match mode with
                | Some Tls_verify_full when ca = [] && field tk "ca" = None ->
                    error ctx (key p "ca") "required when mode is verify-full";
                    None
                | Some m -> Some (m, ca)
                | None -> None))
      in
      (* verify-full checks the certificate against the host's IP address or DNS name;
         a host that is neither (e.g. "pg_1": '_' is not allowed in host names) could
         only get a chain check, so it is refused (fail closed) *)
      (match host with
      | Some h when !verify_full && not (verifiable_host h) ->
          error ctx (key path "host")
            (Printf.sprintf
               "host %S cannot be verified by tls.mode verify-full: use an IP address or \
                a valid DNS host name (letters, digits, '-' and '.')"
               h)
      | _ -> ());
      match (host, port, database, user, password, connect_timeout, tls) with
      | ( Some host,
          Some port,
          Some database,
          Some user,
          Some password,
          Some connect_timeout,
          Some (tls_mode, tls_ca) ) ->
          Some { host; port; database; user; password; tls_mode; tls_ca; connect_timeout }
      | _ -> None)

let policies_j ctx path j =
  match j with
  | `List items ->
      List.concat
        (List.mapi
           (fun i item ->
             let p = idx path i in
             match obj ctx p ~keys:[ "path"; "inline" ] item with
             | None -> []
             | Some kvs -> (
                 let report errs =
                   List.iter
                     (fun (e : Load_error.t) ->
                       ctx.errors :=
                         { e with path = (if e.path = "" then p else p ^ "." ^ e.path) }
                         :: !(ctx.errors))
                     errs
                 in
                 match (field kvs "path", field kvs "inline") with
                 | Some pj, None -> (
                     match str ctx (key p "path") pj with
                     | None -> []
                     | Some f -> (
                         note_file ctx (absolute ctx f);
                         match Policy_load.of_file (absolute ctx f) with
                         | Ok pol -> [ pol ]
                         | Error errs ->
                             List.iter (fun e -> ctx.errors := e :: !(ctx.errors)) errs;
                             []))
                 | None, Some inline -> (
                     match
                       Policy_load.of_json ?file:ctx.file ?base_dir:ctx.base_dir inline
                     with
                     | Ok pol -> [ pol ]
                     | Error errs ->
                         report errs;
                         [])
                 | _ ->
                     error ctx p "exactly one of path or inline is required";
                     []))
           items)
  | j ->
      error ctx path ("expected a list, got " ^ type_name j);
      []

let binding_j ctx path kvs policies =
  let policy =
    required ctx path kvs "policy" (fun p j ->
        match str ctx p j with
        | None -> None
        | Some name -> (
            match List.assoc_opt name policies with
            | Some pol -> Some (name, pol)
            | None ->
                error ctx p
                  (Printf.sprintf "unknown policy %S (loaded: %s)" name
                     (String.concat ", " (List.map fst policies)));
                None))
  in
  let context =
    optional kvs "context" ~default:(Some Context.empty) path (fun p j ->
        match Context.of_json j with
        | Ok c -> Some c
        | Error e ->
            error ctx p e;
            None)
  in
  match (policy, context) with
  | Some (policy_name, policy), Some context ->
      List.iter
        (fun (_key, field_) ->
          match Context.find context field_ with
          | Some (Context.One _) | Some (Context.Many (_ :: _)) -> ()
          | _ ->
              error ctx (key path "context")
                (Printf.sprintf "policy %S needs context value %S" policy_name field_))
        policy.Policy.tenancy.keys;
      Some { policy_name; policy; context }
  | _ -> None

let valid_user_name s =
  s <> ""
  && String.length s <= 63
  && String.for_all (fun c -> Char.code c >= 0x20 && Char.code c < 0x7f) s

let users_j ctx path j policies =
  match j with
  | `List items ->
      let seen = Hashtbl.create 8 in
      List.filter_map Fun.id
        (List.mapi
           (fun i item ->
             let p = idx path i in
             match
               obj ctx p ~keys:[ "name"; "scram_verifier"; "policy"; "context" ] item
             with
             | None -> None
             | Some kvs -> (
                 let name =
                   required ctx p kvs "name" (fun p j ->
                       match str ctx p j with
                       | Some n when valid_user_name n ->
                           if Hashtbl.mem seen n then (
                             error ctx p (Printf.sprintf "duplicate user %S" n);
                             None)
                           else (
                             Hashtbl.add seen n ();
                             Some n)
                       | Some _ ->
                           error ctx p "user names are 1-63 printable ASCII characters";
                           None
                       | None -> None)
                 in
                 let verifier =
                   required ctx p kvs "scram_verifier" (fun p j ->
                       match str ctx p j with
                       | None -> None
                       | Some v -> (
                           match Scram.parse_verifier v with
                           | Ok v -> Some v
                           | Error e ->
                               error ctx p e;
                               None))
                 in
                 let b = binding_j ctx p kvs policies in
                 match (name, verifier, b) with
                 | Some user_name, Some verifier, Some user_binding ->
                     Some { user_name; verifier; user_binding }
                 | _ -> None))
           items)
  | j ->
      error ctx path ("expected a list, got " ^ type_name j);
      []

let identities_j ctx path j policies =
  match j with
  | `List items ->
      List.filter_map Fun.id
        (List.mapi
           (fun i item ->
             let p = idx path i in
             match
               obj ctx p ~keys:[ "subject_cn"; "spiffe_id"; "policy"; "context" ] item
             with
             | None -> None
             | Some kvs -> (
                 let m =
                   match (field kvs "subject_cn", field kvs "spiffe_id") with
                   | Some j, None ->
                       Option.map
                         (fun s -> Subject_cn s)
                         (non_empty ctx (key p "subject_cn")
                            (str ctx (key p "subject_cn") j))
                   | None, Some j -> (
                       match str ctx (key p "spiffe_id") j with
                       | Some s when String.length s > 9 && String.sub s 0 9 = "spiffe://"
                         ->
                           Some (Spiffe_id s)
                       | Some _ ->
                           error ctx (key p "spiffe_id") "must start with spiffe://";
                           None
                       | None -> None)
                   | _ ->
                       error ctx p "exactly one of subject_cn or spiffe_id is required";
                       None
                 in
                 let b = binding_j ctx p kvs policies in
                 match (m, b) with
                 | Some id_match, Some id_binding -> Some { id_match; id_binding }
                 | _ -> None))
           items)
  | j ->
      error ctx path ("expected a list, got " ^ type_name j);
      []

(* ------------------------------------------------------------------ *)
(* Audit sinks                                                          *)

let audit_on_error_values =
  [ ("fail_closed", Audit_fail_closed); ("buffer", Audit_buffer); ("drop", Audit_drop) ]

let default_max_buffer = function
  | Config.Sink_stdout | Config.Sink_file _ -> 10_000
  | Config.Sink_s3 _ | Config.Sink_gcs _ -> 100_000

let replace_all s ~sub ~by =
  let n = String.length s and m = String.length sub in
  let b = Buffer.create n in
  let rec go i =
    if i >= n then ()
    else if i + m <= n && String.sub s i m = sub then (
      Buffer.add_string b by;
      go (i + m))
    else (
      Buffer.add_char b s.[i];
      go (i + 1))
  in
  go 0;
  Buffer.contents b

(* Strings here are already resolved: a "${" left in one is literal and must stay
   literal when Haltsql.Config (which resolves placeholders itself) decodes it again. *)
let rec escape_placeholders (j : Yojson.Safe.t) : Yojson.Safe.t =
  match j with
  | `String s -> `String (replace_all s ~sub:"${" ~by:"$${")
  | `List l -> `List (List.map escape_placeholders l)
  | `Assoc kvs -> `Assoc (List.map (fun (k, v) -> (k, escape_placeholders v)) kvs)
  | j -> j

(* stdout / file / s3 / gcs sinks are decoded by Haltsql.Config, exactly as the
   server's audit.sinks entries, so both components accept the same sink syntax. *)
let delegate_sink ctx path kvs =
  let doc =
    `Assoc
      [
        ("apiVersion", `String api_version);
        ("kind", `String "Config");
        ("audit", `Assoc [ ("sinks", `List [ escape_placeholders (`Assoc kvs) ]) ]);
      ]
  in
  match Config.of_json ?file:ctx.file ?base_dir:ctx.base_dir ~env:(fun _ -> None) doc with
  | Ok { Config.sinks = [ s ]; _ } -> Some s.Config.sink
  | Ok _ ->
      error ctx path "invalid audit sink";
      None
  | Error errs ->
      let pre = "audit.sinks[0]" in
      let lp = String.length pre in
      List.iter
        (fun (e : Load_error.t) ->
          let p =
            if String.length e.path >= lp && String.sub e.path 0 lp = pre then
              path ^ String.sub e.path lp (String.length e.path - lp)
            else if e.path = "" then path
            else key path e.path
          in
          ctx.errors := { e with path = p } :: !(ctx.errors))
        errs;
      None

(* [on_error] and [max_buffer_records] (proxy-level delivery policy), shared by the
   single-sink form and the entries of [sinks]. *)
let delivery_j ctx path kvs =
  let on_error =
    optional kvs "on_error" ~default:(Some Audit_fail_closed) path (fun p j ->
        enum ctx p audit_on_error_values j)
  in
  let mbr =
    optional kvs "max_buffer_records" ~default:(Some None) path (fun p j ->
        Option.map Option.some (int ctx p ~min:1 ~max:1_000_000 j))
  in
  (match (on_error, mbr) with
  | Some (Audit_fail_closed | Audit_drop), Some (Some _) ->
      error ctx (key path "max_buffer_records") "only allowed with on_error: buffer"
  | _ -> ());
  match (on_error, mbr) with Some o, Some m -> Some (o, m) | _ -> None

let spec_of sink (on_error, mbr) =
  {
    sink;
    sink_on_error = on_error;
    max_buffer_records = Option.value mbr ~default:(default_max_buffer sink);
  }

let audit_sink_item ctx path j =
  match j with
  | `Assoc kvs -> (
      let ty_ok =
        match field kvs "type" with
        | Some (`String ("stdout" | "file" | "s3" | "gcs")) -> true
        | Some (`String ("elasticsearch" | "kafka")) ->
            error ctx (key path "type")
              "not supported by haltsql-proxy (supported: stdout, file, s3, gcs)";
            false
        | Some (`String s) ->
            error ctx (key path "type")
              (Printf.sprintf "invalid value %S (expected one of: stdout, file, s3, gcs)"
                 s);
            false
        | Some j ->
            error ctx (key path "type") ("expected a string, got " ^ type_name j);
            false
        | None ->
            error ctx (key path "type") "required";
            false
      in
      let delivery = delivery_j ctx path kvs in
      if not ty_ok then None
      else
        let kvs' =
          List.filter_map
            (fun (k, v) ->
              match k with
              | "max_buffer_records" -> None
              | "on_error" -> (
                  match delivery with
                  | Some (Audit_buffer, _) -> Some (k, `String "buffer")
                  | _ -> None)
              | _ -> Some (k, v))
            kvs
        in
        match (delegate_sink ctx path kvs', delivery) with
        | Some sink, Some d -> Some (spec_of sink d)
        | _ -> None)
  | j ->
      error ctx path ("expected an object, got " ^ type_name j);
      None

let audit_j ctx p j =
  match
    obj ctx p
      ~keys:[ "type"; "path"; "on_error"; "max_buffer_records"; "sinks"; "log_raw_sql" ]
      j
  with
  | None -> None
  | Some ak -> (
      let raw =
        optional ak "log_raw_sql" ~default:(Some false) p (fun p j -> bool ctx p j)
      in
      let sinks =
        match field ak "sinks" with
        | Some sj -> (
            List.iter
              (fun k ->
                if field ak k <> None then
                  error ctx (key p k) "not allowed together with sinks")
              [ "type"; "path"; "on_error"; "max_buffer_records" ];
            let sp = key p "sinks" in
            match sj with
            | `List [] ->
                error ctx sp "at least one sink is required (use type: none for no audit)";
                None
            | `List items ->
                let specs =
                  List.mapi (fun i it -> audit_sink_item ctx (idx sp i) it) items
                in
                if List.for_all Option.is_some specs then
                  Some (List.filter_map Fun.id specs)
                else None
            | j ->
                error ctx sp ("expected a list, got " ^ type_name j);
                None)
        | None -> (
            let delivery = delivery_j ctx p ak in
            match
              required ctx p ak "type" (fun p j ->
                  enum ctx p [ ("stdout", `Stdout); ("file", `File); ("none", `None) ] j)
            with
            | Some `Stdout ->
                if field ak "path" <> None then
                  error ctx (key p "path") "only allowed with type: file";
                Option.map (fun d -> [ spec_of Config.Sink_stdout d ]) delivery
            | Some `None ->
                List.iter
                  (fun k ->
                    if field ak k <> None then
                      error ctx (key p k) "not allowed with type: none")
                  [ "path"; "on_error"; "max_buffer_records" ];
                Some []
            | Some `File -> (
                match
                  required ctx p ak "path" (fun pp j ->
                      Option.map (absolute ctx) (non_empty ctx pp (str ctx pp j)))
                with
                | Some f ->
                    Option.map (fun d -> [ spec_of (Config.Sink_file f) d ]) delivery
                | None -> None)
            | None -> None)
      in
      (* two sinks writing one file (or sharing a spool) would interleave two chains *)
      (match sinks with
      | Some specs ->
          let seen = Hashtbl.create 4 in
          List.iteri
            (fun i s ->
              let where = if field ak "sinks" = None then p else idx (key p "sinks") i in
              let claim what v =
                if Hashtbl.mem seen (what, v) then
                  error ctx where
                    (Printf.sprintf "%s %S is used by more than one audit sink" what v)
                else Hashtbl.add seen (what, v) ()
              in
              match s.sink with
              | Config.Sink_stdout -> claim "output" "stdout"
              | Config.Sink_file f -> claim "file" f
              | Config.Sink_s3 c -> Option.iter (claim "spool_dir") c.s3_spool_dir
              | Config.Sink_gcs c -> Option.iter (claim "spool_dir") c.gcs_spool_dir)
            specs
      | None -> ());
      match (sinks, raw) with Some s, Some r -> Some (s, r) | _ -> None)

let legacy_audit specs =
  match
    List.find_map
      (fun s ->
        match s.sink with
        | Config.Sink_stdout -> Some Audit_stdout
        | Config.Sink_file f -> Some (Audit_file f)
        | Config.Sink_s3 _ | Config.Sink_gcs _ -> None)
      specs
  with
  | Some a -> a
  | None -> Audit_none

let valid_sqlstate s =
  String.length s = 5
  && String.for_all (function '0' .. '9' | 'A' .. 'Z' -> true | _ -> false) s

let decode ctx (j : Yojson.Safe.t) =
  let top =
    [
      "apiVersion";
      "kind";
      "listen";
      "tls";
      "upstream";
      "policies";
      "auth";
      "limits";
      "deny_sqlstate";
      "allow_transaction_control";
      "audit";
      "logging";
      "shutdown_grace_seconds";
      "reload";
    ]
  in
  match obj ctx "" ~keys:top j with
  | None -> None
  | Some kvs -> (
      (match field kvs "apiVersion" with
      | Some (`String v) when v = api_version -> ()
      | Some _ -> error ctx "apiVersion" (Printf.sprintf "expected %S" api_version)
      | None -> error ctx "apiVersion" "required");
      (match field kvs "kind" with
      | Some (`String k) when k = kind -> ()
      | Some _ -> error ctx "kind" (Printf.sprintf "expected %S" kind)
      | None -> error ctx "kind" "required");
      let listen =
        optional kvs "listen"
          ~default:(Some ("127.0.0.1", 6432))
          ""
          (fun p j ->
            match str ctx p j with
            | None -> None
            | Some s -> (
                match String.rindex_opt s ':' with
                | Some i ->
                    let h = String.sub s 0 i
                    and port = String.sub s (i + 1) (String.length s - i - 1) in
                    let h =
                      if
                        String.length h >= 2
                        && h.[0] = '['
                        && h.[String.length h - 1] = ']'
                      then String.sub h 1 (String.length h - 2)
                      else h
                    in
                    if
                      valid_host h && port <> ""
                      && String.length port <= 5
                      && String.for_all (function '0' .. '9' -> true | _ -> false) port
                      && int_of_string port >= 0
                      && int_of_string port <= 65535
                    then Some (h, int_of_string port)
                    else (
                      error ctx p
                        (Printf.sprintf "invalid listen address %S (expected host:port)" s);
                      None)
                | None ->
                    error ctx p
                      (Printf.sprintf "invalid listen address %S (expected host:port)" s);
                    None))
      in
      let tls =
        optional kvs "tls" ~default:(Some None) "" (fun p j ->
            Option.map Option.some (client_tls_j ctx p j))
      in
      let upstream = required ctx "" kvs "upstream" (fun p j -> upstream_j ctx p j) in
      let policies =
        match field kvs "policies" with
        | None ->
            error ctx "policies" "required";
            []
        | Some j -> policies_j ctx "policies" j
      in
      let policies =
        let seen = Hashtbl.create 8 in
        List.filter_map
          (fun (pol : Policy.t) ->
            if Hashtbl.mem seen pol.name then (
              error ctx "policies" (Printf.sprintf "duplicate policy name %S" pol.name);
              None)
            else (
              Hashtbl.add seen pol.name ();
              Some (pol.name, pol)))
          policies
      in
      let auth =
        required ctx "" kvs "auth" (fun p j ->
            match obj ctx p ~keys:[ "method"; "users"; "identities" ] j with
            | None -> None
            | Some ak -> (
                match
                  required ctx p ak "method" (fun p j ->
                      enum ctx p [ ("scram", `Scram); ("cert", `Cert) ] j)
                with
                | None -> None
                | Some `Scram ->
                    if field ak "identities" <> None then
                      error ctx (key p "identities") "only allowed with method: cert";
                    let users =
                      match field ak "users" with
                      | None ->
                          error ctx (key p "users") "required for method: scram";
                          []
                      | Some j -> users_j ctx (key p "users") j policies
                    in
                    if users = [] && field ak "users" <> None then
                      error ctx (key p "users") "at least one user is required";
                    Some (Scram_users users)
                | Some `Cert ->
                    if field ak "users" <> None then
                      error ctx (key p "users") "only allowed with method: scram";
                    let ids =
                      match field ak "identities" with
                      | None ->
                          error ctx (key p "identities") "required for method: cert";
                          []
                      | Some j -> identities_j ctx (key p "identities") j policies
                    in
                    if ids = [] && field ak "identities" <> None then
                      error ctx (key p "identities") "at least one identity is required";
                    Some (Cert_identities ids)))
      in
      let limits =
        optional kvs "limits"
          ~default:
            (Some
               {
                 max_connections = 100;
                 max_message_bytes = 1_048_576;
                 idle_timeout = 0.;
                 auth_timeout = 30.;
                 worker_threads = Offload.default_threads ();
               })
          ""
          (fun p j ->
            match
              obj ctx p
                ~keys:
                  [
                    "max_connections";
                    "max_message_bytes";
                    "idle_timeout_seconds";
                    "auth_timeout_seconds";
                    "worker_threads";
                  ]
                j
            with
            | None -> None
            | Some lk -> (
                let mc =
                  optional lk "max_connections" ~default:(Some 100) p (fun p j ->
                      int ctx p ~min:1 ~max:100_000 j)
                in
                let mm =
                  optional lk "max_message_bytes" ~default:(Some 1_048_576) p (fun p j ->
                      int ctx p ~min:1024 ~max:(1024 * 1024 * 1024) j)
                in
                let it =
                  optional lk "idle_timeout_seconds" ~default:(Some 0.) p (fun p j ->
                      number ctx p ~min:0. ~max:604800. j)
                in
                let at =
                  optional lk "auth_timeout_seconds" ~default:(Some 30.) p (fun p j ->
                      number ctx p ~min:1. ~max:600. j)
                in
                let wt =
                  optional lk "worker_threads"
                    ~default:(Some (Offload.default_threads ()))
                    p
                    (fun p j -> int ctx p ~min:1 ~max:64 j)
                in
                match (mc, mm, it, at, wt) with
                | ( Some max_connections,
                    Some max_message_bytes,
                    Some idle_timeout,
                    Some auth_timeout,
                    Some worker_threads ) ->
                    Some
                      {
                        max_connections;
                        max_message_bytes;
                        idle_timeout;
                        auth_timeout;
                        worker_threads;
                      }
                | _ -> None))
      in
      let deny_sqlstate =
        optional kvs "deny_sqlstate" ~default:(Some "42501") "" (fun p j ->
            match str ctx p j with
            | Some s when valid_sqlstate s -> Some s
            | Some s ->
                error ctx p (Printf.sprintf "invalid SQLSTATE %S (5 characters 0-9A-Z)" s);
                None
            | None -> None)
      in
      let allow_tx =
        optional kvs "allow_transaction_control" ~default:(Some true) "" (fun p j ->
            bool ctx p j)
      in
      let audit =
        optional kvs "audit"
          ~default:
            (Some
               ( [
                   {
                     sink = Config.Sink_stdout;
                     sink_on_error = Audit_fail_closed;
                     max_buffer_records = default_max_buffer Config.Sink_stdout;
                   };
                 ],
                 false ))
          "" (audit_j ctx)
      in
      let reload =
        optional kvs "reload"
          ~default:(Some { watch = false; poll_interval = 2. })
          ""
          (fun p j ->
            match obj ctx p ~keys:[ "watch"; "poll_interval_seconds" ] j with
            | None -> None
            | Some rk -> (
                let watch =
                  optional rk "watch" ~default:(Some false) p (fun p j -> bool ctx p j)
                in
                let poll =
                  optional rk "poll_interval_seconds" ~default:(Some 2.) p (fun p j ->
                      number ctx p ~min:0.1 ~max:3600. j)
                in
                match (watch, poll) with
                | Some watch, Some poll_interval -> Some { watch; poll_interval }
                | _ -> None))
      in
      let log_level =
        optional kvs "logging" ~default:(Some "info") "" (fun p j ->
            match obj ctx p ~keys:[ "level" ] j with
            | None -> None
            | Some lk ->
                optional lk "level" ~default:(Some "info") p (fun p j ->
                    enum ctx p
                      [
                        ("debug", "debug");
                        ("info", "info");
                        ("warn", "warn");
                        ("error", "error");
                      ]
                      j))
      in
      let shutdown_grace =
        optional kvs "shutdown_grace_seconds" ~default:(Some 10.) "" (fun p j ->
            number ctx p ~min:0. ~max:3600. j)
      in
      (* cross-field checks *)
      (match (auth, tls) with
      | Some (Cert_identities _), Some (Some t) when t.client_auth <> Client_cert_require
        ->
          error ctx "tls.client_auth" "must be require when auth.method is cert"
      | Some (Cert_identities _), Some (Some t) when not t.tls_required ->
          error ctx "tls.required" "must be true when auth.method is cert"
      | Some (Cert_identities _), Some None ->
          error ctx "tls" "required when auth.method is cert"
      | _ -> ());
      match
        ( listen,
          tls,
          upstream,
          auth,
          limits,
          deny_sqlstate,
          audit,
          log_level,
          shutdown_grace,
          allow_tx,
          reload )
      with
      | ( Some (listen_host, listen_port),
          Some tls,
          Some upstream,
          Some auth,
          Some limits,
          Some deny_sqlstate,
          Some (audit_sinks, log_raw_sql),
          Some log_level,
          Some shutdown_grace,
          Some allow_transaction_control,
          Some reload ) ->
          Some
            {
              listen_host;
              listen_port;
              tls;
              upstream;
              policies;
              auth;
              limits;
              deny_sqlstate;
              allow_transaction_control;
              audit = legacy_audit audit_sinks;
              audit_sinks;
              log_raw_sql;
              log_level;
              shutdown_grace;
              reload;
              source_files = List.rev !(ctx.files);
            }
      | _ -> None)

let of_json ?file ?base_dir ?(env = Sys.getenv_opt) j =
  let ctx = { file; base_dir; errors = ref []; files = ref [] } in
  let j = resolve_tree ctx ~env j in
  let r = if !(ctx.errors) = [] then decode ctx j else None in
  match (r, List.rev !(ctx.errors)) with
  | Some c, [] -> Ok c
  | _, (_ :: _ as errs) -> Error errs
  | None, [] -> Error [ Load_error.make ?file "invalid ProxyConfig" ]

let of_file ?env path =
  match Docload.of_file path with
  | Error e -> Error e
  | Ok j ->
      let base_dir =
        let d = Filename.dirname path in
        if Filename.is_relative d then Filename.concat (Sys.getcwd ()) d else d
      in
      let abs =
        if Filename.is_relative path then Filename.concat (Sys.getcwd ()) path else path
      in
      Result.map
        (fun c ->
          { c with source_files = abs :: List.filter (fun f -> f <> abs) c.source_files })
        (of_json ~file:path ~base_dir ?env j)

let on_error_name = function
  | Audit_fail_closed -> "fail_closed"
  | Audit_buffer -> "buffer"
  | Audit_drop -> "drop"

let sink_name = function
  | Config.Sink_stdout -> "stdout"
  | Config.Sink_file f -> f
  | Config.Sink_s3 c -> Printf.sprintf "s3://%s/%s" c.s3_bucket c.s3_prefix
  | Config.Sink_gcs c -> Printf.sprintf "gs://%s/%s" c.gcs_bucket c.gcs_prefix

(* Never includes credentials (static S3 keys, service-account paths are fine). *)
let audit_sink_json s : Yojson.Safe.t =
  let opt k = function Some v -> [ (k, `String v) ] | None -> [] in
  let kind =
    match s.sink with
    | Config.Sink_stdout -> [ ("type", `String "stdout") ]
    | Config.Sink_file f -> [ ("type", `String "file"); ("path", `String f) ]
    | Config.Sink_s3 c ->
        [
          ("type", `String "s3");
          ("bucket", `String c.s3_bucket);
          ("prefix", `String c.s3_prefix);
          ("region", `String c.s3_region);
          ( "credentials",
            `String
              (match c.s3_credentials with
              | Config.S3_env -> "env"
              | Config.S3_static _ -> "static (redacted)"
              | Config.S3_web_identity -> "web_identity"
              | Config.S3_instance -> "instance") );
        ]
        @ opt "endpoint" c.s3_endpoint
        @ opt "spool_dir" c.s3_spool_dir
    | Config.Sink_gcs c ->
        [
          ("type", `String "gcs");
          ("bucket", `String c.gcs_bucket);
          ("prefix", `String c.gcs_prefix);
        ]
        @ opt "spool_dir" c.gcs_spool_dir
  in
  `Assoc
    (kind
    @ [ ("on_error", `String (on_error_name s.sink_on_error)) ]
    @
    match s.sink_on_error with
    | Audit_buffer -> [ ("max_buffer_records", `Int s.max_buffer_records) ]
    | Audit_fail_closed | Audit_drop -> [])

let to_json_redacted c : Yojson.Safe.t =
  let r = `String "<redacted>" in
  let binding b =
    [ ("policy", `String b.policy_name); ("context", Context.to_json b.context) ]
  in
  `Assoc
    [
      ("apiVersion", `String api_version);
      ("kind", `String kind);
      ("listen", `String (Printf.sprintf "%s:%d" c.listen_host c.listen_port));
      ( "tls",
        match c.tls with
        | None -> `Null
        | Some t ->
            `Assoc
              [
                ("cert", `String "<loaded>");
                ("key", r);
                ("client_ca", `Int (List.length t.client_ca));
                ( "client_auth",
                  `String
                    (match t.client_auth with
                    | Client_cert_none -> "none"
                    | Client_cert_optional -> "optional"
                    | Client_cert_require -> "require") );
                ("required", `Bool t.tls_required);
              ] );
      ( "upstream",
        `Assoc
          [
            ("host", `String c.upstream.host);
            ("port", `Int c.upstream.port);
            ("database", `String c.upstream.database);
            ("user", `String c.upstream.user);
            ("password", match c.upstream.password with None -> `Null | Some _ -> r);
            ( "tls",
              `Assoc
                [
                  ( "mode",
                    `String
                      (match c.upstream.tls_mode with
                      | Tls_disable -> "disable"
                      | Tls_require -> "require"
                      | Tls_verify_full -> "verify-full") );
                ] );
            ("connect_timeout_seconds", `Float c.upstream.connect_timeout);
          ] );
      ( "policies",
        `List
          (List.map
             (fun (n, (p : Policy.t)) ->
               `Assoc [ ("name", `String n); ("version", `String p.version) ])
             c.policies) );
      ( "auth",
        match c.auth with
        | Scram_users us ->
            `Assoc
              [
                ("method", `String "scram");
                ( "users",
                  `List
                    (List.map
                       (fun u ->
                         `Assoc
                           ([ ("name", `String u.user_name); ("scram_verifier", r) ]
                           @ binding u.user_binding))
                       us) );
              ]
        | Cert_identities ids ->
            `Assoc
              [
                ("method", `String "cert");
                ( "identities",
                  `List
                    (List.map
                       (fun i ->
                         `Assoc
                           ((match i.id_match with
                            | Subject_cn s -> ("subject_cn", `String s)
                            | Spiffe_id s -> ("spiffe_id", `String s))
                           :: binding i.id_binding))
                       ids) );
              ] );
      ( "limits",
        `Assoc
          [
            ("max_connections", `Int c.limits.max_connections);
            ("max_message_bytes", `Int c.limits.max_message_bytes);
            ("idle_timeout_seconds", `Float c.limits.idle_timeout);
            ("auth_timeout_seconds", `Float c.limits.auth_timeout);
            ("worker_threads", `Int c.limits.worker_threads);
          ] );
      ("deny_sqlstate", `String c.deny_sqlstate);
      ("allow_transaction_control", `Bool c.allow_transaction_control);
      ( "audit",
        `Assoc
          [
            ( "type",
              `String
                (match c.audit with
                | Audit_stdout -> "stdout"
                | Audit_file _ -> "file"
                | Audit_none -> "none") );
            ("sinks", `List (List.map audit_sink_json c.audit_sinks));
            ("log_raw_sql", `Bool c.log_raw_sql);
          ] );
      ( "reload",
        `Assoc
          [
            ("watch", `Bool c.reload.watch);
            ("poll_interval_seconds", `Float c.reload.poll_interval);
          ] );
      ("logging", `Assoc [ ("level", `String c.log_level) ]);
      ("shutdown_grace_seconds", `Float c.shutdown_grace);
    ]
