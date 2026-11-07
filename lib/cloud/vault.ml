open Lwt.Infix
module Config = Haltsql_load.Config

type t = {
  cfg : Config.vault;
  now : unit -> float;
  timeout : float;
  mutable ctx : Http.ctx option;
  lock : Lwt_mutex.t;
  mutable token : (string * float option) option;
}

let create ?(now = Unix.gettimeofday) ?(timeout = 10.) cfg =
  { cfg; now; timeout; ctx = None; lock = Lwt_mutex.create (); token = None }

let valid_segment s =
  s <> "" && s <> "." && s <> ".."
  && String.for_all
       (fun c -> c > ' ' && c < '\127' && not (String.contains "?#%\\\"<>{}|^`" c))
       s

let api_path p =
  let segs = String.split_on_char '/' p in
  if not (List.for_all valid_segment segs) then
    Error (Printf.sprintf "invalid Vault path %S" p)
  else
    let segs =
      match segs with
      | m :: "data" :: (_ :: _ as rest) -> m :: "data" :: rest
      | m :: rest -> m :: "data" :: rest
      | [] -> []
    in
    match segs with
    | [ _; "data" ] ->
        Error (Printf.sprintf "Vault path %S names a mount, not a secret" p)
    | _ -> Ok ("/v1/" ^ String.concat "/" (List.map Http.pct_encode segs))

let base t =
  let a = t.cfg.vault_address in
  if String.length a > 0 && a.[String.length a - 1] = '/' then
    String.sub a 0 (String.length a - 1)
  else a

let ctx t =
  match t.ctx with
  | Some c -> Lwt.return (Ok c)
  | None -> (
      match t.cfg.vault_ca_file with
      | None ->
          t.ctx <- Some Http.default_ctx;
          Lwt.return (Ok Http.default_ctx)
      | Some f -> (
          Http.ctx_of_ca_file f >|= function
          | Ok c ->
              t.ctx <- Some c;
              Ok c
          | Error e -> Error e))

let ns_headers t =
  match t.cfg.vault_namespace with Some n -> [ ("x-vault-namespace", n) ] | None -> []

let vault_errors body =
  match Yojson.Safe.from_string body with
  | `Assoc kv -> (
      match List.assoc_opt "errors" kv with
      | Some (`List l) ->
          let es = List.filter_map (function `String s -> Some s | _ -> None) l in
          if es = [] then "" else ": " ^ String.concat "; " es
      | _ -> "")
  | _ -> ""
  | exception _ -> ""

let req t ?(headers = []) ?body meth path =
  ctx t >>= function
  | Error e -> Lwt.return (Error ("vault: " ^ e))
  | Ok ctx ->
      Http.request ~ctx ~timeout:t.timeout
        ~headers:(ns_headers t @ headers)
        ?body meth
        (Uri.of_string (base t ^ path))
      >|= Result.map_error (fun e -> "vault: " ^ e)

let login t =
  let do_login mount payload =
    req t
      ~headers:[ ("content-type", "application/json") ]
      ~body:(Yojson.Safe.to_string payload)
      `POST
      (Printf.sprintf "/v1/auth/%s/login"
         (String.concat "/" (List.map Http.pct_encode (String.split_on_char '/' mount))))
    >|= function
    | Error e -> Error e
    | Ok r when r.status <> 200 ->
        Error
          (Printf.sprintf "vault login (%s) failed: HTTP %d%s" mount r.status
             (vault_errors r.body))
    | Ok r -> (
        match Yojson.Safe.from_string r.body with
        | exception _ -> Error "vault login: malformed response"
        | `Assoc kv -> (
            match List.assoc_opt "auth" kv with
            | Some (`Assoc a) -> (
                match List.assoc_opt "client_token" a with
                | Some (`String tok) when tok <> "" ->
                    let lease =
                      match List.assoc_opt "lease_duration" a with
                      | Some (`Int n) when n > 0 -> Some n
                      | _ -> None
                    in
                    Ok (tok, Option.map (fun n -> t.now () +. float_of_int n) lease)
                | _ -> Error "vault login: response has no client_token")
            | _ -> Error "vault login: response has no auth block")
        | _ -> Error "vault login: malformed response")
  in
  match t.cfg.vault_auth with
  | Config.Vault_token tok -> Lwt.return (Ok (tok, None))
  | Config.Vault_kubernetes { role; jwt_path; mount } -> (
      match Cloud_util.read_file ~limit:65536 jwt_path with
      | Error m ->
          Lwt.return
            (Error ("vault kubernetes auth: cannot read service account token: " ^ m))
      | Ok jwt ->
          do_login mount
            (`Assoc [ ("role", `String role); ("jwt", `String (String.trim jwt)) ]))
  | Config.Vault_approle { role_id; secret_id; mount } ->
      do_login mount
        (`Assoc [ ("role_id", `String role_id); ("secret_id", `String secret_id) ])

let get_token t ~force =
  Lwt_mutex.with_lock t.lock (fun () ->
      let valid =
        match t.token with
        | Some (tok, None) -> Some tok
        | Some (tok, Some exp) when t.now () < exp -. 30. -> Some tok
        | _ -> None
      in
      match valid with
      | Some tok when not force -> Lwt.return (Ok tok)
      | _ -> (
          login t >|= function
          | Ok (tok, exp) ->
              t.token <- Some (tok, exp);
              Ok tok
          | Error e -> Error e))

let read t reference =
  match String.index_opt reference '#' with
  | None -> Lwt.return (Error "vault reference needs #<field>")
  | Some i -> (
      let path = String.sub reference 0 i
      and field = String.sub reference (i + 1) (String.length reference - i - 1) in
      match api_path path with
      | Error e -> Lwt.return (Error e)
      | Ok api ->
          let rec attempt ~retried =
            get_token t ~force:retried >>= function
            | Error e -> Lwt.return (Error e)
            | Ok tok -> (
                req t ~headers:[ ("x-vault-token", tok) ] `GET api >>= function
                | Error e -> Lwt.return (Error e)
                | Ok r
                  when r.status = 403 && (not retried)
                       &&
                       match t.cfg.vault_auth with
                       | Config.Vault_token _ -> false
                       | _ -> true ->
                    attempt ~retried:true
                | Ok r when r.status = 404 ->
                    Lwt.return (Error (Printf.sprintf "vault: secret %s not found" path))
                | Ok r when r.status <> 200 ->
                    Lwt.return
                      (Error
                         (Printf.sprintf "vault: read %s failed: HTTP %d%s" path r.status
                            (vault_errors r.body)))
                | Ok r ->
                    Lwt.return
                      (match Yojson.Safe.from_string r.body with
                      | exception _ -> Error "vault: malformed response"
                      | j -> (
                          let data =
                            match j with
                            | `Assoc kv -> (
                                match List.assoc_opt "data" kv with
                                | Some (`Assoc d) -> (
                                    match List.assoc_opt "data" d with
                                    | Some (`Assoc dd) -> Some dd
                                    | _ -> None)
                                | _ -> None)
                            | _ -> None
                          in
                          match data with
                          | None ->
                              Error
                                (Printf.sprintf "vault: %s is not a KV v2 secret" path)
                          | Some kv -> (
                              match List.assoc_opt field kv with
                              | None ->
                                  Error
                                    (Printf.sprintf "vault: field %S not found in %s"
                                       field path)
                              | Some v -> (
                                  match Cloud_util.scalar_to_string v with
                                  | Some s -> Ok s
                                  | None ->
                                      Error
                                        (Printf.sprintf
                                           "vault: field %S in %s is not a scalar" field
                                           path))))))
          in
          attempt ~retried:false)
