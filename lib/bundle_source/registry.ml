open Lwt.Infix
module Http = Haltsql_cloud.Http

type credentials =
  | Anonymous
  | Basic of { username : string; password : string }
  | Bearer of string

type token = { value : string; expires : float }

type t = {
  ref_ : Oci_ref.t;
  base : string;  (** scheme://registry *)
  ctx : Http.ctx option;
  timeout : float;
  now : unit -> float;
  credentials : credentials;
  mutable use_basic : bool;
  tokens : (string, token) Hashtbl.t;  (** scope -> token *)
}

let ( let* ) = Result.bind
let ( let*! ) p f = p >>= function Error e -> Lwt.return (Error e) | Ok x -> f x

let create ?ctx ?(timeout = 30.) ?(plain_http = false) ?(now = Unix.gettimeofday)
    ~credentials ref_ =
  let* base = Oci_ref.base_url ~plain_http ref_ in
  (match credentials with
    | Basic { username; _ } when username = "" || String.contains username ':' ->
        Error "registry username must be non-empty and must not contain ':'"
    | _ -> Ok ())
  |> Result.map (fun () ->
      {
        ref_;
        base;
        ctx;
        timeout;
        now;
        credentials;
        use_basic = false;
        tokens = Hashtbl.create 4;
      })

let reference t = t.ref_

let manifest_accept =
  [
    "application/vnd.oci.image.manifest.v1+json";
    "application/vnd.oci.image.index.v1+json";
    "application/vnd.docker.distribution.manifest.v2+json";
    "application/vnd.docker.distribution.manifest.list.v2+json";
  ]

let max_manifest_bytes = 4 * 1024 * 1024
let pull_scope t = Printf.sprintf "repository:%s:pull" t.ref_.repository
let push_scope t = Printf.sprintf "repository:%s:pull,push" t.ref_.repository
let url t path = Uri.of_string (t.base ^ "/v2/" ^ t.ref_.repository ^ path)
let registry_name t = t.ref_.registry

let authorization t ~scope =
  match t.credentials with
  | Bearer tok -> Some ("Bearer " ^ tok)
  | Anonymous | Basic _ -> (
      match Hashtbl.find_opt t.tokens scope with
      | Some tok when tok.expires > t.now () -> Some ("Bearer " ^ tok.value)
      | _ -> (
          match t.credentials with
          | Basic { username; password } when t.use_basic ->
              Some (Http_fetch.basic ~username ~password)
          | _ -> None))

(* Exchanges a Bearer challenge for a token. *)
let fetch_token t ~scope (c : Www_auth.challenge) =
  match Www_auth.param c "realm" with
  | None | Some "" ->
      Lwt.return (Error (Fetch_error.Protocol "Bearer challenge without a realm"))
  | Some realm -> (
      let realm_uri = Uri.of_string realm in
      match Http_fetch.check_url ~what:"token realm" realm_uri with
      | Error e -> Lwt.return (Error (Fetch_error.Protocol e))
      | Ok () -> (
          let q =
            (match Www_auth.param c "service" with
              | Some s -> [ ("service", s) ]
              | None -> [])
            @ [ ("scope", scope); ("client_id", "haltsql") ]
          in
          let uri = Uri.add_query_params' realm_uri q in
          let authorization =
            match t.credentials with
            | Basic { username; password } -> Some (Http_fetch.basic ~username ~password)
            | Anonymous | Bearer _ -> None
          in
          Http_fetch.request ?ctx:t.ctx ~timeout:t.timeout ~max_body:(1024 * 1024)
            ?authorization ~follow:0 `GET uri
          >|= function
          | Error e -> Error e
          | Ok r when r.status = 200 -> (
              let what = "token endpoint " ^ Http.host_header uri in
              match Yojson.Safe.from_string r.body with
              | exception Yojson.Json_error _ ->
                  Error (Fetch_error.Protocol (what ^ " did not return JSON"))
              | `Assoc kvs -> (
                  let str k =
                    match List.assoc_opt k kvs with
                    | Some (`String s) when s <> "" -> Some s
                    | _ -> None
                  in
                  let tok =
                    match str "token" with Some s -> Some s | None -> str "access_token"
                  in
                  match tok with
                  | None -> Error (Fetch_error.Protocol (what ^ " returned no token"))
                  | Some value ->
                      if String.exists (fun ch -> ch < ' ' || ch = '\127') value then
                        Error
                          (Fetch_error.Protocol (what ^ " returned a malformed token"))
                      else
                        let ttl =
                          match List.assoc_opt "expires_in" kvs with
                          | Some (`Int n) when n > 0 -> float_of_int n
                          | _ -> 60.
                        in
                        let ttl = Float.max 1. (ttl -. 10.) in
                        Hashtbl.replace t.tokens scope
                          { value; expires = t.now () +. ttl };
                        Ok ())
              | _ -> Error (Fetch_error.Protocol (what ^ " did not return a JSON object"))
              )
          | Ok r ->
              Error
                (match
                   Fetch_error.of_status
                     ~what:("token endpoint " ^ Http.host_header uri)
                     r.status
                 with
                | Fetch_error.Denied m ->
                    Fetch_error.Denied (m ^ " (check the registry credentials)")
                | e -> e)))

(* Sends a request with the established auth; on 401 handles the challenge and
   retries once. *)
let send t ~scope ?(headers = []) ?body ?max_body ?follow meth uri =
  let go () =
    Http_fetch.request ?ctx:t.ctx ~timeout:t.timeout ?max_body ~headers
      ?authorization:(authorization t ~scope) ?body ?follow meth uri
  in
  go () >>= function
  | Ok r when r.status = 401 -> (
      let challenges =
        match Http.header r "www-authenticate" with
        | Some h -> Www_auth.parse h
        | None -> []
      in
      let denied m =
        Lwt.return (Error (Fetch_error.Denied (registry_name t ^ ": " ^ m)))
      in
      let bearer =
        List.find_opt (fun (c : Www_auth.challenge) -> c.scheme = "bearer") challenges
      in
      let basic =
        List.exists (fun (c : Www_auth.challenge) -> c.scheme = "basic") challenges
      in
      match (t.credentials, bearer, basic) with
      | Bearer _, _, _ -> denied "the registry rejected the configured token"
      | (Anonymous | Basic _), Some c, _ -> (
          fetch_token t ~scope c >>= function
          | Error e -> Lwt.return (Error e)
          | Ok () -> (
              go () >>= function
              | Ok r when r.status = 401 ->
                  denied "authentication failed (token rejected)"
              | x -> Lwt.return x))
      | Basic _, None, true when not t.use_basic -> (
          t.use_basic <- true;
          go () >>= function
          | Ok r when r.status = 401 ->
              denied "authentication failed (basic credentials rejected)"
          | x -> Lwt.return x)
      | Anonymous, None, true -> denied "the registry requires credentials"
      | _ -> denied "authentication failed")
  | x -> Lwt.return x

let accept_header = ("accept", String.concat ", " manifest_accept)

let head_manifest t reference =
  send t ~scope:(pull_scope t) ~headers:[ accept_header ] ~max_body:max_manifest_bytes
    `HEAD
    (url t ("/manifests/" ^ reference))
  >|= function
  | Error e -> Error e
  | Ok r when r.status = 200 -> (
      match Http.header r "docker-content-digest" with
      | Some d when Oci_ref.valid_digest (String.trim d) -> Ok (Some (String.trim d))
      | _ -> Ok None)
  | Ok r ->
      Error (Fetch_error.of_status ~what:("manifest HEAD on " ^ registry_name t) r.status)

type manifest = { digest : string; media_type : string option; body : string }

let strip_params ct =
  match String.index_opt ct ';' with
  | Some i -> String.trim (String.sub ct 0 i)
  | None -> String.trim ct

let get_manifest t reference =
  send t ~scope:(pull_scope t) ~headers:[ accept_header ] ~max_body:max_manifest_bytes
    `GET
    (url t ("/manifests/" ^ reference))
  >|= function
  | Error e -> Error e
  | Ok r when r.status = 200 -> (
      let header_digest =
        Option.map String.trim (Http.header r "docker-content-digest")
      in
      let pinned = if Oci_ref.valid_digest reference then Some reference else None in
      let integrity m = Error (Fetch_error.Integrity (registry_name t ^ ": " ^ m)) in
      let check what d =
        match d with
        | None -> Ok ()
        | Some d ->
            if Content_digest.matches ~expected:d r.body then Ok ()
            else
              integrity
                (Printf.sprintf "manifest content does not match the %s digest %s" what d)
      in
      match header_digest with
      | Some d when not (Oci_ref.valid_digest d) ->
          integrity "the registry sent a malformed Docker-Content-Digest"
      | _ -> (
          match check "requested" pinned with
          | Error e -> Error e
          | Ok () -> (
              match check "Docker-Content-Digest" header_digest with
              | Error e -> Error e
              | Ok () ->
                  let digest =
                    match (pinned, header_digest) with
                    | Some d, _ -> d
                    | None, Some d -> d
                    | None, None -> Content_digest.sha256 r.body
                  in
                  Ok
                    {
                      digest;
                      media_type = Option.map strip_params (Http.header r "content-type");
                      body = r.body;
                    })))
  | Ok r ->
      Error (Fetch_error.of_status ~what:("manifest GET on " ^ registry_name t) r.status)

let get_blob t ~digest ~size =
  if not (Oci_ref.valid_digest digest) then
    Lwt.return (Error (Fetch_error.Integrity ("malformed blob digest " ^ digest)))
  else if size < 0 then Lwt.return (Error (Fetch_error.Integrity "negative blob size"))
  else
    send t ~scope:(pull_scope t) ~max_body:size `GET (url t ("/blobs/" ^ digest))
    >|= function
    | Error e -> Error e
    | Ok r when r.status = 200 ->
        if String.length r.body <> size then
          Error
            (Fetch_error.Integrity
               (Printf.sprintf "blob %s is %d bytes, the manifest says %d" digest
                  (String.length r.body) size))
        else if not (Content_digest.matches ~expected:digest r.body) then
          Error
            (Fetch_error.Integrity
               (Printf.sprintf "blob content does not match its digest %s" digest))
        else Ok r.body
    | Ok r ->
        Error (Fetch_error.of_status ~what:("blob GET on " ^ registry_name t) r.status)

let blob_exists t digest =
  send t ~scope:(push_scope t) ~max_body:max_int `HEAD (url t ("/blobs/" ^ digest))
  >|= function
  | Error e -> Error e
  | Ok r when r.status = 200 -> Ok true
  | Ok r when r.status = 404 -> Ok false
  | Ok r ->
      Error (Fetch_error.of_status ~what:("blob HEAD on " ^ registry_name t) r.status)

let push_blob t content =
  let digest = Content_digest.sha256 content in
  let*! exists = blob_exists t digest in
  if exists then Lwt.return (Ok digest)
  else
    let*! r =
      send t ~scope:(push_scope t)
        ~headers:[ ("content-length", "0") ]
        ~body:"" ~follow:0 `POST (url t "/blobs/uploads/")
    in
    if r.status <> 202 then
      Lwt.return
        (Error
           (Fetch_error.of_status
              ~what:("blob upload start on " ^ registry_name t)
              r.status))
    else
      match Http.header r "location" with
      | None ->
          Lwt.return (Error (Fetch_error.Protocol "blob upload: no Location header"))
      | Some loc -> (
          let base = url t "/blobs/uploads/" in
          let target = Uri.resolve "" base (Uri.of_string loc) in
          match Http_fetch.check_url ~what:"blob upload location" target with
          | Error e -> Lwt.return (Error (Fetch_error.Protocol e))
          | Ok () ->
              let target = Uri.add_query_param' target ("digest", digest) in
              let*! r =
                send t ~scope:(push_scope t)
                  ~headers:
                    [
                      ("content-type", "application/octet-stream");
                      ("content-length", string_of_int (String.length content));
                    ]
                  ~body:content ~follow:0 `PUT target
              in
              if r.status = 201 || r.status = 204 then Lwt.return (Ok digest)
              else
                Lwt.return
                  (Error
                     (Fetch_error.of_status
                        ~what:("blob upload on " ^ registry_name t)
                        r.status)))

let put_manifest t ~reference ~media_type body =
  let digest = Content_digest.sha256 body in
  if Oci_ref.valid_digest reference && reference <> digest then
    Lwt.return
      (Error (Fetch_error.Integrity "manifest digest does not match the reference"))
  else
    send t ~scope:(push_scope t)
      ~headers:
        [
          ("content-type", media_type);
          ("content-length", string_of_int (String.length body));
        ]
      ~body ~follow:0 `PUT
      (url t ("/manifests/" ^ reference))
    >|= function
    | Error e -> Error e
    | Ok r when r.status = 201 || r.status = 200 -> (
        match Option.map String.trim (Http.header r "docker-content-digest") with
        | Some d when d <> digest ->
            Error
              (Fetch_error.Integrity
                 (Printf.sprintf "the registry stored the manifest as %s, expected %s" d
                    digest))
        | _ -> Ok digest)
    | Ok r ->
        Error
          (Fetch_error.of_status ~what:("manifest PUT on " ^ registry_name t) r.status)
