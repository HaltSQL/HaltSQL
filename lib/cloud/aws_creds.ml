(** AWS credential providers (env, static, web identity, IMDSv2) with caching; see
    aws_creds.mli. *)

open Lwt.Infix

type source =
  | Env
  | Static of Sigv4.credentials
  | Web_identity
  | Instance
  | Chain of source list

let default_chain = Chain [ Env; Web_identity; Instance ]

let source_of_s3 : Haltsql_load.Config.s3_credentials -> source = function
  | S3_env -> Env
  | S3_static { access_key_id; secret_access_key; session_token } ->
      Static { Sigv4.access_key_id; secret_access_key; session_token }
  | S3_web_identity -> Web_identity
  | S3_instance -> Instance

type cached = { creds : Sigv4.credentials; expires : float option }

type t = {
  env : string -> string option;
  now : unit -> float;
  margin : float;
  timeout : float;
  region : string;
  source : source;
  lock : Lwt_mutex.t;
  mutable cache : cached option;
  mutable fetches : int;
}

let nonempty env k =
  match env k with Some v when String.trim v <> "" -> Some (String.trim v) | _ -> None

let create ?(env = Sys.getenv_opt) ?(now = Unix.gettimeofday) ?(refresh_margin = 300.)
    ?(timeout = 5.) ?region source =
  let region =
    match region with
    | Some r -> r
    | None -> (
        match nonempty env "AWS_REGION" with
        | Some r -> r
        | None -> Option.value ~default:"us-east-1" (nonempty env "AWS_DEFAULT_REGION"))
  in
  {
    env;
    now;
    margin = refresh_margin;
    timeout;
    region;
    source;
    lock = Lwt_mutex.create ();
    cache = None;
    fetches = 0;
  }

let invalidate t = t.cache <- None
let fetch_count t = t.fetches

let from_env t =
  match (nonempty t.env "AWS_ACCESS_KEY_ID", nonempty t.env "AWS_SECRET_ACCESS_KEY") with
  | Some a, Some s ->
      Lwt.return
        (Ok
           {
             creds =
               {
                 access_key_id = a;
                 secret_access_key = s;
                 session_token = nonempty t.env "AWS_SESSION_TOKEN";
               };
             expires = None;
           })
  | _ -> Lwt.return (Error "env: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set")

let valid_session_name s =
  String.length s >= 2
  && String.length s <= 64
  && String.for_all
       (fun c ->
         (c >= 'a' && c <= 'z')
         || (c >= 'A' && c <= 'Z')
         || (c >= '0' && c <= '9')
         || String.contains "+=,.@_-" c)
       s

let parse_expiration s =
  match Cloud_util.parse_rfc3339 s with Some f -> Some f | None -> None

let web_identity t =
  match (nonempty t.env "AWS_WEB_IDENTITY_TOKEN_FILE", nonempty t.env "AWS_ROLE_ARN") with
  | None, _ | _, None ->
      Lwt.return
        (Error "web identity: AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN are not set")
  | Some file, Some role -> (
      let session =
        Option.value ~default:"haltsql" (nonempty t.env "AWS_ROLE_SESSION_NAME")
      in
      if not (valid_session_name session) then
        Lwt.return (Error "web identity: invalid AWS_ROLE_SESSION_NAME")
      else
        match Cloud_util.read_file ~limit:65536 file with
        | Error m -> Lwt.return (Error ("web identity: cannot read token file: " ^ m))
        | Ok token -> (
            let token = String.trim token in
            let endpoint =
              match nonempty t.env "AWS_ENDPOINT_URL_STS" with
              | Some e -> e
              | None -> Printf.sprintf "https://sts.%s.amazonaws.com" t.region
            in
            match Http.check_endpoint ~what:"STS endpoint" endpoint with
            | Error m -> Lwt.return (Error ("web identity: " ^ m))
            | Ok base -> (
                let body =
                  Http.form_encode
                    [
                      ("Action", "AssumeRoleWithWebIdentity");
                      ("Version", "2011-06-15");
                      ("RoleArn", role);
                      ("RoleSessionName", session);
                      ("WebIdentityToken", token);
                      ("DurationSeconds", "3600");
                    ]
                in
                let uri =
                  Uri.with_path base (if Uri.path base = "" then "/" else Uri.path base)
                in
                Http.request ~timeout:t.timeout
                  ~headers:
                    [
                      ("content-type", "application/x-www-form-urlencoded; charset=utf-8");
                      ("accept", "application/xml");
                    ]
                  ~body `POST uri
                >|= function
                | Error m -> Error ("web identity: " ^ m)
                | Ok r when r.status <> 200 ->
                    let code =
                      Option.value ~default:"" (Cloud_util.xml_tag r.body "Code")
                    in
                    Error
                      (Printf.sprintf "web identity: STS returned HTTP %d %s" r.status
                         code)
                | Ok r -> (
                    let tag = Cloud_util.xml_tag r.body in
                    match
                      ( tag "AccessKeyId",
                        tag "SecretAccessKey",
                        tag "SessionToken",
                        tag "Expiration" )
                    with
                    | Some a, Some s, Some tok, exp ->
                        Ok
                          {
                            creds =
                              {
                                access_key_id = a;
                                secret_access_key = s;
                                session_token = Some tok;
                              };
                            expires = Option.bind exp parse_expiration;
                          }
                    | _ -> Error "web identity: malformed STS response"))))

let instance t =
  if
    Option.map String.lowercase_ascii (nonempty t.env "AWS_EC2_METADATA_DISABLED")
    = Some "true"
  then Lwt.return (Error "instance: IMDS disabled by AWS_EC2_METADATA_DISABLED")
  else
    let base =
      Option.value ~default:"http://169.254.169.254"
        (nonempty t.env "AWS_EC2_METADATA_SERVICE_ENDPOINT")
    in
    let base =
      if String.length base > 0 && base.[String.length base - 1] = '/' then
        String.sub base 0 (String.length base - 1)
      else base
    in
    let u p = Uri.of_string (base ^ p) in
    let ( let* ) = Lwt_result.bind in
    let fail m = Lwt.return (Error ("instance: " ^ m)) in
    let req ?(headers = []) meth path =
      Http.request ~timeout:t.timeout ~headers meth (u path) >>= function
      | Error m -> fail m
      | Ok r when r.status <> 200 ->
          fail (Printf.sprintf "IMDS %s returned HTTP %d" path r.status)
      | Ok r -> Lwt.return (Ok r.body)
    in
    let* token =
      req
        ~headers:[ ("x-aws-ec2-metadata-token-ttl-seconds", "21600") ]
        `PUT "/latest/api/token"
    in
    let h = [ ("x-aws-ec2-metadata-token", String.trim token) ] in
    let* roles = req ~headers:h `GET "/latest/meta-data/iam/security-credentials/" in
    match
      String.split_on_char '\n' roles |> List.map String.trim |> List.filter (( <> ) "")
    with
    | [] -> fail "no IAM role attached to the instance"
    | role :: _ when String.contains role '/' || String.contains role '.' ->
        fail "invalid role name from IMDS"
    | role :: _ -> (
        let* body =
          req ~headers:h `GET ("/latest/meta-data/iam/security-credentials/" ^ role)
        in
        match Yojson.Safe.from_string body with
        | exception _ -> fail "malformed credentials document"
        | j -> (
            let f = Cloud_util.json_string_field j in
            match (f "Code", f "AccessKeyId", f "SecretAccessKey", f "Token") with
            | (None | Some "Success"), Some a, Some s, tok ->
                Lwt.return
                  (Ok
                     {
                       creds =
                         { access_key_id = a; secret_access_key = s; session_token = tok };
                       expires = Option.bind (f "Expiration") parse_expiration;
                     })
            | Some c, _, _, _ when c <> "Success" -> fail ("IMDS credentials code " ^ c)
            | _ -> fail "malformed credentials document"))

let rec fetch t = function
  | Env -> from_env t
  | Static c -> Lwt.return (Ok { creds = c; expires = None })
  | Web_identity -> web_identity t
  | Instance -> instance t
  | Chain sources ->
      let rec go errs = function
        | [] ->
            Lwt.return
              (Error
                 ("no AWS credentials found (" ^ String.concat "; " (List.rev errs) ^ ")"))
        | s :: rest -> (
            fetch t s >>= function
            | Ok c -> Lwt.return (Ok c)
            | Error e -> go (e :: errs) rest)
      in
      go [] sources

let fresh t c = match c.expires with None -> true | Some e -> t.now () < e -. t.margin
let still_valid t c = match c.expires with None -> true | Some e -> t.now () < e

let get t =
  match t.cache with
  | Some c when fresh t c -> Lwt.return (Ok c.creds)
  | _ ->
      Lwt_mutex.with_lock t.lock (fun () ->
          match t.cache with
          | Some c when fresh t c -> Lwt.return (Ok c.creds)
          | prev -> (
              fetch t t.source >|= function
              | Ok c ->
                  t.fetches <- t.fetches + 1;
                  t.cache <- Some c;
                  Ok c.creds
              | Error e -> (
                  match prev with
                  | Some c when still_valid t c -> Ok c.creds
                  | _ -> Error e)))
