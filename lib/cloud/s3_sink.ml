open Lwt.Infix
module Config = Haltsql_load.Config

let object_url (c : Config.s3_sink) key =
  let enc = Http.pct_encode ~keep_slash:true key in
  match c.s3_endpoint with
  | Some e ->
      let e =
        if String.length e > 0 && e.[String.length e - 1] = '/' then
          String.sub e 0 (String.length e - 1)
        else e
      in
      Uri.of_string (Printf.sprintf "%s/%s/%s" e c.s3_bucket enc)
  | None ->
      Uri.of_string
        (Printf.sprintf "https://%s.s3.%s.amazonaws.com/%s" c.s3_bucket c.s3_region enc)

let credential_codes =
  [ "ExpiredToken"; "InvalidToken"; "RequestExpired"; "TokenRefreshRequired" ]

let put_object ?(now = Unix.gettimeofday) ?(timeout = 30.) ~credentials
    (c : Config.s3_sink) ~key ~body =
  Aws_creds.get credentials >>= function
  | Error m -> Lwt.return (Error (Object_sink.Retryable ("credentials: " ^ m)))
  | Ok creds -> (
      let uri = object_url c key in
      let t = now () in
      let lock =
        match c.s3_object_lock with
        | None -> []
        | Some { lock_mode; retain_days } ->
            [
              ( "x-amz-object-lock-mode",
                match lock_mode with
                | Config.Governance -> "GOVERNANCE"
                | Config.Compliance -> "COMPLIANCE" );
              ( "x-amz-object-lock-retain-until-date",
                Cloud_util.rfc3339 (t +. (float_of_int retain_days *. 86400.)) );
            ]
      in
      let headers =
        [
          ("content-type", "application/x-ndjson");
          ( "content-md5",
            Cloud_util.base64 Digestif.MD5.(to_raw_string (digest_string body)) );
          ( "x-amz-checksum-sha256",
            Cloud_util.base64 Digestif.SHA256.(to_raw_string (digest_string body)) );
          ("if-none-match", "*");
        ]
        @ lock
      in
      let signed =
        Sigv4.sign ~s3:true creds ~service:"s3" ~region:c.s3_region ~time:t ~meth:"PUT"
          ~uri ~headers ~payload:body
      in
      Http.request ~timeout ~headers:signed ~body `PUT uri >|= function
      | Error m -> Error (Object_sink.Retryable m)
      | Ok r when r.status >= 200 && r.status < 300 -> Ok ()
      | Ok r when r.status = 412 ->
          Ok () (* same name = same content (sha256 in the key) *)
      | Ok r ->
          let code = Option.value ~default:"" (Cloud_util.xml_tag r.body "Code") in
          let msg = Printf.sprintf "S3 PUT returned HTTP %d %s" r.status code in
          if List.mem code credential_codes then begin
            Aws_creds.invalidate credentials;
            Error (Object_sink.Retryable msg)
          end
          else if r.status = 429 || r.status >= 500 || code = "SlowDown" then
            Error (Object_sink.Retryable msg)
          else Error (Object_sink.Permanent msg))

let create ?env ?now ?host ?run_id ?spool_dir ?max_buffer_records ?max_attempts
    ?base_backoff ?timeout ?credentials ?on_event ~on_error (c : Config.s3_sink) =
  let credentials =
    match credentials with
    | Some cr -> cr
    | None ->
        Aws_creds.create ?env ?now ~region:c.s3_region
          (Aws_creds.source_of_s3 c.s3_credentials)
  in
  let endpoint_ok =
    match c.s3_endpoint with
    | None -> Ok ()
    | Some e -> (
        let u = Uri.of_string e in
        match Uri.scheme u with
        | Some ("https" | "http") when Uri.host u <> None -> Ok ()
        | _ -> Error (Printf.sprintf "s3 sink: invalid endpoint %S" e))
  in
  match endpoint_ok with
  | Error e -> Error e
  | Ok () ->
      let spool_dir = match spool_dir with Some d -> Some d | None -> c.s3_spool_dir in
      Object_sink.create ?now ?host ?run_id ?spool_dir ?max_buffer_records ?max_attempts
        ?base_backoff ?on_event
        ~name:(Printf.sprintf "s3://%s/%s" c.s3_bucket c.s3_prefix)
        ~prefix:c.s3_prefix ~batch:c.s3_batch ~on_error
        (put_object ?now ?timeout ~credentials c)
