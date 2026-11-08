(** Google Cloud Storage audit sink; see gcs_sink.mli. *)

open Lwt.Infix
module Config = Haltsql_load.Config

let upload ?(timeout = 30.) ?(endpoint = "https://storage.googleapis.com") ~auth ~bucket
    ~key ~body () =
  Gcp_auth.token auth >>= function
  | Error m -> Lwt.return (Error (Object_sink.Retryable ("gcp auth: " ^ m)))
  | Ok tok -> (
      let base =
        if String.length endpoint > 0 && endpoint.[String.length endpoint - 1] = '/' then
          String.sub endpoint 0 (String.length endpoint - 1)
        else endpoint
      in
      let uri =
        Uri.of_string
          (Printf.sprintf
             "%s/upload/storage/v1/b/%s/o?uploadType=media&name=%s&ifGenerationMatch=0"
             base (Http.pct_encode bucket) (Http.pct_encode key))
      in
      let md5 = Cloud_util.base64 Digestif.MD5.(to_raw_string (digest_string body)) in
      Http.request ~timeout
        ~headers:
          [ ("authorization", "Bearer " ^ tok); ("content-type", "application/x-ndjson") ]
        ~body `POST uri
      >|= function
      | Error m -> Error (Object_sink.Retryable m)
      | Ok r when r.status = 200 -> (
          match
            Cloud_util.json_string_field
              (try Yojson.Safe.from_string r.body with _ -> `Null)
              "md5Hash"
          with
          | Some h when h = md5 -> Ok ()
          | Some _ ->
              Error (Object_sink.Retryable "GCS md5Hash does not match the uploaded body")
          | None -> Error (Object_sink.Retryable "GCS response has no md5Hash"))
      | Ok r when r.status = 412 -> Ok ()
      | Ok r when r.status = 401 ->
          Gcp_auth.invalidate auth;
          Error (Object_sink.Retryable "GCS returned HTTP 401")
      | Ok r when r.status = 429 || r.status >= 500 ->
          Error (Object_sink.Retryable (Printf.sprintf "GCS returned HTTP %d" r.status))
      | Ok r ->
          Error (Object_sink.Permanent (Printf.sprintf "GCS returned HTTP %d" r.status)))

let create ?(env = Sys.getenv_opt) ?now ?host ?run_id ?spool_dir ?max_buffer_records
    ?max_attempts ?base_backoff ?timeout ?endpoint ?auth ?on_event ~on_error
    (c : Config.gcs_sink) =
  let auth =
    match auth with
    | Some a -> Ok a
    | None -> (
        match c.gcs_credentials with
        | Config.Gcs_metadata -> Ok (Gcp_auth.metadata ~env ?now ())
        | Config.Gcs_service_account_file f -> Gcp_auth.service_account_file ?now f)
  in
  let endpoint =
    match endpoint with
    | Some e -> Some e
    | None -> (
        match env "STORAGE_EMULATOR_HOST" with
        | Some h when String.trim h <> "" ->
            let h = String.trim h in
            Some
              (if String.length h > 4 && String.sub h 0 4 = "http" then h
               else "http://" ^ h)
        | _ -> None)
  in
  match auth with
  | Error e -> Error ("gcs sink: " ^ e)
  | Ok auth ->
      let spool_dir = match spool_dir with Some d -> Some d | None -> c.gcs_spool_dir in
      Object_sink.create ?now ?host ?run_id ?spool_dir ?max_buffer_records ?max_attempts
        ?base_backoff ?on_event
        ~name:(Printf.sprintf "gs://%s/%s" c.gcs_bucket c.gcs_prefix)
        ~prefix:c.gcs_prefix ~batch:c.gcs_batch ~on_error (fun ~key ~body ->
          upload ?timeout ?endpoint ~auth ~bucket:c.gcs_bucket ~key ~body ())
