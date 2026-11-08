open Lwt.Infix
module Http = Haltsql_cloud.Http
module Config = Haltsql_load.Config
module B = Haltsql_bundle

type fetched = { bundle : string; signature : string; etag : string option }
type outcome = Not_modified | Fetched of fetched

let clean_etag = function
  | Some e ->
      let e = String.trim e in
      if
        e = ""
        || String.length e > 1024
        || String.exists (fun c -> c < ' ' || c = '\127') e
      then None
      else Some e
  | None -> None

(* GET [uri] (the bundle when [conditional]): 200 -> body, 304 -> not modified. *)
let get ~send ~what ~max_body ~etag uri =
  let headers = match etag with Some e -> [ ("if-none-match", e) ] | None -> [] in
  send ~headers ~max_body uri >|= function
  | Error e -> Error e
  | Ok (r : Http.response) when r.status = 200 ->
      Ok (`Body (r.body, clean_etag (Http.header r "etag")))
  | Ok r when r.status = 304 && etag <> None -> Ok `Not_modified
  | Ok r -> Error (Fetch_error.of_status ~what r.status)

let fetch_pair ~send ~what ~etag bundle_uri sig_uri =
  get ~send ~what:(what ^ " (bundle)") ~max_body:B.default_max_bytes ~etag bundle_uri
  >>= function
  | Error e -> Lwt.return (Error e)
  | Ok `Not_modified -> Lwt.return (Ok Not_modified)
  | Ok (`Body (bundle, etag)) -> (
      get ~send ~what:(what ^ " (signature)") ~max_body:B.max_signature_bytes ~etag:None
        sig_uri
      >|= function
      | Error e -> Error e
      | Ok `Not_modified ->
          Error (Fetch_error.Protocol "unexpected 304 for the signature")
      | Ok (`Body (signature, _)) -> Ok (Fetched { bundle; signature; etag }))

let https ?ctx ?timeout ?authorization ~etag url =
  let bundle_uri = Uri.of_string url in
  let sig_uri = Uri.of_string (url ^ ".sig") in
  let send ~headers ~max_body uri =
    Http_fetch.request ?ctx ?timeout ~max_body ~headers ?authorization `GET uri
  in
  match Http_fetch.check_url ~what:"bundle source" bundle_uri with
  | Error e -> Lwt.return (Error (Fetch_error.Protocol e))
  | Ok () ->
      fetch_pair ~send
        ~what:("GET " ^ Http.host_header bundle_uri)
        ~etag bundle_uri sig_uri

let s3_object_url (c : Config.s3_source) key =
  let enc = Http.pct_encode ~keep_slash:true key in
  match c.src_endpoint with
  | Some e ->
      let e =
        if String.length e > 0 && e.[String.length e - 1] = '/' then
          String.sub e 0 (String.length e - 1)
        else e
      in
      Uri.of_string (Printf.sprintf "%s/%s/%s" e c.src_bucket enc)
  | None ->
      Uri.of_string
        (Printf.sprintf "https://%s.s3.%s.amazonaws.com/%s" c.src_bucket c.src_region enc)

let credential_codes =
  [ "ExpiredToken"; "InvalidToken"; "RequestExpired"; "TokenRefreshRequired" ]

let s3 ?ctx ?timeout ?(now = Unix.gettimeofday) ~credentials ~etag (c : Config.s3_source)
    =
  let bundle_uri = s3_object_url c c.src_key in
  let sig_uri = s3_object_url c (c.src_key ^ ".sig") in
  match Http_fetch.check_url ~what:"s3 endpoint" bundle_uri with
  | Error e -> Lwt.return (Error (Fetch_error.Protocol e))
  | Ok () ->
      let send ~headers ~max_body uri =
        Haltsql_cloud.Aws_creds.get credentials >>= function
        | Error m -> Lwt.return (Error (Fetch_error.Denied ("S3 credentials: " ^ m)))
        | Ok creds -> (
            let signed =
              Haltsql_cloud.Sigv4.sign ~s3:true creds ~service:"s3" ~region:c.src_region
                ~time:(now ()) ~meth:"GET" ~uri ~headers ~payload:""
            in
            Http_fetch.request ?ctx ?timeout ~max_body ~headers:signed ~follow:0 `GET uri
            >|= function
            | Ok r when r.status >= 400 ->
                let code =
                  Option.value ~default:""
                    (Haltsql_cloud.Cloud_util.xml_tag r.body "Code")
                in
                if List.mem code credential_codes then
                  Haltsql_cloud.Aws_creds.invalidate credentials;
                (* keep the status, drop the body *)
                Ok { r with body = "" }
            | x -> x)
      in
      fetch_pair ~send
        ~what:(Printf.sprintf "S3 GET s3://%s/%s" c.src_bucket c.src_key)
        ~etag bundle_uri sig_uri
