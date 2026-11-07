open Lwt.Infix
module Config = Haltsql_load.Config

type t = {
  cfg : Config.aws_secrets;
  now : unit -> float;
  timeout : float;
  creds : Aws_creds.t;
}

let create ?env ?(now = Unix.gettimeofday) ?(timeout = 10.) ?credentials
    (cfg : Config.aws_secrets) =
  let creds =
    match credentials with
    | Some c -> c
    | None -> Aws_creds.create ?env ~now ~region:cfg.aws_region Aws_creds.default_chain
  in
  { cfg; now; timeout; creds }

let credential_errors =
  [
    "ExpiredTokenException";
    "UnrecognizedClientException";
    "InvalidSignatureException";
    "ExpiredToken";
  ]

let get t reference =
  let id, key =
    match String.index_opt reference '#' with
    | None -> (reference, None)
    | Some i ->
        ( String.sub reference 0 i,
          Some (String.sub reference (i + 1) (String.length reference - i - 1)) )
  in
  let endpoint =
    match t.cfg.aws_endpoint with
    | Some e -> e
    | None -> Printf.sprintf "https://secretsmanager.%s.amazonaws.com" t.cfg.aws_region
  in
  let uri = Uri.of_string endpoint in
  let uri = if Uri.path uri = "" then Uri.with_path uri "/" else uri in
  let payload = Yojson.Safe.to_string (`Assoc [ ("SecretId", `String id) ]) in
  let rec attempt ~retried =
    Aws_creds.get t.creds >>= function
    | Error e -> Lwt.return (Error ("aws-sm: " ^ e))
    | Ok creds -> (
        let headers =
          Sigv4.sign creds ~service:"secretsmanager" ~region:t.cfg.aws_region
            ~time:(t.now ()) ~meth:"POST" ~uri
            ~headers:
              [
                ("content-type", "application/x-amz-json-1.1");
                ("x-amz-target", "secretsmanager.GetSecretValue");
              ]
            ~payload
        in
        Http.request ~timeout:t.timeout ~headers ~body:payload `POST uri >>= function
        | Error e -> Lwt.return (Error ("aws-sm: " ^ e))
        | Ok r when r.status = 200 -> (
            match Yojson.Safe.from_string r.body with
            | exception _ -> Lwt.return (Error "aws-sm: malformed response")
            | j ->
                let value =
                  match Cloud_util.json_string_field j "SecretString" with
                  | Some s -> Ok s
                  | None -> (
                      match Cloud_util.json_string_field j "SecretBinary" with
                      | Some b ->
                          Result.map_error
                            (fun _ -> "aws-sm: invalid SecretBinary")
                            (Cloud_util.base64_decode b)
                      | None ->
                          Error "aws-sm: response has no SecretString or SecretBinary")
                in
                Lwt.return
                  (match (value, key) with
                  | Error e, _ -> Error e
                  | Ok v, None -> Ok v
                  | Ok v, Some k ->
                      Cloud_util.json_key
                        ~what:(Printf.sprintf "aws-sm secret %s" id)
                        ~key:k v))
        | Ok r ->
            let ty =
              match Yojson.Safe.from_string r.body with
              | exception _ -> ""
              | j -> (
                  match Cloud_util.json_string_field j "__type" with
                  | Some s -> (
                      match String.rindex_opt s '#' with
                      | Some i -> String.sub s (i + 1) (String.length s - i - 1)
                      | None -> s)
                  | None -> "")
            in
            if List.mem ty credential_errors && not retried then begin
              Aws_creds.invalidate t.creds;
              attempt ~retried:true
            end
            else
              Lwt.return
                (Error
                   (Printf.sprintf "aws-sm: GetSecretValue %s failed: HTTP %d %s" id
                      r.status ty)))
  in
  attempt ~retried:false
