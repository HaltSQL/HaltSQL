open Lwt.Infix

let default_scope = "https://www.googleapis.com/auth/cloud-platform"

type sa = {
  email : string;
  key : Mirage_crypto_pk.Rsa.priv;
  key_id : string option;
  token_uri : Uri.t;
  scope : string;
}

type source = Metadata of Uri.t | Sa of sa

type t = {
  source : source;
  now : unit -> float;
  timeout : float;
  lock : Lwt_mutex.t;
  mutable cache : (string * float) option;
}

let make ?(now = Unix.gettimeofday) ?(timeout = 5.) source =
  { source; now; timeout; lock = Lwt_mutex.create (); cache = None }

let metadata ?(env = Sys.getenv_opt) ?now ?timeout () =
  let host =
    match env "GCE_METADATA_HOST" with
    | Some h when String.trim h <> "" -> String.trim h
    | _ -> "metadata.google.internal"
  in
  let has_scheme p =
    String.length host >= String.length p && String.sub host 0 (String.length p) = p
  in
  let base =
    if has_scheme "http://" || has_scheme "https://" then host else "http://" ^ host
  in
  make ?now ?timeout
    (Metadata
       (Uri.of_string
          (base ^ "/computeMetadata/v1/instance/service-accounts/default/token")))

let service_account ?now ?timeout ?(scope = default_scope) json =
  match Yojson.Safe.from_string json with
  | exception _ -> Error "service account key is not valid JSON"
  | j -> (
      let f = Cloud_util.json_string_field j in
      match (f "type", f "client_email", f "private_key") with
      | Some "service_account", Some email, Some pem -> (
          let token_uri =
            Option.value ~default:"https://oauth2.googleapis.com/token" (f "token_uri")
          in
          match Http.check_endpoint ~what:"service account token_uri" token_uri with
          | Error e -> Error e
          | Ok token_uri -> (
              match X509.Private_key.decode_pem pem with
              | Ok (`RSA key) ->
                  Ok
                    (make ?now ?timeout
                       (Sa { email; key; key_id = f "private_key_id"; token_uri; scope }))
              | Ok _ -> Error "service account private_key is not an RSA key"
              | Error (`Msg _) ->
                  Error "service account private_key is not a valid PEM key"))
      | Some ty, _, _ when ty <> "service_account" ->
          Error (Printf.sprintf "credentials type %S is not service_account" ty)
      | _ -> Error "service account key needs type, client_email and private_key")

let service_account_file ?now ?timeout ?scope path =
  match Cloud_util.read_file ~limit:65536 path with
  | Error m -> Error ("cannot read service account key: " ^ m)
  | Ok s -> service_account ?now ?timeout ?scope s

let default ?(env = Sys.getenv_opt) ?now ?timeout () =
  match env "GOOGLE_APPLICATION_CREDENTIALS" with
  | Some p when String.trim p <> "" -> service_account_file ?now ?timeout (String.trim p)
  | _ -> Ok (metadata ~env ?now ?timeout ())

let jwt_assertion ~key ~key_id ~email ~scope ~aud ~now =
  let iat = int_of_float now in
  let header =
    `Assoc
      ([ ("alg", `String "RS256"); ("typ", `String "JWT") ]
      @ match key_id with Some k -> [ ("kid", `String k) ] | None -> [])
  in
  let claims =
    `Assoc
      [
        ("iss", `String email);
        ("scope", `String scope);
        ("aud", `String aud);
        ("iat", `Int iat);
        ("exp", `Int (iat + 3600));
      ]
  in
  let enc j = Cloud_util.base64url_nopad (Yojson.Safe.to_string j) in
  let signing_input = enc header ^ "." ^ enc claims in
  let sg = Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:`SHA256 ~key (`Message signing_input) in
  signing_input ^ "." ^ Cloud_util.base64url_nopad sg

let parse_token_response body =
  match Yojson.Safe.from_string body with
  | exception _ -> Error "malformed token response"
  | j -> (
      let expires =
        match j with
        | `Assoc kv -> (
            match List.assoc_opt "expires_in" kv with
            | Some (`Int n) -> Some n
            | Some (`Float f) -> Some (int_of_float f)
            | _ -> None)
        | _ -> None
      in
      match (Cloud_util.json_string_field j "access_token", expires) with
      | Some tok, Some e when tok <> "" -> Ok (tok, e)
      | Some tok, None when tok <> "" -> Ok (tok, 300)
      | _ -> Error "token response has no access_token")

let fetch t =
  match t.source with
  | Metadata uri -> (
      Http.request ~timeout:t.timeout ~headers:[ ("metadata-flavor", "Google") ] `GET uri
      >|= function
      | Error m -> Error ("metadata server: " ^ m)
      | Ok r when r.status <> 200 ->
          Error (Printf.sprintf "metadata server returned HTTP %d" r.status)
      | Ok r when Http.header r "metadata-flavor" <> Some "Google" ->
          Error "metadata server response lacks Metadata-Flavor: Google"
      | Ok r -> parse_token_response r.body)
  | Sa sa -> (
      let assertion =
        jwt_assertion ~key:sa.key ~key_id:sa.key_id ~email:sa.email ~scope:sa.scope
          ~aud:(Uri.to_string sa.token_uri) ~now:(t.now ())
      in
      let body =
        Http.form_encode
          [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            ("assertion", assertion);
          ]
      in
      Http.request ~timeout:t.timeout
        ~headers:[ ("content-type", "application/x-www-form-urlencoded") ]
        ~body `POST sa.token_uri
      >|= function
      | Error m -> Error ("token endpoint: " ^ m)
      | Ok r when r.status <> 200 ->
          let err =
            try Cloud_util.json_string_field (Yojson.Safe.from_string r.body) "error"
            with _ -> None
          in
          Error
            (Printf.sprintf "token endpoint returned HTTP %d %s" r.status
               (Option.value ~default:"" err))
      | Ok r -> parse_token_response r.body)

let token t =
  let valid () =
    match t.cache with
    | Some (tok, exp) when t.now () < exp -. 60. -> Some tok
    | _ -> None
  in
  match valid () with
  | Some tok -> Lwt.return (Ok tok)
  | None ->
      Lwt_mutex.with_lock t.lock (fun () ->
          match valid () with
          | Some tok -> Lwt.return (Ok tok)
          | None -> (
              fetch t >|= function
              | Ok (tok, exp) ->
                  t.cache <- Some (tok, t.now () +. float_of_int exp);
                  Ok tok
              | Error e -> Error e))

let invalidate t = t.cache <- None
