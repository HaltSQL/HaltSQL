(* Built-in TLS: PEM loading, cipher policy, client-certificate verification. *)

module Config = Haltsql.Config

let ciphers : Tls.Ciphersuite.ciphersuite list =
  [
    `AES_256_GCM_SHA384;
    `AES_128_GCM_SHA256;
    `CHACHA20_POLY1305_SHA256;
    `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    `ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    `ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
  ]

let files (t : Config.tls) =
  List.filter_map
    (function Some (Config.Pem_path p) -> Some p | _ -> None)
    [ Some t.cert; Some t.key; t.client_ca ]

let ( let* ) = Result.bind

let read what = function
  | Config.Pem_inline s -> Ok s
  | Config.Pem_path p -> (
      match In_channel.with_open_bin p In_channel.input_all with
      | s -> Ok s
      | exception Sys_error e -> Error (Printf.sprintf "server.tls.%s: %s" what e))

let label what = function
  | Config.Pem_path p -> Printf.sprintf "server.tls.%s (%s)" what p
  | Config.Pem_inline _ -> Printf.sprintf "server.tls.%s (inline PEM)" what

let certs what pem =
  let* s = read what pem in
  match X509.Certificate.decode_pem_multiple s with
  | Ok (_ :: _ as l) -> Ok l
  | Ok [] -> Error (label what pem ^ ": no certificate found")
  | Error (`Msg m) -> Error (label what pem ^ ": invalid PEM certificate: " ^ m)

let now () = Some (Ptime_clock.now ())

let client_usage_ok leaf =
  match X509.Extension.(find Ext_key_usage (X509.Certificate.extensions leaf)) with
  | None -> true
  | Some (_, usages) -> List.exists (fun u -> u = `Client_auth || u = `Any) usages

let authenticator (t : Config.tls) =
  match (t.client_auth, t.client_ca) with
  | Config.Client_auth_none, _ -> Ok None
  | _, None -> Error "server.tls.client_auth needs server.tls.client_ca"
  | mode, Some ca_pem ->
      let* cas = certs "client_ca" ca_pem in
      let chain = X509.Authenticator.chain_of_trust ~time:now cas in
      let auth : X509.Authenticator.t =
       fun ?ip ~host certs ->
        match (certs, mode) with
        | [], Config.Client_auth_optional -> Ok None
        | [], _ -> Error `EmptyCertificateChain
        | leaf :: _, _ -> (
            match chain ?ip ~host certs with
            | Error _ as e -> e
            | Ok _ as ok ->
                (* A leaf that restricts its extended key usage must allow
                   client authentication. *)
                if client_usage_ok leaf then ok else Error (`LeafInvalidExtensions leaf))
      in
      Ok (Some (auth, List.map X509.Certificate.subject cas))

let load (t : Config.tls) =
  let* chain = certs "cert" t.cert in
  let* key_pem = read "key" t.key in
  let* key =
    match X509.Private_key.decode_pem key_pem with
    | Ok k -> Ok k
    | Error (`Msg _) -> Error (label "key" t.key ^ ": invalid PEM private key")
  in
  let leaf = List.hd chain in
  let* () =
    let a = X509.Public_key.fingerprint (X509.Certificate.public_key leaf)
    and b = X509.Public_key.fingerprint (X509.Private_key.public key) in
    if Eqaf.equal a b then Ok ()
    else Error "server.tls.key does not match the public key of server.tls.cert"
  in
  let* auth = authenticator t in
  let version =
    match t.min_version with
    | Config.Tls_1_2 -> (`TLS_1_2, `TLS_1_3)
    | Config.Tls_1_3 -> (`TLS_1_3, `TLS_1_3)
  in
  let authenticator, acceptable_cas =
    match auth with Some (a, cas) -> (Some a, Some cas) | None -> (None, None)
  in
  match
    Tls.Config.server ~ciphers ~version ~reneg:false
      ~certificates:(`Single (chain, key))
      ?authenticator ?acceptable_cas ()
  with
  | Ok c -> Ok c
  | Error (`Msg m) -> Error ("invalid TLS configuration: " ^ m)

let peer_certificate t =
  match Tls_lwt.Unix.epoch t with Ok e -> e.Tls.Core.peer_certificate | Error () -> None
