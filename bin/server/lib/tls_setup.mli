(** Built-in TLS for haltsql-server ([server.tls]).

    - TLS 1.2 and 1.3 only ([min_version] picks the floor); TLS 1.2 is limited to ECDHE
      with AEAD ciphers (AES-GCM, ChaCha20-Poly1305), TLS 1.3 to AES-GCM and
      ChaCha20-Poly1305.
    - [client_auth: optional] requests a client certificate and, when one is sent,
      verifies it against [client_ca]; [required] additionally refuses handshakes without
      one. Verification is RFC 5280 chain validation at the current time.
    - The certificate and key are checked to match at load time. *)

val load : Haltsql.Config.tls -> (Tls.Config.server, string) result
(** Reads and validates the PEM material (files are read now) and builds the server
    configuration. Error messages name files but never include key material. *)

val files : Haltsql.Config.tls -> string list
(** The files behind [cert], [key] and [client_ca] (inline PEM has none), watched for
    certificate rotation. *)

val ciphers : Tls.Ciphersuite.ciphersuite list
(** The allowed cipher suites. *)

val peer_certificate : Tls_lwt.Unix.t -> X509.Certificate.t option
(** The verified client certificate of an established session, if any. *)
