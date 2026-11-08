(** Client-certificate identities (mTLS).

    The certificate chain itself is validated by the TLS layer against
    [server.tls.client_ca]; this module only extracts the identity of an already validated
    leaf certificate and maps it to a configured identity. *)

type peer = {
  spiffe_id : string option;
      (** the SPIFFE ID: set only when the certificate has exactly one URI SAN and it is a
          [spiffe://] URI (an X.509-SVID must have exactly one) *)
  uri_sans : string list;
  subject_cn : string option;
  fingerprint : string;  (** lower-case hex SHA-256 of the DER certificate *)
}

val peer_of_certificate : X509.Certificate.t -> peer

val subject : peer -> string
(** The SPIFFE ID if any, else the subject CN, else ["sha256:" ^ fingerprint]. *)

val find_identity :
  Haltsql.Config.mtls_identity list -> peer -> Haltsql.Config.mtls_identity option
(** The first identity (in configuration order) whose [spiffe_id] equals the peer's SPIFFE
    ID or whose [subject_cn] equals the peer's subject CN. Exact, case-sensitive. *)
