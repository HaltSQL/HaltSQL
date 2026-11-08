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
      (** the subject CN as UTF-8 (see {!cn_text}); [None] when absent or undecodable *)
  fingerprint : string;  (** lower-case hex SHA-256 of the DER certificate *)
}

val cn_text : X509.Distinguished_name.Common_name.t -> string option
(** [cn_text cn] is the CN as UTF-8 text. UTF8String must be valid UTF-8, PrintableString
    must be ASCII, BMPString (UTF-16BE) and UniversalString (UCS-4BE) are transcoded.
    TeletexString, malformed content, the empty string and strings containing control
    characters give [None], so such a CN never matches a configured identity. *)

val peer_of_certificate : X509.Certificate.t -> peer
(** Extracts the identity fields of a leaf certificate. Performs no validation: only call
    it on a certificate the TLS layer has already verified. *)

val subject : peer -> string
(** The SPIFFE ID if any, else the subject CN, else ["sha256:" ^ fingerprint]. *)

val find_identity :
  Haltsql.Config.mtls_identity list -> peer -> Haltsql.Config.mtls_identity option
(** The first identity (in configuration order) whose [spiffe_id] equals the peer's SPIFFE
    ID or whose [subject_cn] equals the peer's subject CN. Exact, case-sensitive. *)
