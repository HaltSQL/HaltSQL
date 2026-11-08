(** Ed25519 signing keys for policy bundles.

    On disk, keys use the standard OpenSSL-compatible PEM encodings, so keys made with
    [openssl genpkey -algorithm ed25519] work too:
    - private key: PKCS#8 ([-----BEGIN PRIVATE KEY-----]), file mode [0600];
    - public key: SubjectPublicKeyInfo ([-----BEGIN PUBLIC KEY-----]).

    A public key may also be given as the base64 of its 32 raw bytes. *)

type public
type secret

val keyid : public -> string
(** ["sha256:<hex>"] of the 32 raw public-key bytes. Identifies the key in signature
    files; it is a lookup hint, never a substitute for verification. *)

val raw : public -> string
(** The 32 raw public-key bytes. *)

val equal : public -> public -> bool
(** Constant-time comparison of the raw key bytes. *)

val generate : unit -> secret
(** A fresh key from the operating system's CSPRNG. *)

val public_of_secret : secret -> public
(** The public half of a secret key. *)

val sign : secret -> string -> string
(** 64-byte RFC 8032 signature. *)

val verify : public -> signature:string -> string -> bool
(** [verify key ~signature msg]: [false] (never an exception) for a malformed or
    wrong-length signature. *)

(** {1 Encodings} *)

val public_to_pem : public -> string
(** SubjectPublicKeyInfo PEM. *)

val public_to_base64 : public -> string
(** Base64 of the 32 raw bytes. *)

val secret_to_pem : secret -> string
(** Unencrypted PKCS#8 PEM. Contains the secret key: write it with mode [0600]. *)

val public_of_string : string -> (public, string) result
(** Accepts a PEM public key or the base64 of the 32 raw bytes (surrounding whitespace is
    ignored). *)

val secret_of_string : string -> (secret, string) result
(** A PEM PKCS#8 Ed25519 private key. Error messages never contain key material. *)

val public_of_file : string -> (public, string) result
(** Reads {!public_of_string} from a regular file of at most 16 KiB. *)

val secret_of_file : string -> (secret, string) result
(** Refuses a key file that is not a regular file or that group or others can access (like
    ssh, fail closed: [chmod 600 FILE]). *)

val of_config : Haltsql_load.Config.public_key -> (public, string) result
(** Decodes a [policies[].public_keys] entry of the runtime configuration. *)
