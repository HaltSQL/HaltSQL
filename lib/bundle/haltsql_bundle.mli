(** Signed policy bundles (see [docs/policy-bundles.md]).

    A bundle ([*.haltsqlbundle]) is a single canonical JSON document (see {!Canonical})
    followed by one newline:

    {v
    { "apiVersion": "haltsql.dev/v1",
      "kind": "PolicyBundle",
      "metadata": { "name": "prod-policies", "version": "2026.11.07",
                    "created_by": "haltsql/0.1.0",
                    "source": { "url": "https://github.com/acme/policies",
                                "commit": "4f0c..." } },
      "policies": [ { "name": "saas-analytics", "document": { <Policy_load.to_json> } } ],
      "catalogs": { "saas": { <catalog snapshot> } },
      "digest": "sha256:<hex of the canonical document without the digest member>" }
    v}

    Its detached signature file ([<bundle>.sig]) is canonical JSON too, either one
    signature [{"algorithm":"ed25519","keyid":"sha256:...","signature":"<base64>"}] or,
    while rotating keys, [{"signatures":[ ... ]}].

    Each signature covers {!signing_input} of the exact bundle bytes. Loading verifies, in
    this order and failing closed at the first problem: size limits, the signature (any
    trusted key, any listed signature), canonical form, the digest, the document structure
    (unknown members are errors), and only then compiles the policies. *)

module Canonical = Canonical
module Key = Key
module B64 = B64

(** {1 Errors} *)

type error =
  | Io of string  (** a file cannot be read or written *)
  | Too_large of { what : string; size : int; limit : int }
  | Signature_invalid of string
      (** malformed signature file, or no signature verifies with a trusted key *)
  | Malformed of string  (** not canonical JSON, bad structure, unknown member, ... *)
  | Digest_mismatch of { expected : string; actual : string }
  | Invalid_policy of { policy : string; errors : Haltsql_core.Load_error.t list }
  | Invalid_catalog of { catalog : string; errors : Haltsql_core.Load_error.t list }
  | Invalid_key of string

val error_to_string : error -> string
(** One or more lines; never contains key material. *)

(** {1 Bundles} *)

type source = { url : string option; commit : string option }

type metadata = {
  name : string;  (** 1-128 characters: letters, digits, [_ - .]; starts alphanumeric *)
  version : string;  (** 1-64 printable non-space ASCII characters *)
  created_by : string option;
  source : source;
}

type t = {
  metadata : metadata;
  policies : Haltsql_core.Policy.t list;  (** in bundle order *)
  catalogs : (string * Haltsql_core.Catalog.t) list;  (** sorted by name *)
  digest : string;  (** ["sha256:<hex>"] *)
}

val api_version : string
(** ["haltsql.dev/v1"] *)

val default_max_bytes : int
(** 16 MiB: the default size limit for a bundle file. *)

val max_signature_bytes : int
val max_policies : int

val build :
  metadata ->
  policies:Haltsql_core.Policy.t list ->
  catalogs:(string * Haltsql_core.Catalog.t) list ->
  (string, error) result
(** The canonical bundle bytes. Deterministic: the same inputs always give the same bytes
    (no timestamps). Fails on invalid metadata, duplicate or missing policy names, invalid
    catalog names, or a result larger than {!default_max_bytes}. The result is re-parsed
    with {!parse_unverified} before it is returned. *)

val parse_unverified :
  ?max_bytes:int -> ?name_prefix:string -> string -> (t, error) result
(** Checks canonical form, digest and structure, then compiles every policy and catalog.
    {b Does not check any signature}: use it only for inspection or before signing.
    [name_prefix] is prepended to every policy name before compiling. *)

(** {1 Signatures} *)

type signature = { keyid : string; signature : string  (** 64 raw bytes *) }

val signing_input : string -> string
(** [signing_input bundle_bytes] is the message that is signed: the ASCII domain separator
    ["haltsql.dev/v1 PolicyBundle signature\n"] followed by the bundle bytes. *)

val sign : Key.secret -> string -> signature

val signatures_to_string : signature list -> string
(** Canonical signature-file contents (with a trailing newline). One signature uses the
    single-object form; several use [{"signatures":[...]}]. *)

val signatures_of_string : string -> (signature list, error) result
(** Strict: canonical JSON, known members only, algorithm [ed25519], 1-16 signatures,
    64-byte signatures. *)

val verify_signatures :
  Key.public list -> string -> signature list -> (Key.public, error) result
(** The first trusted key that verifies one of the signatures over [bundle_bytes]. A
    signature whose keyid matches no trusted key is skipped. Fails with
    {!Signature_invalid} when the key list is empty or nothing verifies. *)

(** {1 Loading (for the server)} *)

val read_file : max_bytes:int -> what:string -> string -> (string, error) result
(** Reads a regular file of at most [max_bytes] bytes. *)

val signature_path : string -> string
(** [bundle ^ ".sig"] *)

val load_verified_bundle :
  ?max_bytes:int ->
  ?name_prefix:string ->
  ?signature_file:string ->
  string ->
  Key.public list ->
  (t * Key.public, error) result
(** [load_verified_bundle path keys] reads [path] and its signature file (default
    {!signature_path}), verifies a signature with one of [keys] {e before} parsing
    anything, then {!parse_unverified}. Returns the bundle and the key that verified it.
*)

val load_verified :
  ?max_bytes:int ->
  ?name_prefix:string ->
  ?signature_file:string ->
  string ->
  Key.public list ->
  (Haltsql_core.Policy.t list, error) result
(** The policies of {!load_verified_bundle}. Key rotation: list both the old and the new
    public key while bundles signed by either are in circulation. *)

val load_config_ref :
  ?max_bytes:int ->
  Haltsql_load.Config.bundle_ref ->
  (Haltsql_core.Policy.t list, error) result
(** Decodes the entry's public keys (any undecodable key is an error), then
    {!load_verified} with the entry's [name_prefix]. *)
