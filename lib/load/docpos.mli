(** Position-tracking YAML / JSON reader: the first stage of every document loader.

    Policy, config, catalog and scenario documents are read here into a [Yojson.Safe.t]
    tree plus a table of source positions keyed by rendered key path (see
    {!Lpath.to_string}), so decoders can report [file:line:col: path: message]. The public
    entry point is [Docload]; this module is internal to [haltsql.load].

    {2 Safety limits}

    Documents may come from untrusted places (bundles, CI checkouts), so reading is
    bounded and never raises:
    - input is limited to {!max_document_bytes};
    - nesting is limited to 64 levels (both formats);
    - YAML alias expansion may produce at most 10 000 nodes in total (billion-laughs
      protection);
    - duplicate mapping keys are errors in both formats;
    - JSON is strict RFC 8259 and must be valid UTF-8.

    {2 YAML typing}

    YAML uses the 1.2 core schema with deliberate restrictions: only plain (unquoted)
    scalars are typed; [yes]/[no]/[on]/[off] stay strings; decimal integers with a leading
    zero ([012]) stay strings (YAML 1.1 tools would read them as octal); [.inf] and [.nan]
    are rejected; every explicit tag is rejected; a stream holds at most one document. *)

type pos = { line : int;  (** 1-based *) column : int  (** 1-based *) }
(** A source position. *)

type positions = (string, pos) Hashtbl.t
(** Rendered key path ({!Lpath.to_string}; [""] for the root) -> position of the key (for
    mapping members) or of the value (for list elements and the root). *)

(** Document syntax. *)
type format = Yaml | Json

val max_document_bytes : int
(** Largest accepted document, in bytes (4 MiB). *)

val is_digit : char -> bool
(** ASCII ['0'..'9']. *)

val resolve_plain : string -> (Yojson.Safe.t, string) result
(** YAML 1.2 core-schema typing of a plain scalar, with the restrictions described above.
    Also used to type values substituted from environment variables. *)

val parse :
  ?file:string ->
  format ->
  string ->
  (Yojson.Safe.t * positions, Haltsql_core.Load_error.t list) result
(** [parse ?file fmt s] reads one document. [file] is used only in error locations. Never
    raises: every problem is a located {!Haltsql_core.Load_error.t}. *)

val read_file : ?limit:int -> string -> (string, Haltsql_core.Load_error.t list) result
(** [read_file file] reads a whole file, refusing files larger than [limit] (default
    {!max_document_bytes}) before reading them. *)

val format_of_path : string -> format option
(** From the extension, case-insensitively: [.yaml]/[.yml] -> [Yaml], [.json] -> [Json].
*)

val parse_file :
  ?format:format ->
  string ->
  (Yojson.Safe.t * positions, Haltsql_core.Load_error.t list) result
(** [parse_file file] is {!read_file} followed by {!parse}, detecting the format from the
    extension unless [format] is given. *)
