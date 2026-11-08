(** Shared YAML/JSON document reader (PLAN.md §6.6).

    Both formats are parsed into the same [Yojson.Safe.t] tree. YAML is read with YAML 1.2
    core-schema semantics ([no]/[on]/[yes] stay strings, [012] is not octal). Duplicate
    keys, custom tags and excessive alias expansion are errors. *)

open Haltsql_core

type format = Yaml | Json

val format_of_path : string -> format option
(** From extension: [.yaml]/[.yml] -> Yaml, [.json] -> Json. *)

val max_document_bytes : int
(** Largest accepted document, in bytes (4 MiB). Larger inputs are rejected before
    parsing. *)

val of_string :
  ?file:string -> format -> string -> (Yojson.Safe.t, Load_error.t list) result
(** Parses one document. Never raises; [file] is used only in error locations. *)

val of_file : ?format:format -> string -> (Yojson.Safe.t, Load_error.t list) result
(** Detects the format from the extension unless [format] is given. *)

val to_string : format -> Yojson.Safe.t -> string
(** Pretty-print a tree in either format (used by [haltsql convert]). *)
