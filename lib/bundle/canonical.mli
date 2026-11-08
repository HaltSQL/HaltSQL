(** Canonical JSON serialization used for bundle digests and signatures.

    The canonical form of a JSON value is its compact serialization (no insignificant
    whitespace) with the members of every object sorted by key in byte order. Only [null],
    booleans, strings, integers that fit an OCaml [int], arrays and objects are allowed:
    floats, big-integer literals and duplicate object keys are rejected, so two equal
    documents always serialize to the same bytes. *)

val normalize : Yojson.Safe.t -> (Yojson.Safe.t, string) result
(** Sorts object members recursively; [Error] on a float, a big integer literal or a
    duplicate key (the message names the JSON path). *)

val to_string : Yojson.Safe.t -> (string, string) result
(** [normalize] then compact serialization. *)

val of_string : string -> (Yojson.Safe.t, string) result
(** Parses [s] and succeeds only when [s] is exactly the canonical serialization of the
    parsed value (followed by one optional ['\n']). Rejects every non-canonical encoding:
    whitespace, unsorted or duplicate keys, alternative escapes, floats. *)
