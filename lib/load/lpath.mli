(** Key paths inside a policy, config, catalog or scenario document.

    Every {!Haltsql_core.Load_error.t} carries the path of the offending value, rendered
    with {!to_string}, e.g. [tables."app.orders".tenant_column] or [policies[0].path]. The
    document readers ([Docpos]) record source positions under the same rendered paths, so
    a decoder that knows a value's path can also report its line and column.

    Internal to [haltsql.load]. *)

(** One step into a document. *)
type seg = Key of string  (** a mapping key *) | Idx of int  (** a 0-based list index *)

type t = seg list
(** A path, stored {b innermost segment first} (so extending it is O(1)). The empty list
    is the document root. *)

val root : t
(** The document root; renders as [""]. *)

val key : t -> string -> t
(** [key p k] is the path of key [k] in the mapping at [p]. *)

val idx : t -> int -> t
(** [idx p i] is the path of element [i] of the list at [p]. *)

val parent : t -> t option
(** The enclosing path, or [None] for {!root}. *)

val to_string : t -> string
(** Outermost segment first, keys joined with ['.'], indices as [[i]]. Keys made only of
    ASCII letters, digits, ['_'] and ['-'] are written bare; any other key is written in
    double quotes with ['"'], ['\\'] and newlines escaped, so the rendering is
    unambiguous. *)
