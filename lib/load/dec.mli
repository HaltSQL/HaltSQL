(** Decoding combinators shared by the document loaders (policy, catalog, config,
    scenario).

    A loader walks the [Yojson.Safe.t] tree produced by [Docpos] with these helpers,
    threading a {!ctx} and the {!Lpath.t} of the current value. Errors are
    {b accumulated, never raised}: a decoder that finds a problem records it and returns
    [None] (or a default), and decoding continues, so one pass reports every problem in a
    document. Each error is located at the nearest source position known for its path.

    A loader must check {!has_errors} before using its result: a decoder may return
    [Some _] for a value whose children produced errors (e.g. {!list_of} drops failing
    elements). Loaders therefore only ever return [Ok] when {!val-errors} is empty, which
    is what makes loading fail closed.

    Internal to [haltsql.load]. *)

type json = Yojson.Safe.t

type ctx
(** Error accumulator for one document: the file name, its key-path positions, and the
    errors recorded so far. *)

val create : ?file:string -> ?positions:Docpos.positions -> unit -> ctx
(** [create ?file ?positions ()] is a context with no errors. Without [positions] errors
    are reported without line/column. *)

(** {1 Errors} *)

val error : ctx -> Lpath.t -> string -> unit
(** [error ctx path msg] records [msg] at [path], located at the nearest enclosing path
    that has a known source position. *)

val error_unlocated : ctx -> Lpath.t -> string -> unit
(** Like {!error} but without line/column, for problems that do not come from the document
    text (e.g. environment-variable overrides). *)

val type_error : ctx -> Lpath.t -> string -> json -> unit
(** [type_error ctx path expected j] records ["expected <expected>, found <type of j>"].
*)

val add_errors : ctx -> Haltsql_core.Load_error.t list -> unit
(** Appends already-built errors (e.g. from loading a referenced file), keeping their
    order. *)

val errors : ctx -> Haltsql_core.Load_error.t list
(** All recorded errors, in the order they were recorded. *)

val has_errors : ctx -> bool

(** {1 Shapes}

    Every decoder below records a type error and returns [None] when the value has the
    wrong shape. *)

val obj : ctx -> Lpath.t -> keys:string list -> json -> (string * json) list option
(** A mapping whose keys must all be in [keys]; each unknown key is an error (with a "did
    you mean" hint when a close match exists). The members are returned even when there
    are unknown keys, so decoding can continue. *)

val map : ctx -> Lpath.t -> json -> (string * json) list option
(** A mapping with arbitrary keys. *)

val string : ctx -> Lpath.t -> json -> string option
val non_empty_string : ctx -> Lpath.t -> json -> string option
val bool : ctx -> Lpath.t -> json -> bool option

val int : ctx -> Lpath.t -> ?min:int -> ?max:int -> json -> int option
(** An integer within the optional inclusive bounds. Integers too large for a native [int]
    are errors. *)

val list : ctx -> Lpath.t -> json -> json list option

val list_of : ctx -> Lpath.t -> (Lpath.t -> json -> 'a option) -> json -> 'a list option
(** [list_of ctx path f j] decodes every element with [f] (given the element's path).
    [None] only if [j] is not a list; elements for which [f] returns [None] are dropped
    (their errors are recorded). *)

val string_list : ctx -> Lpath.t -> json -> string list option

val enum : ctx -> Lpath.t -> values:(string * 'a) list -> json -> 'a option
(** A string that must be one of the keys of [values]. *)

(** {1 Fields} *)

val field : (string * json) list -> string -> json option
(** [field kvs k] is the value of [k]; an explicit [null] counts as absent. *)

val opt :
  (string * json) list -> Lpath.t -> string -> (Lpath.t -> json -> 'a option) -> 'a option
(** [opt kvs path k f] decodes optional field [k] with [f] (given the field's path). *)

val req :
  ctx ->
  (string * json) list ->
  Lpath.t ->
  string ->
  (Lpath.t -> json -> 'a option) ->
  'a option
(** Like {!opt}, but records ["required"] when the field is absent. *)

val header :
  ctx -> ?required:bool -> (string * json) list -> Lpath.t -> kind:string -> unit
(** Checks the [apiVersion] (["haltsql.dev/v1"]) and [kind] keys common to every document.
    [required] (default [true]) makes them mandatory; documents embedded in another
    document pass [false]. *)

(** {1 Misc} *)

val dedup : 'a list -> 'a list
(** Removes structurally equal duplicates, keeping the first occurrence and the order. *)

val absolute : ?base_dir:string -> string -> string
(** [absolute ?base_dir p] makes [p] absolute (relative to [base_dir], itself relative to
    the current directory; default: the current directory) and normalizes [.] and [..]
    lexically. Symlinks are not resolved. *)

val base_dir_of : ?base_dir:string -> string option -> string option
(** The directory relative paths in a document resolve against: [base_dir] if given,
    otherwise the directory of the document's file, if any. *)
