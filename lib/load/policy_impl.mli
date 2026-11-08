(** Policy documents: decoding, validation and normalization into
    {!Haltsql_core.Policy.t}.

    The public API is [Policy_load]; [Config] uses {!decode} for policies written inline
    in a config document. See PLAN.md section 6.5 for the document format.

    {2 Guarantees}

    A policy is returned only if the whole document decoded without a single error
    (unknown keys, bad identifiers, duplicate tables after normalization, tenant columns
    naming an undeclared tenancy key, columns missing from the catalog snapshot, ...):
    loading fails closed. On success the invariants documented on {!Haltsql_core.Policy}
    hold, in particular:
    - identifiers are folded as PostgreSQL would ({!Ident}); unqualified table names are
      qualified with the first [search_path] schema;
    - function presets are expanded; operators and denied casts are sorted and unique;
    - the catalog is {b empty} unless a [catalog:] snapshot is given. It is never derived
      from the policy's own column lists, because consumers treat catalog entries as
      complete column lists (a derived entry would make [SELECT *] look safe);
    - [version] is ["sha256:<hex>"] of the canonical (key-sorted) {!to_json} form, so the
      same policy written in YAML or JSON gets the same version.

    Placeholders: only [${ctx.<field>}] is accepted, and only as a value under
    [tenancy.keys]; [${env:...}] / [${file:...}] are rejected in policies. *)

open Haltsql_core

(** {1 Built-in allowlists} *)

val function_presets : (string * string list) list
(** Named function allowlists usable in [functions.presets] (["aggregates"], ["math"],
    ["string"], ["regex"], ["datetime"], ["json"], ["conditional"], ["window"]). They
    contain only side-effect-free built-ins: nothing that sleeps, reads files, opens
    connections, touches large objects, sequences, settings, advisory locks or other
    backends, produces random values, or generates unbounded rows. *)

val default_operators : string list
(** Operators allowed when a policy has no [operators] section. *)

val default_deny_casts : string list
(** Cast target types denied when a policy has no [deny_casts] section: the
    object-identifier types ([regclass], [regproc], ...) whose input functions read the
    system catalogs, and [txid_snapshot]. *)

(** {1 Lexical helpers shared with [Config]} *)

val is_word_char : char -> bool
(** ASCII letter, digit or ['_']. *)

val valid_name : string -> bool
(** A policy name: 1-128 characters from letters, digits, ['.'], ['_'] and ['-'], starting
    with a letter or digit. *)

(** {1 Decoding} *)

val decode :
  Dec.ctx ->
  ?base_dir:string ->
  ?inline:bool ->
  Lpath.t ->
  Yojson.Safe.t ->
  Policy.t option
(** [decode ctx ?base_dir ?inline path j] decodes the policy document at [path], recording
    every problem in [ctx]. [base_dir] resolves a relative [catalog:] path. [inline]
    (default [false]) makes the [apiVersion]/[kind] header optional, for policies embedded
    in a config document. Returns [Some _] only if [ctx] has no errors after decoding;
    callers must still check {!Dec.has_errors} when they share [ctx] with other decoders.
*)

val of_json :
  ?file:string ->
  ?base_dir:string ->
  ?positions:Docpos.positions ->
  Yojson.Safe.t ->
  (Policy.t, Load_error.t list) result
(** Decodes a whole policy document. [base_dir] defaults to the directory of [file]. *)

val of_string :
  ?file:string ->
  ?base_dir:string ->
  Docpos.format ->
  string ->
  (Policy.t, Load_error.t list) result
(** Parses (with source positions) and decodes a policy document. *)

val of_file : string -> (Policy.t, Load_error.t list) result
(** Reads a policy file (YAML or JSON, by extension); a relative [catalog:] path is
    resolved against the file's directory. *)

(** {1 Normalized form} *)

val to_json : Policy.t -> Yojson.Safe.t
(** The normalized policy document: presets expanded, identifiers rendered so that loading
    the output gives back an equal policy. Its key-sorted compact serialization is what
    [version] hashes. *)
