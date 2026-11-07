(** PII manifests: which columns carry personal or sensitive data, normalized from data
    catalog exports (see {!Pii_import}).

    File format (JSON):
    {v
    {"tables": {"app.customers": {"columns": {
        "email": {"classifications": ["PII", "email"], "source": "dbt"}}}}}
    v}
    An optional ["metadata"] object is allowed and ignored. Table keys follow the catalog
    snapshot convention ({!Snapshot.table_key}). When manifests are merged, ["source"]
    lists every contributing tool, comma-separated. *)

type entry = {
  schema : string;
  table : string;
  column : string;
  classifications : string list;  (** sorted, de-duplicated *)
  sources : string list;  (** sorted, de-duplicated tool names, e.g. ["dbt"] *)
}

type t = entry list
(** Sorted by (schema, table, column); one entry per column. *)

val empty : t

val add : t -> entry -> t
(** Adds or merges (union of classifications and sources). *)

val merge : t list -> t

val find : t -> schema:string -> table:string -> column:string -> entry option
(** ASCII case-insensitive on every part: catalogs exported from other engines often
    upper-case names, and over-matching only ever excludes more columns. *)

val to_json : ?metadata:(string * Yojson.Safe.t) list -> t -> Yojson.Safe.t
val of_json : Yojson.Safe.t -> (t, string) result
val of_file : string -> (t, string) result

(** Matching of tool labels (tags, classifications, glossary terms) against configured PII
    terms. *)
module Matcher : sig
  type config = {
    tags : string list;  (** terms matched against tags/classifications/attributes *)
    terms : string list;  (** terms matched against business-glossary terms *)
  }

  val default_terms : string list
  (** [pii; sensitive; confidential; restricted; gdpr; phi; pci; personal; email; phone;
       ssn; secret]. *)

  val default : config

  val tokens : string -> string list
  (** Lower-cased words: split on every non-alphanumeric byte and on camelCase boundaries.
      ["urn:li:tag:PersonalData"] gives [urn; li; tag; personal; data]. *)

  val find_match : string list -> string -> string option
  (** [find_match terms label]: the first term whose token sequence occurs contiguously in
      the label's tokens. ["contains_pii"] matches [pii]; ["pii_email"] matches [pii];
      ["piiset"] does not. A single-word term of three or more letters also matches the
      acronym of a label of two or more words: ["Personally Identifiable Information"]
      matches [pii], ["Protected Health Information"] matches [phi]. *)
end
