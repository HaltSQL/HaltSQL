(** Live fetching of PII metadata from data catalogs ([haltsql schema fetch]).

    {1 Security model}

    A data catalog is trusted for {e labels} (tags, classifications, glossary terms): a
    stale label can only make HaltSQL exclude too little, which the name heuristics and
    review mitigate, and the import errs towards flagging. A data catalog is {b never}
    trusted for {e structure}: HaltSQL's analyzer treats a typed catalog snapshot as the
    complete column list of every table (to expand [SELECT *]) and as the complete list of
    relations in a schema (to rule out [search_path] shadowing). A catalog crawler that
    lags behind [ALTER TABLE ... ADD COLUMN ssn] would turn that into a leak.

    So the structure seen by a provider is only ever written as a {e non-authoritative}
    snapshot ({!catalog_snapshot}): untyped columns and [metadata.authoritative: false].
    The catalog loader refuses to load such a snapshot as a policy [catalog:], and
    [haltsql policy draft] uses it only to choose column lists, emitting no [catalog:]
    reference, so [SELECT *] stays denied. The authoritative structure comes from
    [haltsql schema pull] against Postgres. *)

open Haltsql_catalog_tools

val providers : (module Provider.S) list
(** Every built-in provider. *)

val find : string -> (module Provider.S) option
(** By {!Provider.S.name}. *)

type result = {
  manifest : Pii.t;
  scanned_columns : int;
  tables : Provider.table list;
  warnings : string list;
  requests : int;
}

val run :
  ?config:Pii.Matcher.config ->
  (module Provider.S) ->
  Fetch_client.t ->
  Provider.filter ->
  (result, string) Stdlib.result Lwt.t
(** Fetches and imports. Fails when the provider fails or returns no column metadata. *)

val catalog_snapshot : database:string option -> Provider.table list -> Snapshot.t
(** A non-authoritative snapshot of the catalog's view: every column untyped,
    [authoritative = false]. *)
