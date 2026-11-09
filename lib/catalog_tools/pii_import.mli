(** Importers that turn data-catalog exports into a {!Pii.t} manifest.

    Each importer extracts, per column, the labels the tool attaches (tags,
    classifications, sensitivity attributes, glossary terms) and keeps the columns where a
    label matches the configured terms ({!Pii.Matcher}). Recorded classifications are the
    matching labels as the tool shows them (URN prefixes removed).

    Supported inputs:
    - [Dbt]: [manifest.json] (column [tags], [meta], [config.tags], [config.meta],
      [policy_tags]; nested meta keys such as [{"governance": {"pii": true}}]; values that
      are [false]/[null]/["no"] do not count; column [description], matched word by word
      and recorded as ["comment:<term>"]) and [catalog.json] (column comments, matched
      word by word). Tables are [schema] + [alias]/[identifier]/[name], so models with an
      alias or a custom schema and sources with an identifier name the relation dbt built
      or reads. Validated against dbt-core 1.12 / dbt-postgres 1.11 output
      (test/catalog_live/dbt).
    - [Datahub]: file-sink exports (MCE snapshots and MCPs, including MCPs whose
      [aspect.value] is a JSON string) and GraphQL dataset responses. Tags
      ([urn:li:tag:*]) and glossary terms ([urn:li:glossaryTerm:*], plus their
      [name]/[properties.name]) on [schemaMetadata] and [editableSchemaMetadata] fields.
      The dataset URN gives the table (last two dot-separated name parts); field paths in
      the v2 format ([[version=2.0].[type=string].email]) are reduced to the last name.
    - [Unity]: rows of [information_schema.column_tags] (array of objects, an object with
      a ["column_tags"]/["rows"] array, or a SQL Statement API result with
      [manifest.schema.columns] + [result.data_array]); or Unity Catalog REST table JSON
      (one table, a list, or [{"tables": [...]}]) whose columns carry [tags] as a map or
      as a list of [{key,value}] / [{tag_name,tag_value}].
    - [Atlan]: asset search results ([{"entities": [...]}], a list, or
      [{"entity": {...}}]) of [Column] assets: [classifications]/[atlanTags] ([typeName],
      [displayName], [tagName]), [classificationNames], and glossary [meanings]
      ([displayText]) / [meaningNames]. Table from [tableName]/[viewName]/
      [materialisedViewName] + [schemaName], else the last segments of [qualifiedName].
    - [Collibra]: asset exports (a list, or [{"results": [...]}]/[{"assets": [...]}]) of
      column assets identified by [fullName] (["db>schema>table>column"] or dotted):
      classification-like attributes (attribute type names mentioning classification,
      sensitivity, privacy, confidentiality, personal, PII or security; given as a list of
      [{type:{name}, value}] or as a map), [tags], accepted/suggested data classification
      matches ([classificationMatches]/[dataClassifications], [REJECTED] ignored), and
      relations to business terms.
    - [Openmetadata]: OpenMetadata table entities as returned by
      [GET /api/v1/tables?fields=columns,tags] (one table, a list, or the paged
      [{"data": [...]}] response). Table from [databaseSchema.name] + [name], else the
      last two parts of [fullyQualifiedName] (double-quoted parts honoured). Labels are
      [columns[].tags[].tagFQN]: [source: "Glossary"] is a glossary term, anything else
      (normally ["Classification"]) a tag; the full FQN is matched, so ["PII.Sensitive"]
      and ["PersonalData.Personal"] count while ["Tier.Tier1"] does not. Tags on nested
      [children] (STRUCT fields) apply to the top-level column. Column descriptions and
      table-level tags are not labels. *)

type source = Dbt | Datahub | Unity | Atlan | Collibra | Openmetadata

val source_to_string : source -> string
(** ["dbt"], ["datahub"], ["unity"], ["atlan"], ["collibra"], ["openmetadata"]. *)

val source_of_string : string -> source option
(** Parses a [--from] source name. *)

val all_sources : source list
(** Every supported source, in documentation order. *)

type result = {
  manifest : Pii.t;
  scanned_columns : int;  (** columns found in the export, matched or not *)
  warnings : string list;
}

val import :
  ?config:Pii.Matcher.config -> source -> Yojson.Safe.t -> (result, string) Stdlib.result
(** Fails when the document has no column metadata this importer understands. *)

val import_file :
  ?config:Pii.Matcher.config -> source -> string -> (result, string) Stdlib.result
(** {!import} on a JSON file. *)
