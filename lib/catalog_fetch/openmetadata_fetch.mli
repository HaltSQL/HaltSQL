(** OpenMetadata provider for [haltsql schema fetch --from openmetadata].

    Reads table entities from the OpenMetadata REST API
    ([GET /api/v1/tables?fields=columns,tags], cursor-paginated through [paging.after])
    and hands them to the {!Haltsql_catalog_tools.Pii_import.Openmetadata} importer.

    - Base URL: the server root, e.g. [https://openmetadata.example.com] (the provider
      adds [/api/v1/...]), or the API root ending in [/api] (it then adds [/v1/...]).
    - Auth: a bot JWT sent as [Authorization: Bearer]. A bot with the [DataConsumer] role
      is enough. Default token variable: [OPENMETADATA_TOKEN].
    - Scope: [filter.service] is the database service name, [filter.database] the database
      name inside it (requires [service]: OpenMetadata database FQNs are
      [service.database]), [filter.schemas] the schema names (one [databaseSchema=]
      listing each; needs service and database). With service only, [service=] scopes the
      listing. Returned tables are re-checked against the filter, so a server that ignores
      a query parameter cannot widen the scope.
    - Soft-deleted tables are excluded ([include=non-deleted]).
    - No tables in scope is an error: OpenMetadata answers an unknown database or service
      with an empty list, not a 404.

    Validated against a live OpenMetadata 2.0.7 server: see
    [test/catalog_live/openmetadata/README.md]. *)

include Provider.S

val page_size : unit -> int
(** Entities requested per page ([limit]): 100, or [HALTSQL_OPENMETADATA_PAGE_SIZE]
    (1-1000) when set; the live validation sets it small to exercise pagination. *)

val quote_name : string -> string
(** One FQN part, double-quoted when it contains a dot, as OpenMetadata does. *)
