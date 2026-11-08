(** DataHub provider for [haltsql schema fetch --from datahub].

    Lists postgres datasets with the GraphQL [scrollAcrossEntities] query (types
    [DATASET], filtered by platform [urn:li:dataPlatform:postgres], paginated through
    [nextScrollId]) and reads, for each dataset, [schemaMetadata.fields] (column names,
    [nativeDataType], tags and glossary terms set by ingestion) and
    [editableSchemaMetadata.editableSchemaFieldInfo] (tags and terms added in the UI or
    through GraphQL), with tag and term names. The response is handed to the
    {!Haltsql_catalog_tools.Pii_import.Datahub} importer.

    - Base URL: the GMS root (e.g. [http://datahub-gms:8080]) or the frontend root (e.g.
      [https://datahub.example.com]); requests go to [/api/graphql]. A GraphQL root ending
      in [/api] or [/api/v2] (the frontend's [/api/v2/graphql]) also works: requests then
      go to [.../graphql].
    - Auth: a Personal Access Token sent as [Authorization: Bearer]; the server must have
      metadata service authentication enabled. Default token variable: [DATAHUB_TOKEN].
    - Scope: only datasets on the [postgres] platform. [filter.service] is the platform
      instance (a server-side [platformInstance] filter). [filter.database] and
      [filter.schemas] are resolved to containers first: database containers (subtype
      [Database]) with that name, then their schema containers (subtype [Schema],
      optionally with those names); datasets are then listed by [container]. So the
      database must have been ingested with containers (the Postgres source does this by
      default). Every returned container and dataset is re-checked against the filter on
      its platform, instance and [parentContainers], so a server that ignores a filter
      cannot widen the scope.
    - Schema and table come from the last two parts of the dataset urn's name, as the
      importer derives them; column types are [nativeDataType], lower-cased.
    - No dataset (or no database container) in scope is an error.

    Validated against a live DataHub v1.8.0: see [test/catalog_live/datahub/README.md]. *)

include Provider.S

val page_size : unit -> int
(** Datasets requested per page ([count]): 100, or [HALTSQL_DATAHUB_PAGE_SIZE] (1-1000)
    when set; the live validation sets it small to exercise pagination. *)
