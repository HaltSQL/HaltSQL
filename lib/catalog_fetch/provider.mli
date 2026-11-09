(** What a live catalog provider returns, and the signature every provider implements. *)

type filter = {
  service : string option;
      (** provider-specific scope: OpenMetadata database service, DataHub platform
          instance, Unity Catalog catalog name *)
  database : string option;  (** database name as the catalog records it *)
  schemas : string list;  (** only these schemas; [[]] = all *)
}

type column = { name : string; data_type : string option }
type table = { schema : string; name : string; columns : column list }

type fetched = {
  source : Haltsql_catalog_tools.Pii_import.source;
      (** the importer that understands [document] *)
  document : Yojson.Safe.t;  (** fed to {!Haltsql_catalog_tools.Pii_import.import} *)
  tables : table list;
      (** the tables and columns as the catalog sees them. NOT authoritative: a crawler
          can lag behind migrations, so this is only ever used to build a
          non-authoritative snapshot (see {!Catalog_fetch.catalog_snapshot}). *)
  warnings : string list;
}

module type S = sig
  val name : string
  (** the [--from] value, e.g. ["openmetadata"] *)

  val description : string
  (** one line for [--help] *)

  val default_token_env : string
  (** e.g. ["OPENMETADATA_TOKEN"] *)

  val fetch : Fetch_client.t -> filter -> (fetched, string) result Lwt.t
end
