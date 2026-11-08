type filter = { service : string option; database : string option; schemas : string list }
type column = { name : string; data_type : string option }
type table = { schema : string; name : string; columns : column list }

type fetched = {
  source : Haltsql_catalog_tools.Pii_import.source;
  document : Yojson.Safe.t;
  tables : table list;
  warnings : string list;
}

module type S = sig
  val name : string
  val description : string
  val default_token_env : string
  val fetch : Fetch_client.t -> filter -> (fetched, string) result Lwt.t
end
