(* Test driver: the schema pull/import/fetch and policy draft subcommands, wired the way
   main.ml registers them. [schema fetch] gets a fake provider: it imports the dbt
   manifest named by $FAKE_CATALOG_DOC (tables from its nodes), or, when that is unset,
   GETs /manifest from --url (to exercise network errors). *)

open Cmdliner
module Cf = Haltsql_catalog_fetch

module Fake : Cf.Provider.S = struct
  let name = "fake"
  let description = "test provider"
  let default_token_env = "FAKE_CATALOG_TOKEN"

  let tables_of_dbt (filter : Cf.Provider.filter) (doc : Yojson.Safe.t) =
    let open Yojson.Safe.Util in
    match member "nodes" doc with
    | `Assoc nodes ->
        List.filter_map
          (fun (_, n) ->
            match (member "schema" n, member "name" n, member "columns" n) with
            | `String schema, `String name, `Assoc cols
              when filter.schemas = [] || List.mem schema filter.schemas ->
                Some
                  {
                    Cf.Provider.schema;
                    name;
                    columns =
                      List.map
                        (fun (c, _) -> { Cf.Provider.name = c; data_type = None })
                        cols;
                  }
            | _ -> None)
          nodes
    | _ -> []

  let fetch client filter =
    let open Lwt.Syntax in
    let+ doc =
      match Sys.getenv_opt "FAKE_CATALOG_DOC" with
      | Some f -> Lwt.return (Ok (Yojson.Safe.from_file f))
      | None -> Cf.Fetch_client.get_json client "/manifest"
    in
    Result.map
      (fun document ->
        {
          Cf.Provider.source = Haltsql_catalog_tools.Pii_import.Dbt;
          document;
          tables = tables_of_dbt filter document;
          warnings = [];
        })
      doc
end

let () =
  let main =
    Cmd.group (Cmd.info "haltsql")
      [
        Cmd.group (Cmd.info "schema")
          (Cmd_schema.cmds @ [ Cmd_schema_fetch.cmd_with ~providers:[ (module Fake) ] ]);
        Cmd.group
          (Cmd.info "schema-noproviders")
          [ Cmd_schema_fetch.cmd_with ~providers:[] ];
        Cmd_policy_draft.cmd;
      ]
  in
  exit
    (match Cmd.eval_value main with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error _ -> 2)
