(* Stub: implemented in the foundation commit. *)
open Haltsql_catalog_tools

(* Each provider PR adds one line here. *)
let providers : (module Provider.S) list = []

let find n =
  List.find_opt (fun (module P : Provider.S) -> String.equal P.name n) providers

type result = {
  manifest : Pii.t;
  scanned_columns : int;
  tables : Provider.table list;
  warnings : string list;
  requests : int;
}

let run ?config:_ _ _ _ = Lwt.return (Error "not implemented")
let catalog_snapshot ~database:_ _ = failwith "not implemented"
