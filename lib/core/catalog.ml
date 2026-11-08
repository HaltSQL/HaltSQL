(** Schema knowledge used for name resolution and [*] expansion.

    Built from the policy's column lists and, optionally, a schema snapshot produced by
    [haltsql schema pull]. All names are stored exactly as Postgres stores them (unquoted
    identifiers lower-cased).

    Trust rule: the analyzer treats an entry as the {b complete} column list of the real
    table, so it may expand [*] against it. It therefore only trusts entries that carry
    column types (snapshots from [haltsql schema pull] always do); an untyped entry is
    ignored, which can only cause a denial. *)

type column = {
  col_name : string;
  col_type : string option;  (** lower-case type name, when the snapshot records it *)
}

type table = {
  schema : string;
  name : string;
  columns : column list;  (** complete column list of the real table *)
}

type t = { tables : table list }

let empty = { tables = [] }

(** [find t ~schema ~name] is the entry for [schema.name] (exact, case-sensitive match).
*)
let find t ~schema ~name =
  List.find_opt
    (fun tb -> String.equal tb.schema schema && String.equal tb.name name)
    t.tables

(** Column names of a table, in catalog order. *)
let column_names tb = List.map (fun c -> c.col_name) tb.columns

(** Snapshot file format:
    [{"tables": {"app.orders": {"columns": [{"name": "id", "type": "int8"}]}}}] Column
    entries may also be plain strings. *)
let to_json t : Yojson.Safe.t =
  `Assoc
    [
      ( "tables",
        `Assoc
          (List.map
             (fun tb ->
               ( tb.schema ^ "." ^ tb.name,
                 `Assoc
                   [
                     ( "columns",
                       `List
                         (List.map
                            (fun c ->
                              `Assoc
                                (("name", `String c.col_name)
                                ::
                                (match c.col_type with
                                | Some ty -> [ ("type", `String ty) ]
                                | None -> [])))
                            tb.columns) );
                   ] ))
             t.tables) );
    ]
