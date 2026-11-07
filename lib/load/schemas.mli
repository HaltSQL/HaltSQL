(** JSON Schemas (draft 2020-12) for each document kind, published for editor autocomplete
    and CI validation ([haltsql schema export]). *)

val policy : Yojson.Safe.t
val config : Yojson.Safe.t
val catalog : Yojson.Safe.t
val scenario : Yojson.Safe.t

val all : (string * Yojson.Safe.t) list
(** [(file_name, schema)], e.g. [("policy.schema.json", policy)]. *)
