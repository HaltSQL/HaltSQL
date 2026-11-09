(* Catalog snapshot decoding (internal; see [Catalog_load]).

   Snapshot names are stored EXACTLY as written: a snapshot describes the
   database as Postgres stores it (e.g. produced by [haltsql schema pull]), so
   unquoted names are not case-folded. Table keys are ["schema.table"]; a part
   that contains '.' or '"' (or does not look like an identifier) is written in
   double quotes, e.g. ["app.\"odd.name\""]. Column entries are names or
   [{name, type}] objects. *)

open Haltsql_core

let keys = [ "apiVersion"; "kind"; "metadata"; "tables" ]

let render_raw name =
  if name <> "" && Ident.parse_parts ~lower_unquoted:false name = Ok [ name ] then name
  else
    let b = Buffer.create (String.length name + 2) in
    Buffer.add_char b '"';
    String.iter
      (fun c -> if c = '"' then Buffer.add_string b "\"\"" else Buffer.add_char b c)
      name;
    Buffer.add_char b '"';
    Buffer.contents b

let table_key (tb : Catalog.table) = render_raw tb.schema ^ "." ^ render_raw tb.name

let to_json (c : Catalog.t) : Yojson.Safe.t =
  `Assoc
    [
      ( "tables",
        `Assoc
          (List.map
             (fun (tb : Catalog.table) ->
               ( table_key tb,
                 `Assoc
                   [
                     ( "columns",
                       `List
                         (List.map
                            (fun (c : Catalog.column) ->
                              match c.col_type with
                              | None -> `String c.col_name
                              | Some ty ->
                                  `Assoc
                                    [ ("name", `String c.col_name); ("type", `String ty) ])
                            tb.columns) );
                   ] ))
             c.tables) );
    ]

let decode_column ctx path (j : Yojson.Safe.t) : Catalog.column option =
  match j with
  | `String "" ->
      Dec.error ctx path "column name must not be empty";
      None
  | `String s -> Some { col_name = s; col_type = None }
  | `Assoc _ -> (
      match Dec.obj ctx path ~keys:[ "name"; "type" ] j with
      | None -> None
      | Some kvs -> (
          let name = Dec.req ctx kvs path "name" (Dec.non_empty_string ctx) in
          let ty = Dec.opt kvs path "type" (Dec.non_empty_string ctx) in
          match name with
          | Some n ->
              Some { col_name = n; col_type = Option.map String.lowercase_ascii ty }
          | None -> None))
  | j ->
      Dec.type_error ctx path "a column name or {name, type}" j;
      None

let decode_table ctx path key (j : Yojson.Safe.t) : Catalog.table option =
  let ids =
    match Ident.parse_parts ~lower_unquoted:false key with
    | Ok [ s; n ] -> Some (s, n)
    | Ok _ ->
        Dec.error ctx path
          (Printf.sprintf "catalog table %S must be written as \"schema.table\"" key);
        None
    | Error e ->
        Dec.error ctx path e;
        None
  in
  match Dec.obj ctx path ~keys:[ "columns" ] j with
  | None -> None
  | Some kvs -> (
      let cols =
        Dec.req ctx kvs path "columns" (fun p v ->
            Dec.list_of ctx p (decode_column ctx) v)
      in
      (match cols with
      | Some [] -> Dec.error ctx (Lpath.key path "columns") "must not be empty"
      | Some cs ->
          let seen = Hashtbl.create 16 in
          List.iteri
            (fun i (c : Catalog.column) ->
              if Hashtbl.mem seen c.col_name then
                Dec.error ctx
                  (Lpath.idx (Lpath.key path "columns") i)
                  (Printf.sprintf "duplicate column %S" c.col_name)
              else Hashtbl.add seen c.col_name ())
            cs
      | None -> ());
      match (ids, cols) with
      | Some (schema, name), Some columns -> Some { Catalog.schema; name; columns }
      | _ -> None)

let non_authoritative_message =
  "this catalog snapshot is not authoritative: it describes a data catalog's view of the \
   tables (from `haltsql schema fetch`), which can lag behind the database, so it cannot \
   be trusted for SELECT * expansion or search_path checks. Snapshot the database with \
   `haltsql schema pull` and reference that file instead"

(* SECURITY: the analyzer trusts a catalog as the complete column list of every table and
   the complete relation list of every schema. [metadata.authoritative: false] marks a
   snapshot built from a data catalog (which can lag behind ALTER TABLE): refused unless
   the caller only wants the structure as a hint (the policy drafter). *)
let check_authoritative ctx path ~allow_non_authoritative kvs =
  match Dec.field kvs "metadata" with
  | None -> ()
  | Some (`Assoc m) -> (
      let p = Lpath.key (Lpath.key path "metadata") "authoritative" in
      match List.assoc_opt "authoritative" m with
      | None | Some (`Bool true) -> ()
      | Some (`Bool false) ->
          if not allow_non_authoritative then Dec.error ctx p non_authoritative_message
      | Some j -> Dec.type_error ctx p "a boolean" j)
  | Some j -> Dec.type_error ctx (Lpath.key path "metadata") "a mapping" j

let decode ?(allow_non_authoritative = false) ctx path (j : Yojson.Safe.t) :
    Catalog.t option =
  match Dec.obj ctx path ~keys j with
  | None -> None
  | Some kvs -> (
      Dec.header ctx ~required:false kvs path ~kind:"Catalog";
      check_authoritative ctx path ~allow_non_authoritative kvs;
      let tables =
        Dec.req ctx kvs path "tables" (fun p v ->
            match Dec.map ctx p v with
            | None -> None
            | Some tkvs ->
                Some
                  (List.filter_map
                     (fun (k, tj) -> decode_table ctx (Lpath.key p k) k tj)
                     tkvs))
      in
      match tables with
      | None -> None
      | Some tables ->
          let seen = Hashtbl.create 16 in
          List.iter
            (fun (tb : Catalog.table) ->
              let k = (tb.schema, tb.name) in
              if Hashtbl.mem seen k then
                Dec.error ctx (Lpath.key path "tables")
                  (Printf.sprintf "table %s is listed twice" (table_key tb))
              else Hashtbl.add seen k ())
            tables;
          let tables =
            List.stable_sort
              (fun (a : Catalog.table) (b : Catalog.table) ->
                compare (a.schema, a.name) (b.schema, b.name))
              tables
          in
          Some { Catalog.tables })

let of_json ?allow_non_authoritative ?file ?positions ?(path = Lpath.root) j =
  let ctx = Dec.create ?file ?positions () in
  match decode ?allow_non_authoritative ctx path j with
  | Some c when not (Dec.has_errors ctx) -> Ok c
  | _ -> Error (Dec.errors ctx)

let of_file ?allow_non_authoritative file =
  match Docpos.parse_file file with
  | Error e -> Error e
  | Ok (j, positions) -> of_json ?allow_non_authoritative ~file ~positions j
