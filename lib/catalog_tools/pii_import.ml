(** Data-catalog importers (see pii_import.mli). *)

type source = Dbt | Datahub | Unity | Atlan | Collibra | Openmetadata

let source_to_string = function
  | Dbt -> "dbt"
  | Datahub -> "datahub"
  | Unity -> "unity"
  | Atlan -> "atlan"
  | Collibra -> "collibra"
  | Openmetadata -> "openmetadata"

let all_sources = [ Dbt; Datahub; Unity; Atlan; Collibra; Openmetadata ]
let source_of_string s = List.find_opt (fun x -> source_to_string x = s) all_sources

type result = { manifest : Pii.t; scanned_columns : int; warnings : string list }

(* A label attached to a column; [Tag] labels are matched against config.tags, [Term]
   labels against config.terms. [Comment] is free text: matched against config.tags
   word by word, and recorded as "comment:<term>". *)
type label = Tag of string | Term of string | Comment of string

type candidate = {
  c_schema : string;
  c_table : string;
  c_column : string;
  labels : label list;
}

(* ------------------------------------------------------------ JSON helpers *)

let field k = function `Assoc kvs -> List.assoc_opt k kvs | _ -> None
let str k j = match field k j with Some (`String s) when s <> "" -> Some s | _ -> None
let list k j = match field k j with Some (`List l) -> l | _ -> []
let assoc k j = match field k j with Some (`Assoc kvs) -> kvs | _ -> []

let rec first_some = function
  | [] -> None
  | Some x :: _ -> Some x
  | None :: rest -> first_some rest

let strip_prefix ~prefix s =
  if String.starts_with ~prefix s then
    String.sub s (String.length prefix) (String.length s - String.length prefix)
  else s

let truthy_string s =
  match String.lowercase_ascii (String.trim s) with
  | "" | "false" | "no" | "n" | "0" | "none" | "null" | "off" -> false
  | _ -> true

(* Labels from a key/value metadata tree (dbt meta, Unity tags map):
   - [k: true] -> "k"; [k: false|null|"no"] -> nothing;
   - [k: "v"] -> "k=v"; [k: [v1, v2]] -> "k=v1", "k=v2";
   - nested objects -> "outer.inner..." paths. *)
let rec meta_labels prefix (j : Yojson.Safe.t) : string list =
  let name k = if prefix = "" then k else prefix ^ "." ^ k in
  match j with
  | `Assoc kvs -> List.concat_map (fun (k, v) -> meta_value (name k) v) kvs
  | _ -> []

and meta_value k (v : Yojson.Safe.t) =
  match v with
  | `Bool true -> [ k ]
  | `Int n when n <> 0 -> [ k ]
  | `String s when truthy_string s -> (
      match String.lowercase_ascii (String.trim s) with
      | "true" | "yes" | "y" | "1" -> [ k ]
      | _ -> [ k ^ "=" ^ s ])
  | `List l -> List.concat_map (fun x -> meta_value k x) l
  | `Assoc _ -> meta_labels k v
  | _ -> []

let string_list (j : Yojson.Safe.t option) =
  match j with
  | Some (`List l) ->
      List.filter_map (function `String s when s <> "" -> Some s | _ -> None) l
  | Some (`String s) when s <> "" -> [ s ]
  | _ -> []

(* ------------------------------------------------------------ matching *)

let display label =
  label
  |> strip_prefix ~prefix:"urn:li:tag:"
  |> strip_prefix ~prefix:"urn:li:glossaryTerm:"

let classify (cfg : Pii.Matcher.config) labels =
  List.filter_map
    (function
      | Tag l -> Option.map (fun _ -> display l) (Pii.Matcher.find_match cfg.tags l)
      | Term l -> Option.map (fun _ -> display l) (Pii.Matcher.find_match cfg.terms l)
      | Comment l ->
          Option.map (fun t -> "comment:" ^ t) (Pii.Matcher.find_match cfg.tags l))
    labels
  |> List.sort_uniq compare

let finish cfg source ~what (cands : candidate list) warnings =
  if cands = [] then
    Error
      (Printf.sprintf "no column metadata found; is this a %s export (%s)?"
         (source_to_string source) what)
  else
    let manifest =
      List.fold_left
        (fun acc c ->
          match classify cfg c.labels with
          | [] -> acc
          | classifications ->
              Pii.add acc
                {
                  Pii.schema = c.c_schema;
                  table = c.c_table;
                  column = c.c_column;
                  classifications;
                  sources = [ source_to_string source ];
                })
        Pii.empty cands
    in
    let scanned =
      List.sort_uniq compare
        (List.map (fun c -> (c.c_schema, c.c_table, c.c_column)) cands)
    in
    Ok { manifest; scanned_columns = List.length scanned; warnings = List.rev warnings }

(* ------------------------------------------------------------ dbt *)

let dbt cfg (j : Yojson.Safe.t) =
  let cands = ref [] and warnings = ref [] in
  let node_entries = assoc "nodes" j @ assoc "sources" j in
  List.iter
    (fun (uid, node) ->
      match field "metadata" node with
      | Some (`Assoc _ as md) when str "schema" md <> None -> (
          (* catalog.json *)
          let schema = Option.value (str "schema" md) ~default:"" in
          match str "name" md with
          | None ->
              warnings := Printf.sprintf "%s: no table name; skipped" uid :: !warnings
          | Some table ->
              List.iter
                (fun (k, col) ->
                  let column = Option.value (str "name" col) ~default:k in
                  let labels =
                    match str "comment" col with Some c -> [ Comment c ] | None -> []
                  in
                  cands :=
                    { c_schema = schema; c_table = table; c_column = column; labels }
                    :: !cands)
                (assoc "columns" node))
      | _ -> (
          (* manifest.json *)
          let rt = Option.value (str "resource_type" node) ~default:"" in
          if rt <> "" && not (List.mem rt [ "model"; "seed"; "snapshot"; "source" ]) then
            ()
          else
            let table =
              first_some [ str "alias" node; str "identifier" node; str "name" node ]
            in
            match (str "schema" node, table) with
            | Some schema, Some table ->
                List.iter
                  (fun (k, col) ->
                    let column = Option.value (str "name" col) ~default:k in
                    let config = Option.value (field "config" col) ~default:`Null in
                    let tags =
                      string_list (field "tags" col)
                      @ string_list (field "tags" config)
                      @ string_list (field "policy_tags" col)
                    in
                    let metas =
                      meta_labels "" (Option.value (field "meta" col) ~default:`Null)
                      @ meta_labels "" (Option.value (field "meta" config) ~default:`Null)
                    in
                    (* The column description is free text, like a catalog.json
                       comment; descriptions of sources never reach catalog.json
                       (persist_docs only writes comments on models). *)
                    let description =
                      match str "description" col with
                      | Some d -> [ Comment d ]
                      | None -> []
                    in
                    cands :=
                      {
                        c_schema = schema;
                        c_table = table;
                        c_column = column;
                        labels = List.map (fun t -> Tag t) (tags @ metas) @ description;
                      }
                      :: !cands)
                  (assoc "columns" node)
            | _ ->
                if assoc "columns" node <> [] then
                  warnings :=
                    Printf.sprintf "%s: no schema or name; skipped" uid :: !warnings))
    node_entries;
  finish cfg Dbt ~what:"manifest.json or catalog.json with nodes/sources"
    (List.rev !cands) !warnings

(* ------------------------------------------------------------ DataHub *)

(* urn:li:dataset:(urn:li:dataPlatform:postgres,analytics.app.customers,PROD) *)
let dataset_of_urn urn =
  let prefix = "urn:li:dataset:(" in
  if not (String.starts_with ~prefix urn) then None
  else
    let inner =
      String.sub urn (String.length prefix) (String.length urn - String.length prefix)
    in
    let inner =
      if String.ends_with ~suffix:")" inner then
        String.sub inner 0 (String.length inner - 1)
      else inner
    in
    match String.index_opt inner ',' with
    | None -> None
    | Some i -> (
        let rest = String.sub inner (i + 1) (String.length inner - i - 1) in
        let name =
          match String.rindex_opt rest ',' with
          | Some j -> String.sub rest 0 j
          | None -> rest
        in
        match List.rev (String.split_on_char '.' name) with
        | table :: schema :: _ when table <> "" && schema <> "" ->
            Some (Ok (schema, table))
        | _ -> Some (Error name))

let field_name path =
  String.split_on_char '.' path
  |> List.filter (fun s -> s <> "" && s.[0] <> '[')
  |> List.rev
  |> function
  | x :: _ -> Some x
  | [] -> None

(* Tag and glossary-term labels anywhere inside a field object. *)
let datahub_labels (j : Yojson.Safe.t) =
  let out = ref [] in
  let kind_of s =
    if String.starts_with ~prefix:"urn:li:tag:" s then Some (fun x -> Tag x)
    else if String.starts_with ~prefix:"urn:li:glossaryTerm:" s then
      Some (fun x -> Term x)
    else None
  in
  let rec walk (j : Yojson.Safe.t) =
    match j with
    | `String s -> ( match kind_of s with Some k -> out := k s :: !out | None -> ())
    | `List l -> List.iter walk l
    | `Assoc kvs ->
        (match first_some [ str "urn" j; str "tag" j; str "term" j ] with
        | Some u -> (
            match kind_of u with
            | Some k ->
                let names =
                  List.filter_map Fun.id
                    [ str "name" j; Option.bind (field "properties" j) (str "name") ]
                in
                List.iter (fun n -> out := k n :: !out) names
            | None -> ())
        | None -> ());
        List.iter (fun (_, v) -> walk v) kvs
    | _ -> ()
  in
  walk j;
  List.rev !out

let datahub cfg (j : Yojson.Safe.t) =
  let cands = ref [] and warnings = ref [] in
  let bad = Hashtbl.create 4 in
  let rec walk dataset (j : Yojson.Safe.t) =
    match j with
    | `List l -> List.iter (walk dataset) l
    | `Assoc kvs -> (
        let dataset =
          match
            List.find_map
              (fun k ->
                match str k j with
                | Some u when String.starts_with ~prefix:"urn:li:dataset:" u -> Some u
                | _ -> None)
              [ "urn"; "entityUrn" ]
          with
          | Some u -> (
              match dataset_of_urn u with
              | Some (Ok d) -> Some d
              | Some (Error name) ->
                  if not (Hashtbl.mem bad name) then begin
                    Hashtbl.add bad name ();
                    warnings :=
                      Printf.sprintf "dataset %S has no schema.table name; skipped" name
                      :: !warnings
                  end;
                  None
              | None -> None)
          | None -> dataset
        in
        match (str "fieldPath" j, dataset) with
        | Some fp, Some (schema, table) -> (
            match field_name fp with
            | Some column ->
                cands :=
                  {
                    c_schema = schema;
                    c_table = table;
                    c_column = column;
                    labels = datahub_labels j;
                  }
                  :: !cands
            | None -> ())
        | _ ->
            List.iter
              (fun (k, v) ->
                match (k, v) with
                | "value", `String s when String.length s > 0 && s.[0] = '{' -> (
                    match Yojson.Safe.from_string s with
                    | inner -> walk dataset inner
                    | exception Yojson.Json_error _ -> ())
                | _ -> walk dataset v)
              kvs)
    | _ -> ()
  in
  walk None j;
  finish cfg Datahub ~what:"MCE/MCP file or GraphQL dataset JSON with schema fields"
    (List.rev !cands) !warnings

(* ------------------------------------------------------------ Unity Catalog *)

let tag_labels (j : Yojson.Safe.t option) =
  match j with
  | Some (`Assoc kvs) ->
      List.concat_map
        (fun (k, v) ->
          match v with
          | `String s when String.trim s <> "" -> [ k; k ^ "=" ^ s ]
          | `Null | `String _ -> [ k ]
          | v -> meta_value k v)
        kvs
  | Some (`List l) ->
      List.concat_map
        (fun t ->
          match t with
          | `String s -> [ s ]
          | `Assoc _ -> (
              let k = first_some [ str "key" t; str "tag_name" t; str "name" t ] in
              let v = first_some [ str "value" t; str "tag_value" t ] in
              match (k, v) with
              | Some k, Some v -> [ k; k ^ "=" ^ v ]
              | Some k, None -> [ k ]
              | None, _ -> [])
          | _ -> [])
        l
  | _ -> []

let unity cfg (j : Yojson.Safe.t) =
  let cands = ref [] and warnings = ref [] in
  let add_row (r : Yojson.Safe.t) =
    match (str "schema_name" r, str "table_name" r, str "column_name" r) with
    | Some s, Some t, Some c ->
        let labels =
          match (str "tag_name" r, str "tag_value" r) with
          | Some k, Some v -> [ Tag k; Tag (k ^ "=" ^ v) ]
          | Some k, None -> [ Tag k ]
          | None, _ -> []
        in
        cands := { c_schema = s; c_table = t; c_column = c; labels } :: !cands
    | _ ->
        warnings :=
          "column_tags row without schema_name/table_name/column_name; skipped"
          :: !warnings
  in
  let add_table (t : Yojson.Safe.t) =
    match (str "schema_name" t, str "name" t) with
    | Some s, Some tb ->
        List.iter
          (fun col ->
            match str "name" col with
            | Some c ->
                let labels = List.map (fun l -> Tag l) (tag_labels (field "tags" col)) in
                cands := { c_schema = s; c_table = tb; c_column = c; labels } :: !cands
            | None -> ())
          (list "columns" t)
    | _ -> warnings := "table without schema_name/name; skipped" :: !warnings
  in
  let is_row r = str "column_name" r <> None in
  let is_table t = field "columns" t <> None in
  (match j with
  | `List l ->
      List.iter
        (fun x -> if is_row x then add_row x else if is_table x then add_table x)
        l
  | `Assoc _ -> (
      match
        ( field "result" j,
          Option.bind (field "manifest" j) (fun m ->
              Option.bind (field "schema" m) (fun s -> field "columns" s)) )
      with
      | Some res, Some (`List cols) ->
          let names = List.map (fun c -> Option.value (str "name" c) ~default:"") cols in
          List.iter
            (function
              | `List vals when List.length vals = List.length names ->
                  add_row (`Assoc (List.combine names vals))
              | _ -> warnings := "malformed data_array row; skipped" :: !warnings)
            (list "data_array" res)
      | _ ->
          if is_table j then add_table j
          else
            List.iter
              (fun x -> if is_row x then add_row x else if is_table x then add_table x)
              (list "column_tags" j @ list "rows" j @ list "tables" j))
  | _ -> ());
  finish cfg Unity ~what:"information_schema.column_tags rows or table JSON with columns"
    (List.rev !cands) !warnings

(* ------------------------------------------------------------ Atlan *)

let atlan cfg (j : Yojson.Safe.t) =
  let cands = ref [] and warnings = ref [] in
  let entities =
    match j with
    | `List l -> l
    | `Assoc _ -> (
        match (field "entities" j, field "entity" j, field "assets" j) with
        | Some (`List l), _, _ -> l
        | _, Some e, _ -> [ e ]
        | _, _, Some (`List l) -> l
        | _ -> [])
    | _ -> []
  in
  List.iter
    (fun e ->
      let attrs = Option.value (field "attributes" e) ~default:`Null in
      let type_name = Option.value (str "typeName" e) ~default:"Column" in
      if type_name = "Column" then begin
        let qn_parts =
          match str "qualifiedName" attrs with
          | Some q -> List.rev (String.split_on_char '/' q)
          | None -> []
        in
        let column =
          first_some
            [ str "name" attrs; (match qn_parts with c :: _ -> Some c | [] -> None) ]
        in
        let table =
          first_some
            [
              str "tableName" attrs;
              str "viewName" attrs;
              str "materialisedViewName" attrs;
              (match qn_parts with _ :: t :: _ -> Some t | _ -> None);
            ]
        in
        let schema =
          first_some
            [
              str "schemaName" attrs;
              (match qn_parts with _ :: _ :: s :: _ -> Some s | _ -> None);
            ]
        in
        match (schema, table, column) with
        | Some s, Some t, Some c ->
            let tag_objs = list "classifications" e @ list "atlanTags" e in
            let tags =
              List.concat_map
                (fun t ->
                  match t with
                  | `String s -> [ s ]
                  | _ ->
                      List.filter_map Fun.id
                        [
                          str "typeName" t;
                          str "displayName" t;
                          str "tagName" t;
                          str "name" t;
                        ])
                tag_objs
              @ string_list (field "classificationNames" e)
              @ string_list (field "atlanTagNames" attrs)
            in
            let terms =
              List.concat_map
                (fun m ->
                  match m with
                  | `String s -> [ s ]
                  | _ -> List.filter_map Fun.id [ str "displayText" m; str "name" m ])
                (list "meanings" e @ list "meanings" attrs @ list "assignedTerms" attrs)
              @ string_list (field "meaningNames" e)
            in
            cands :=
              {
                c_schema = s;
                c_table = t;
                c_column = c;
                labels = List.map (fun x -> Tag x) tags @ List.map (fun x -> Term x) terms;
              }
              :: !cands
        | _ ->
            warnings :=
              Printf.sprintf "column asset %s has no schema/table; skipped"
                (Option.value (str "guid" e) ~default:"?")
              :: !warnings
      end)
    entities;
  finish cfg Atlan ~what:"asset search JSON with Column entities" (List.rev !cands)
    !warnings

(* ------------------------------------------------------------ Collibra *)

let classification_attribute name =
  let toks = Pii.Matcher.tokens name in
  List.exists
    (fun t ->
      List.mem t
        [
          "classification";
          "classifications";
          "sensitivity";
          "privacy";
          "confidentiality";
          "personal";
          "pii";
          "security";
          "sensitive";
          "personally";
          "identifiable";
          "confidential";
          "gdpr";
          "phi";
          "pci";
        ])
    toks

let collibra cfg (j : Yojson.Safe.t) =
  let cands = ref [] and warnings = ref [] in
  let assets =
    match j with
    | `List l -> l
    | `Assoc _ -> (
        match (field "results" j, field "assets" j) with
        | Some (`List l), _ | _, Some (`List l) -> l
        | _ -> [])
    | _ -> []
  in
  List.iter
    (fun a ->
      let type_name =
        match field "type" a with
        | Some (`String s) -> s
        | Some t -> Option.value (str "name" t) ~default:""
        | None -> ""
      in
      if type_name = "" || List.mem "column" (Pii.Matcher.tokens type_name) then begin
        let full = first_some [ str "fullName" a; str "name" a ] in
        let parts =
          match full with
          | Some f when String.contains f '>' -> List.rev (String.split_on_char '>' f)
          | Some f -> List.rev (String.split_on_char '.' f)
          | None -> []
        in
        match parts with
        | c :: t :: s :: _ when c <> "" && t <> "" && s <> "" ->
            let attr_labels name (v : Yojson.Safe.t) =
              if not (classification_attribute name) then []
              else
                match v with
                | `Bool true -> [ name ]
                | `String s when truthy_string s -> (
                    match String.lowercase_ascii s with
                    | "true" | "yes" -> [ name ]
                    | _ -> [ s ])
                | `List l ->
                    List.filter_map
                      (function
                        | `String s when truthy_string s -> Some s
                        | `Assoc _ as o -> first_some [ str "name" o; str "value" o ]
                        | _ -> None)
                      l
                | _ -> []
            in
            let attrs =
              match field "attributes" a with
              | Some (`Assoc kvs) -> List.concat_map (fun (k, v) -> attr_labels k v) kvs
              | Some (`List l) ->
                  List.concat_map
                    (fun at ->
                      let name =
                        match field "type" at with
                        | Some (`String s) -> s
                        | Some t -> Option.value (str "name" t) ~default:""
                        | None -> ""
                      in
                      attr_labels name (Option.value (field "value" at) ~default:`Null))
                    l
              | _ -> []
            in
            let tags =
              List.filter_map
                (function
                  | `String s -> Some s | `Assoc _ as o -> str "name" o | _ -> None)
                (list "tags" a)
            in
            let matches =
              List.filter_map
                (fun m ->
                  let status = Option.value (str "status" m) ~default:"ACCEPTED" in
                  if String.uppercase_ascii status = "REJECTED" then None
                  else
                    first_some
                      [
                        Option.bind (field "classification" m) (str "name"); str "name" m;
                      ])
                (list "classificationMatches" a @ list "dataClassifications" a)
            in
            let terms =
              List.filter_map
                (fun r ->
                  match field "target" r with
                  | Some tgt ->
                      let ttype =
                        match field "type" tgt with
                        | Some (`String s) -> s
                        | Some t -> Option.value (str "name" t) ~default:""
                        | None -> ""
                      in
                      if List.mem "term" (Pii.Matcher.tokens ttype) then str "name" tgt
                      else None
                  | None -> None)
                (list "relations" a)
            in
            cands :=
              {
                c_schema = s;
                c_table = t;
                c_column = c;
                labels =
                  List.map (fun x -> Tag x) (attrs @ tags @ matches)
                  @ List.map (fun x -> Term x) terms;
              }
              :: !cands
        | _ ->
            warnings :=
              Printf.sprintf
                "column asset %s has no schema>table>column full name; skipped"
                (Option.value full ~default:"?")
              :: !warnings
      end)
    assets;
  finish cfg Collibra ~what:"asset export with Column assets" (List.rev !cands) !warnings

(* ------------------------------------------------------------ OpenMetadata *)

(* Splits an OpenMetadata fully qualified name on dots, honouring the double quotes
   OpenMetadata puts around name parts that contain a dot ("svc.db."my.schema".t"). *)
let split_fqn s =
  let parts = ref [] and buf = Buffer.create 16 and quoted = ref false in
  String.iter
    (fun c ->
      match c with
      | '"' -> quoted := not !quoted
      | '.' when not !quoted ->
          parts := Buffer.contents buf :: !parts;
          Buffer.clear buf
      | c -> Buffer.add_char buf c)
    s;
  List.rev (Buffer.contents buf :: !parts)

(* Tag labels on an OpenMetadata column: [source] "Glossary" is a glossary term, anything
   else (normally "Classification") a tag. The full tagFQN is matched, so the
   classification name counts ("PII.Sensitive", "PersonalData.Personal") and so does a
   glossary parent term. *)
let openmetadata_labels (col : Yojson.Safe.t) =
  List.filter_map
    (fun t ->
      match first_some [ str "tagFQN" t; str "name" t ] with
      | None -> None
      | Some fqn -> (
          match str "source" t with
          | Some "Glossary" -> Some (Term fqn)
          | _ -> Some (Tag fqn)))
    (list "tags" col)

(* A STRUCT/MAP/ARRAY column's nested [children] are not separately addressable in SQL:
   their labels apply to the top-level column, which exposes them. *)
let rec openmetadata_all_labels (col : Yojson.Safe.t) =
  openmetadata_labels col @ List.concat_map openmetadata_all_labels (list "children" col)

let openmetadata_table_name (t : Yojson.Safe.t) =
  let fqn_parts =
    match str "fullyQualifiedName" t with Some f -> List.rev (split_fqn f) | None -> []
  in
  let table =
    first_some [ str "name" t; (match fqn_parts with x :: _ -> Some x | [] -> None) ]
  in
  let schema =
    first_some
      [
        Option.bind (field "databaseSchema" t) (str "name");
        (match fqn_parts with _ :: s :: _ -> Some s | _ -> None);
      ]
  in
  (schema, table)

let openmetadata cfg (j : Yojson.Safe.t) =
  let cands = ref [] and warnings = ref [] in
  let tables =
    match j with
    | `List l -> l
    | `Assoc _ when field "columns" j <> None -> [ j ]
    | `Assoc _ -> list "data" j
    | _ -> []
  in
  List.iter
    (fun t ->
      match openmetadata_table_name t with
      | Some s, Some tb ->
          List.iter
            (fun col ->
              match str "name" col with
              | Some c ->
                  cands :=
                    {
                      c_schema = s;
                      c_table = tb;
                      c_column = c;
                      labels = openmetadata_all_labels col;
                    }
                    :: !cands
              | None -> ())
            (list "columns" t)
      | _ ->
          if field "columns" t <> None then
            warnings :=
              Printf.sprintf "table %s has no schema/name; skipped"
                (Option.value (str "id" t) ~default:"?")
              :: !warnings)
    tables;
  finish cfg Openmetadata ~what:"table JSON with columns, a list, or {\"data\": [...]}"
    (List.rev !cands) !warnings

(* ------------------------------------------------------------ entry points *)

let import ?(config = Pii.Matcher.default) source j =
  match source with
  | Dbt -> dbt config j
  | Datahub -> datahub config j
  | Unity -> unity config j
  | Atlan -> atlan config j
  | Collibra -> collibra config j
  | Openmetadata -> openmetadata config j

let import_file ?config source file =
  match In_channel.with_open_bin file In_channel.input_all with
  | exception Sys_error e -> Error ("cannot read " ^ e)
  | s -> (
      match Yojson.Safe.from_string ~fname:file s with
      | exception Yojson.Json_error e ->
          Error (Printf.sprintf "%s: invalid JSON: %s" file e)
      | j -> Result.map_error (fun e -> file ^ ": " ^ e) (import ?config source j))
