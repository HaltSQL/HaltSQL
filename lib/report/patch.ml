(* Structural edits of a policy document; see patch.mli. *)

open Haltsql_core
module Ident = Haltsql_load.Ident
module Docload = Haltsql_load.Docload

type outcome = { applied : string list; skipped : (string * string) list }

let resolve_key (p : Policy.t) k =
  match Ident.parse_parts k with
  | Ok [ n ] -> Some ((match p.search_path with s :: _ -> s | [] -> "public"), n)
  | Ok [ s; n ] -> Some (s, n)
  | Ok _ | Error _ -> None

let same_ident written name =
  match Ident.parse_one written with Ok n -> String.equal n name | Error _ -> false

let update_assoc kvs k f =
  if List.mem_assoc k kvs then
    List.map (fun (k', v) -> if k' = k then (k', f (Some v)) else (k', v)) kvs
  else kvs @ [ (k, f None) ]

exception Skip of string

let skip fmt = Printf.ksprintf (fun s -> raise (Skip s)) fmt

let doc_name (doc : Yojson.Safe.t) =
  match doc with
  | `Assoc kv -> (
      match List.assoc_opt "metadata" kv with
      | Some (`Assoc m) -> (
          match List.assoc_opt "name" m with Some (`String n) -> Some n | _ -> None)
      | _ -> None)
  | _ -> None

let apply_one (p : Policy.t) (doc : Yojson.Safe.t) (s : Suggest.suggestion) =
  let kv =
    match doc with `Assoc kv -> kv | _ -> skip "the policy document is not an object"
  in
  let tables () =
    match List.assoc_opt "tables" kv with
    | Some (`Assoc t) -> t
    | None -> []
    | Some _ -> skip "tables is not a map"
  in
  let find_table schema table =
    List.find_opt (fun (k, _) -> resolve_key p k = Some (schema, table)) (tables ())
  in
  match s.change with
  | Suggest.Add_column { schema; table; column } -> (
      match find_table schema table with
      | None ->
          skip "table %s is not in the document" (Ident.render_qualified schema table)
      | Some (key, `Assoc tkv) -> (
          match List.assoc_opt "columns" tkv with
          | Some (`List cols) ->
              if
                List.exists
                  (function `String w -> same_ident w column | _ -> false)
                  cols
              then skip "the column is already listed"
              else
                let tkv' =
                  update_assoc tkv "columns" (fun _ ->
                      `List (cols @ [ `String (Ident.render column) ]))
                in
                let t' =
                  List.map
                    (fun (k, v) -> if k = key then (k, `Assoc tkv') else (k, v))
                    (tables ())
                in
                `Assoc (update_assoc kv "tables" (fun _ -> `Assoc t'))
          | Some (`String "*") -> skip "the table already allows every column"
          | Some _ | None -> skip "tables.%s.columns is not a list" key)
      | Some (key, _) -> skip "tables.%s is not a map" key)
  | Suggest.Add_function f ->
      if String.lowercase_ascii f <> f then
        skip "mixed-case function name; add it by hand";
      let fkv =
        match List.assoc_opt "functions" kv with
        | Some (`Assoc f) -> f
        | None -> []
        | Some _ -> skip "functions is not a map"
      in
      let allow =
        match List.assoc_opt "allow" fkv with
        | Some (`List l) -> l
        | None -> []
        | Some _ -> skip "functions.allow is not a list"
      in
      if List.mem (`String f) allow then skip "already in functions.allow";
      let fkv' = update_assoc fkv "allow" (fun _ -> `List (allow @ [ `String f ])) in
      `Assoc (update_assoc kv "functions" (fun _ -> `Assoc fkv'))
  | Suggest.Set_limit_max { current = _; proposed } -> (
      match List.assoc_opt "require_limit" kv with
      | Some (`Assoc rl) ->
          (match List.assoc_opt "max" rl with
          | Some (`Int m) when m >= proposed -> skip "require_limit.max is already %d" m
          | _ -> ());
          `Assoc
            (update_assoc kv "require_limit" (fun _ ->
                 `Assoc (update_assoc rl "max" (fun _ -> `Int proposed))))
      | Some _ | None -> skip "the document has no require_limit map")
  | Suggest.Add_table { schema; table; columns; tenant_columns } ->
      if columns = [] then skip "no columns";
      (match find_table schema table with
      | Some _ -> skip "the table is already in the document"
      | None -> ());
      let tenancy =
        match (tenant_columns, p.tenancy.keys) with
        | [], _ -> []
        | [ (c, _) ], [ _ ] -> [ ("tenant_column", `String (Ident.render c)) ]
        | tc, _ ->
            [
              ( "tenant_columns",
                `Assoc (List.map (fun (c, k) -> (Ident.render c, `String k)) tc) );
            ]
      in
      let entry =
        `Assoc
          (("columns", `List (List.map (fun c -> `String (Ident.render c)) columns))
          :: tenancy)
      in
      let t' = tables () @ [ (Ident.render_qualified schema table, entry) ] in
      `Assoc (update_assoc kv "tables" (fun _ -> `Assoc t'))

let apply (p : Policy.t) doc (suggestions : Suggest.suggestion list) =
  let name = doc_name doc in
  List.fold_left
    (fun (doc, o) (s : Suggest.suggestion) ->
      if Some s.policy <> name then
        ( doc,
          {
            o with
            skipped = o.skipped @ [ (s.id, "suggestion is for policy " ^ s.policy) ];
          } )
      else if not s.applicable then
        ( doc,
          {
            o with
            skipped =
              o.skipped @ [ (s.id, "not applicable automatically (see its notes)") ];
          } )
      else
        match apply_one p doc s with
        | doc' -> (doc', { o with applied = o.applied @ [ s.id ] })
        | exception Skip why -> (doc, { o with skipped = o.skipped @ [ (s.id, why) ] }))
    (doc, { applied = []; skipped = [] })
    suggestions

let validate ?file ~base_dir doc = Haltsql_load.Policy_load.of_json ?file ~base_dir doc

(* ---- paths ---- *)

let split_abs p =
  List.fold_left
    (fun acc seg ->
      match seg with
      | "" | "." -> acc
      | ".." -> ( match acc with _ :: rest -> rest | [] -> [])
      | s -> s :: acc)
    [] (String.split_on_char '/' p)
  |> List.rev

let relative_path ~from_dir target =
  let rec drop a b =
    match (a, b) with x :: a', y :: b' when x = y -> drop a' b' | _ -> (a, b)
  in
  let up, down = drop (split_abs from_dir) (split_abs target) in
  match List.map (fun _ -> "..") up @ down with [] -> "." | l -> String.concat "/" l

let rebase_catalog ~from_dir ~to_dir (doc : Yojson.Safe.t) =
  match doc with
  | `Assoc kv -> (
      match List.assoc_opt "catalog" kv with
      | Some (`String p)
        when Filename.is_relative p && split_abs from_dir <> split_abs to_dir ->
          let target = "/" ^ String.concat "/" (split_abs (Filename.concat from_dir p)) in
          `Assoc
            (List.map
               (fun (k, v) ->
                 if k = "catalog" then (k, `String (relative_path ~from_dir:to_dir target))
                 else (k, v))
               kv)
      | _ -> doc)
  | j -> j

let render fmt ~applied doc =
  let body = Docload.to_string fmt doc in
  match fmt with
  | Docload.Json -> body
  | Docload.Yaml ->
      let printable =
        String.map (fun c -> if Char.code c < 0x20 || Char.code c = 0x7f then '?' else c)
      in
      let ids =
        match applied with [] -> "nothing" | l -> printable (String.concat ", " l)
      in
      Printf.sprintf
        "# Patched by `haltsql report --apply-to`; applied: %s.\n\
         # Comments and formatting of the original file are not preserved: review the \
         diff.\n\
         %s"
        ids body
