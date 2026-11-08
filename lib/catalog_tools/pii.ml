(* PII manifests (see pii.mli). *)

type entry = {
  schema : string;
  table : string;
  column : string;
  classifications : string list;
  sources : string list;
}

type t = entry list

let empty = []
let key e = (e.schema, e.table, e.column)

let add (t : t) e =
  let e =
    {
      e with
      classifications = List.sort_uniq compare e.classifications;
      sources = List.sort_uniq compare e.sources;
    }
  in
  let rec go = function
    | [] -> [ e ]
    | x :: rest when key x = key e ->
        {
          x with
          classifications = List.sort_uniq compare (x.classifications @ e.classifications);
          sources = List.sort_uniq compare (x.sources @ e.sources);
        }
        :: rest
    | x :: rest when compare (key x) (key e) > 0 -> e :: x :: rest
    | x :: rest -> x :: go rest
  in
  go t

let merge ts = List.fold_left (List.fold_left add) empty ts
let lc = String.lowercase_ascii

let find t ~schema ~table ~column =
  let s = lc schema and tb = lc table and c = lc column in
  let hits =
    List.filter (fun e -> lc e.schema = s && lc e.table = tb && lc e.column = c) t
  in
  match hits with
  | [] -> None
  | [ e ] -> Some e
  | e :: rest ->
      (* Case variants of the same column: report them together. *)
      Some
        (List.fold_left
           (fun acc x ->
             {
               acc with
               classifications =
                 List.sort_uniq compare (acc.classifications @ x.classifications);
               sources = List.sort_uniq compare (acc.sources @ x.sources);
             })
           e rest)

let to_json ?(metadata = []) t : Yojson.Safe.t =
  let by_table = Hashtbl.create 16 in
  let order = ref [] in
  List.iter
    (fun e ->
      let k = Snapshot.table_key ~schema:e.schema ~name:e.table in
      if not (Hashtbl.mem by_table k) then begin
        Hashtbl.add by_table k (ref []);
        order := k :: !order
      end;
      let cols = Hashtbl.find by_table k in
      cols :=
        ( e.column,
          `Assoc
            [
              ("classifications", `List (List.map (fun c -> `String c) e.classifications));
              ("source", `String (String.concat ", " e.sources));
            ] )
        :: !cols)
    t;
  let tables =
    List.rev_map
      (fun k -> (k, `Assoc [ ("columns", `Assoc (List.rev !(Hashtbl.find by_table k))) ]))
      !order
  in
  `Assoc
    ((if metadata = [] then [] else [ ("metadata", `Assoc metadata) ])
    @ [ ("tables", `Assoc tables) ])

let ( let* ) = Result.bind

let fold_result f acc l =
  List.fold_left
    (fun acc x ->
      let* acc = acc in
      f acc x)
    (Ok acc) l

let of_json (j : Yojson.Safe.t) =
  let strings what = function
    | `List l ->
        fold_result
          (fun acc -> function
            | `String s when s <> "" -> Ok (s :: acc)
            | _ -> Error (what ^ ": expected a list of non-empty strings"))
          [] l
        |> Result.map List.rev
    | _ -> Error (what ^ ": expected a list of strings")
  in
  match j with
  | `Assoc top -> (
      let* () =
        fold_result
          (fun () (k, _) ->
            if k = "tables" || k = "metadata" then Ok ()
            else Error (Printf.sprintf "unknown key %S in PII manifest" k))
          () top
      in
      match List.assoc_opt "tables" top with
      | Some (`Assoc tables) ->
          fold_result
            (fun acc (tk, tv) ->
              let* schema, table = Snapshot.parse_table_key tk in
              match tv with
              | `Assoc [ ("columns", `Assoc cols) ] ->
                  fold_result
                    (fun acc (column, cv) ->
                      let path = Printf.sprintf "tables.%s.columns.%s" tk column in
                      if column = "" then Error (path ^ ": empty column name")
                      else
                        match cv with
                        | `Assoc kvs ->
                            let* () =
                              fold_result
                                (fun () (k, _) ->
                                  if k = "classifications" || k = "source" then Ok ()
                                  else Error (Printf.sprintf "%s: unknown key %S" path k))
                                () kvs
                            in
                            let* classifications =
                              match List.assoc_opt "classifications" kvs with
                              | Some v -> strings (path ^ ".classifications") v
                              | None -> Ok []
                            in
                            let* sources =
                              match List.assoc_opt "source" kvs with
                              | Some (`String s) ->
                                  Ok
                                    (String.split_on_char ',' s |> List.map String.trim
                                    |> List.filter (( <> ) ""))
                              | None -> Ok []
                              | Some _ -> Error (path ^ ".source: expected a string")
                            in
                            Ok
                              (add acc
                                 { schema; table; column; classifications; sources })
                        | _ -> Error (path ^ ": expected an object"))
                    acc cols
              | _ ->
                  Error
                    (Printf.sprintf "tables.%s: expected {\"columns\": {...}} only" tk))
            empty tables
      | Some _ -> Error "tables: expected a mapping"
      | None -> Error "PII manifest has no \"tables\" key")
  | _ -> Error "PII manifest must be a JSON object"

let of_file file =
  match Haltsql_load.Docload.of_file file with
  | Error errs ->
      Error (String.concat "\n" (List.map Haltsql_core.Load_error.to_string errs))
  | Ok j -> Result.map_error (fun e -> file ^ ": " ^ e) (of_json j)

module Matcher = struct
  type config = { tags : string list; terms : string list }

  let default_terms =
    [
      "pii";
      "sensitive";
      "confidential";
      "restricted";
      "gdpr";
      "phi";
      "pci";
      "personal";
      "email";
      "phone";
      "ssn";
      "secret";
      "password";
      "passwd";
      "passcode";
      "token";
      "apikey";
      "credential";
      "cvv";
      "cvc";
      "iban";
      "passport";
      "dob";
      "birthdate";
      "tin";
      "taxid";
      "salary";
    ]

  let default = { tags = default_terms; terms = default_terms }
  let is_alpha c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
  let is_digit c = c >= '0' && c <= '9'
  let is_alnum c = is_alpha c || is_digit c
  let is_upper c = c >= 'A' && c <= 'Z'
  let is_lower c = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')

  let tokens s =
    let n = String.length s in
    let out = ref [] in
    let cur = Buffer.create 16 in
    let flush () =
      if Buffer.length cur > 0 then begin
        out := String.lowercase_ascii (Buffer.contents cur) :: !out;
        Buffer.clear cur
      end
    in
    for i = 0 to n - 1 do
      let c = s.[i] in
      if not (is_alnum c) then flush ()
      else begin
        (* camelCase: "personalData" -> personal|Data; "PIIData" -> PII|Data *)
        (if i > 0 && Buffer.length cur > 0 then
           let p = s.[i - 1] in
           if
             (is_alpha p && is_digit c && Buffer.length cur >= 2)
             || (is_digit p && is_alpha c)
           then flush ()
           else if is_upper c then
             if is_lower p then flush ()
             else if is_upper p && i + 1 < n && s.[i + 1] >= 'a' && s.[i + 1] <= 'z' then
               flush ());
        Buffer.add_char cur c
      end
    done;
    flush ();
    List.rev !out

  let rec is_prefix p l =
    match (p, l) with
    | [], _ -> true
    | _, [] -> false
    | x :: p', y :: l' -> String.equal x y && is_prefix p' l'

  let rec occurs p l =
    is_prefix p l || match l with [] -> false | _ :: l' -> occurs p l'

  (* "Personally Identifiable Information" -> "pii". *)
  let acronym = function
    | _ :: _ :: _ as toks ->
        Some (String.concat "" (List.map (fun t -> String.make 1 t.[0]) toks))
    | _ -> None

  let find_match terms label =
    let lt = tokens label in
    let ac = acronym lt in
    List.find_opt
      (fun term ->
        match tokens term with
        | [] -> false
        | [ t ] when String.length t >= 3 && ac = Some t -> true
        | tt -> occurs tt lt)
      terms
end
