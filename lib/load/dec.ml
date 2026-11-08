(* Decoding combinators shared by the document loaders; see dec.mli for the
   contract. Errors are kept newest-first and reversed once by [errors]. *)

open Haltsql_core

type json = Yojson.Safe.t

type ctx = {
  file : string option;
  positions : Docpos.positions;
  mutable errors : Load_error.t list; (* reversed *)
}

let create ?file ?positions () =
  let positions = match positions with Some p -> p | None -> Hashtbl.create 1 in
  { file; positions; errors = [] }

let rec find_pos ctx p =
  match Hashtbl.find_opt ctx.positions (Lpath.to_string p) with
  | Some pos -> Some pos
  | None -> ( match Lpath.parent p with Some q -> find_pos ctx q | None -> None)

let error ctx path msg =
  let line, column =
    match find_pos ctx path with
    | Some (p : Docpos.pos) -> (Some p.line, Some p.column)
    | None -> (None, None)
  in
  ctx.errors <-
    Load_error.make ?file:ctx.file ?line ?column ~path:(Lpath.to_string path) msg
    :: ctx.errors

(* For problems that do not come from the document (e.g. environment
   variable overrides): file but no line/column. *)
let error_unlocated ctx path msg =
  ctx.errors <-
    Load_error.make ?file:ctx.file ~path:(Lpath.to_string path) msg :: ctx.errors

let add_errors ctx errs = ctx.errors <- List.rev_append errs ctx.errors
let errors ctx = List.rev ctx.errors
let has_errors ctx = ctx.errors <> []

let type_name : json -> string = function
  | `Null -> "null"
  | `Bool _ -> "a boolean"
  | `Int _ | `Intlit _ -> "an integer"
  | `Float _ -> "a number"
  | `String _ -> "a string"
  | `Assoc _ -> "a mapping"
  | `List _ -> "a list"

let type_error ctx path expected (j : json) =
  error ctx path (Printf.sprintf "expected %s, found %s" expected (type_name j))

(* Levenshtein distance, for "did you mean" hints on unknown keys. Two rows
   of [String.length b + 1] ints: memory is linear in the (short) allowed key,
   not quadratic, whatever the length of the key found in the document. *)
let distance a b =
  let la = String.length a and lb = String.length b in
  let prev = Array.init (lb + 1) Fun.id and cur = Array.make (lb + 1) 0 in
  for i = 1 to la do
    cur.(0) <- i;
    for j = 1 to lb do
      let cost = if Char.equal a.[i - 1] b.[j - 1] then 0 else 1 in
      cur.(j) <- min (min (prev.(j) + 1) (cur.(j - 1) + 1)) (prev.(j - 1) + cost)
    done;
    Array.blit cur 0 prev 0 (lb + 1)
  done;
  prev.(lb)

(* Keys longer than this get no "did you mean" hint: no allowed key is
   anywhere near that long, and it bounds the work an adversarial document
   (thousands of huge unknown keys) can cause. *)
let max_suggest_len = 256

let unknown_key_msg k allowed =
  let best =
    if String.length k > max_suggest_len then None
    else
      let lk = String.lowercase_ascii k in
      List.fold_left
        (fun acc a ->
          let dd = distance lk a in
          match acc with Some (_, d0) when d0 <= dd -> acc | _ -> Some (a, dd))
        None allowed
  in
  match best with
  | Some (a, d) when d <= max 1 (String.length a / 3) ->
      Printf.sprintf "unknown key %S (did you mean %S?)" k a
  | _ -> Printf.sprintf "unknown key %S (allowed: %s)" k (String.concat ", " allowed)

(* Expect a mapping whose keys are all in [keys]. Unknown keys are errors. *)
let obj ctx path ~keys (j : json) : (string * json) list option =
  match j with
  | `Assoc kvs ->
      List.iter
        (fun (k, _) ->
          if not (List.mem k keys) then
            error ctx (Lpath.key path k) (unknown_key_msg k keys))
        kvs;
      Some kvs
  | j ->
      type_error ctx path "a mapping" j;
      None

(* Expect a mapping with arbitrary keys. *)
let map ctx path (j : json) : (string * json) list option =
  match j with
  | `Assoc kvs -> Some kvs
  | j ->
      type_error ctx path "a mapping" j;
      None

let field kvs k =
  match List.assoc_opt k kvs with Some `Null | None -> None | Some v -> Some v

let string ctx path : json -> string option = function
  | `String s -> Some s
  | j ->
      type_error ctx path "a string" j;
      None

let non_empty_string ctx path j =
  match string ctx path j with
  | Some "" ->
      error ctx path "must not be empty";
      None
  | x -> x

let bool ctx path : json -> bool option = function
  | `Bool b -> Some b
  | j ->
      type_error ctx path "a boolean (true or false)" j;
      None

let int ctx path ?min ?max (j : json) : int option =
  match j with
  | `Int i ->
      let bad =
        (match min with Some m when i < m -> true | _ -> false)
        || match max with Some m when i > m -> true | _ -> false
      in
      if bad then begin
        error ctx path
          (match (min, max) with
          | Some a, Some b -> Printf.sprintf "must be between %d and %d (got %d)" a b i
          | Some a, None -> Printf.sprintf "must be at least %d (got %d)" a i
          | None, Some b -> Printf.sprintf "must be at most %d (got %d)" b i
          | None, None -> "out of range");
        None
      end
      else Some i
  | `Intlit s ->
      error ctx path ("integer out of range: " ^ s);
      None
  | j ->
      type_error ctx path "an integer" j;
      None

let list ctx path (j : json) : json list option =
  match j with
  | `List l -> Some l
  | j ->
      type_error ctx path "a list" j;
      None

(* Decode every element of a list; [None] if the list itself is malformed.
   Elements that fail are dropped (their errors are recorded). *)
let list_of ctx path f j =
  match list ctx path j with
  | None -> None
  | Some l ->
      Some (List.filter_map Fun.id (List.mapi (fun i x -> f (Lpath.idx path i) x) l))

let string_list ctx path j = list_of ctx path (fun p x -> string ctx p x) j

(* Optional field with a decoder. *)
let opt kvs path k f =
  match field kvs k with None -> None | Some v -> f (Lpath.key path k) v

(* Required field with a decoder. *)
let req ctx kvs path k f =
  match field kvs k with
  | None ->
      error ctx (Lpath.key path k) "required";
      None
  | Some v -> f (Lpath.key path k) v

let enum ctx path ~values (j : json) =
  match j with
  | `String s when List.mem_assoc s values -> Some (List.assoc s values)
  | `String s ->
      error ctx path
        (Printf.sprintf "invalid value %S (expected one of: %s)" s
           (String.concat ", " (List.map fst values)));
      None
  | j ->
      type_error ctx path ("one of: " ^ String.concat ", " (List.map fst values)) j;
      None

(* Header keys common to every document kind. *)
let header ctx ?(required = true) kvs path ~kind =
  (match field kvs "apiVersion" with
  | None -> if required then error ctx (Lpath.key path "apiVersion") "required"
  | Some (`String "haltsql.dev/v1") -> ()
  | Some (`String s) ->
      error ctx (Lpath.key path "apiVersion")
        (Printf.sprintf "unsupported apiVersion %S (expected \"haltsql.dev/v1\")" s)
  | Some j -> type_error ctx (Lpath.key path "apiVersion") "a string" j);
  match field kvs "kind" with
  | None -> if required then error ctx (Lpath.key path "kind") "required"
  | Some (`String k) when k = kind -> ()
  | Some (`String k) ->
      error ctx (Lpath.key path "kind")
        (Printf.sprintf "expected kind %S, found %S" kind k)
  | Some j -> type_error ctx (Lpath.key path "kind") "a string" j

let dedup l =
  let seen = Hashtbl.create 16 in
  List.filter
    (fun x ->
      if Hashtbl.mem seen x then false
      else begin
        Hashtbl.add seen x ();
        true
      end)
    l

(* Lexical path helpers. *)
let normalize_path p =
  let abs = String.length p > 0 && p.[0] = '/' in
  let parts = String.split_on_char '/' p in
  let stack =
    List.fold_left
      (fun acc seg ->
        match seg with
        | "" | "." -> acc
        | ".." -> (
            match acc with
            | x :: rest when x <> ".." -> rest
            | _ -> if abs then acc else ".." :: acc)
        | s -> s :: acc)
      [] parts
  in
  let body = String.concat "/" (List.rev stack) in
  if abs then "/" ^ body else if body = "" then "." else body

let absolute ?base_dir p =
  let base = match base_dir with Some d -> d | None -> Sys.getcwd () in
  let base =
    if Filename.is_relative base then Filename.concat (Sys.getcwd ()) base else base
  in
  normalize_path (if Filename.is_relative p then Filename.concat base p else p)

let base_dir_of ?base_dir file =
  match base_dir with
  | Some d -> Some d
  | None -> ( match file with Some f -> Some (Filename.dirname f) | None -> None)
