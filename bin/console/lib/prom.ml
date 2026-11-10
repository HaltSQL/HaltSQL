(* A small parser for the Prometheus text exposition format (0.0.4): enough for the
   counter and gauge lines HaltSQL verifiers publish on /metrics. Comments, blank lines
   and lines that do not parse are skipped; histogram and summary series parse like any
   other sample. *)

type sample = { name : string; labels : (string * string) list; value : float }

let is_name_char c =
  match c with 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | ':' -> true | _ -> false

(* Parses a label set starting just after the opening brace; returns the labels and the
   index after the closing brace. Label values unescape backslash, quote and newline. *)
let parse_labels s i =
  let n = String.length s in
  let rec skip_ws i =
    if i < n && (s.[i] = ' ' || s.[i] = '\t') then skip_ws (i + 1) else i
  in
  let rec go acc i =
    let i = skip_ws i in
    if i >= n then None
    else if s.[i] = '}' then Some (List.rev acc, i + 1)
    else if s.[i] = ',' then go acc (i + 1)
    else
      let j = ref i in
      while !j < n && is_name_char s.[!j] do
        incr j
      done;
      let key = String.sub s i (!j - i) in
      let k = skip_ws !j in
      if key = "" || k >= n || s.[k] <> '=' then None
      else
        let k = skip_ws (k + 1) in
        if k >= n || s.[k] <> '"' then None
        else
          let b = Buffer.create 16 in
          let rec value k =
            if k >= n then None
            else
              match s.[k] with
              | '"' -> Some (k + 1)
              | '\\' when k + 1 < n ->
                  (match s.[k + 1] with
                  | 'n' -> Buffer.add_char b '\n'
                  | c -> Buffer.add_char b c);
                  value (k + 2)
              | c ->
                  Buffer.add_char b c;
                  value (k + 1)
          in
          match value (k + 1) with
          | None -> None
          | Some k -> go ((key, Buffer.contents b) :: acc) k
  in
  go [] i

let parse_value s =
  match String.lowercase_ascii s with
  | "nan" -> Some Float.nan
  | "+inf" | "inf" -> Some Float.infinity
  | "-inf" -> Some Float.neg_infinity
  | _ -> float_of_string_opt s

let parse_line line =
  let line = String.trim line in
  if line = "" || line.[0] = '#' then None
  else
    let n = String.length line in
    let j = ref 0 in
    while !j < n && is_name_char line.[!j] do
      incr j
    done;
    let name = String.sub line 0 !j in
    if name = "" then None
    else
      let labels_end =
        if !j < n && line.[!j] = '{' then parse_labels line (!j + 1) else Some ([], !j)
      in
      match labels_end with
      | None -> None
      | Some (labels, k) -> (
          let rest = String.trim (String.sub line k (n - k)) in
          (* value, then an optional timestamp *)
          match String.split_on_char ' ' rest |> List.filter (( <> ) "") with
          | v :: _ -> (
              match parse_value v with
              | Some value -> Some { name; labels; value }
              | None -> None)
          | [] -> None)

let parse text = String.split_on_char '\n' text |> List.filter_map parse_line

(** Samples of [name] whose labels include every pair of [labels]. *)
let select ?(labels = []) samples name =
  List.filter
    (fun s ->
      s.name = name
      && List.for_all (fun (k, v) -> List.assoc_opt k s.labels = Some v) labels)
    samples

(** Sum of the matching samples, or [None] when there are none. *)
let sum ?labels samples name =
  match select ?labels samples name with
  | [] -> None
  | l -> Some (List.fold_left (fun acc s -> acc +. s.value) 0. l)

let label s k = List.assoc_opt k s.labels
