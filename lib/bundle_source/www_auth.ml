type challenge = { scheme : string; params : (string * string) list }

let is_tchar c =
  (c >= 'a' && c <= 'z')
  || (c >= 'A' && c <= 'Z')
  || (c >= '0' && c <= '9')
  || String.contains "!#$%&'*+-.^_`|~" c

(* token68 adds '/' and '=' *)
let is_t68 c = is_tchar c || c = '/' || c = '='

let parse s =
  let n = String.length s in
  let rec skip_ws i =
    if i < n && (s.[i] = ' ' || s.[i] = '\t') then skip_ws (i + 1) else i
  in
  let rec skip_sep i =
    if i < n && (s.[i] = ' ' || s.[i] = '\t' || s.[i] = ',') then skip_sep (i + 1) else i
  in
  let token i =
    let j = ref i in
    while !j < n && is_tchar s.[!j] do
      incr j
    done;
    (String.sub s i (!j - i), !j)
  in
  let quoted i =
    (* s.[i] = '"' *)
    let b = Buffer.create 32 in
    let rec go j =
      if j >= n then None
      else
        match s.[j] with
        | '"' -> Some (Buffer.contents b, j + 1)
        | '\\' when j + 1 < n ->
            Buffer.add_char b s.[j + 1];
            go (j + 2)
        | c ->
            Buffer.add_char b c;
            go (j + 1)
    in
    go (i + 1)
  in
  (* Parses "name=value" at i; None when what follows is not a parameter (a new
     scheme, or garbage). *)
  let param i =
    let name, j = token i in
    if name = "" then None
    else
      let j = skip_ws j in
      if j < n && s.[j] = '=' then
        let j = skip_ws (j + 1) in
        if j < n && s.[j] = '"' then
          match quoted j with
          | Some (v, k) -> Some ((String.lowercase_ascii name, v), k)
          | None -> None
        else
          let v, k = token j in
          if v = "" then None else Some ((String.lowercase_ascii name, v), k)
      else None
  in
  let rec challenges acc i =
    let i = skip_sep i in
    if i >= n then List.rev acc
    else
      let scheme, j = token i in
      if scheme = "" then List.rev acc
      else
        let rec params ps j =
          let k = skip_sep j in
          if k >= n then (List.rev ps, k)
          else
            match param k with
            | Some (p, k') -> params (p :: ps) k'
            | None -> (List.rev ps, k)
        in
        let j' = skip_ws j in
        (* token68 form (e.g. "Negotiate abc=="): skip it *)
        let ps, k =
          if j' < n && is_t68 s.[j'] && param j' = None && s.[j'] <> ',' then (
            let e = ref j' in
            while !e < n && is_t68 s.[!e] do
              incr e
            done;
            ([], !e))
          else params [] j
        in
        challenges ({ scheme = String.lowercase_ascii scheme; params = ps } :: acc) k
  in
  try challenges [] 0 with _ -> []

let param c name = List.assoc_opt (String.lowercase_ascii name) c.params
