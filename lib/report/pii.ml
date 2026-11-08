type lookup = schema:string -> table:string -> column:string -> string option

let none ~schema:_ ~table:_ ~column:_ = None

let union (ls : lookup list) ~schema ~table ~column =
  List.find_map (fun (l : lookup) -> l ~schema ~table ~column) ls

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
  ]

let is_lower c = c >= 'a' && c <= 'z'
let is_upper c = c >= 'A' && c <= 'Z'
let is_digit c = c >= '0' && c <= '9'
let is_alnum c = is_lower c || is_upper c || is_digit c

let tokens s =
  let out = ref [] and cur = Buffer.create 16 in
  let flush () =
    if Buffer.length cur > 0 then begin
      out := String.lowercase_ascii (Buffer.contents cur) :: !out;
      Buffer.clear cur
    end
  in
  String.iteri
    (fun i c ->
      if not (is_alnum c) then flush ()
      else begin
        if is_upper c && i > 0 && (is_lower s.[i - 1] || is_digit s.[i - 1]) then flush ();
        Buffer.add_char cur c
      end)
    s;
  flush ();
  List.rev !out

let rec is_prefix p l =
  match (p, l) with
  | [], _ -> true
  | _, [] -> false
  | x :: p', y :: l' -> String.equal x y && is_prefix p' l'

let rec occurs p l =
  match l with [] -> p = [] | _ :: rest -> is_prefix p l || occurs p rest

let name_heuristic ?(terms = default_terms) () ~schema:_ ~table:_ ~column =
  let toks = tokens column in
  List.find_map
    (fun term ->
      let tt = tokens term in
      if tt <> [] && occurs tt toks then
        Some (Printf.sprintf "column name matches %S" term)
      else None)
    terms
