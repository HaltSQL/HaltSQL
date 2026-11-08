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

let is_lower c = c >= 'a' && c <= 'z'
let is_upper c = c >= 'A' && c <= 'Z'
let is_alpha c = is_lower c || is_upper c
let is_digit c = c >= '0' && c <= '9'
let is_alnum c = is_alpha c || is_digit c

let tokens s =
  let n = String.length s in
  let out = ref [] and cur = Buffer.create 16 in
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
      (if i > 0 && Buffer.length cur > 0 then
         let p = s.[i - 1] in
         if
           (is_alpha p && is_digit c && Buffer.length cur >= 2)
           || (is_digit p && is_alpha c)
         then flush ()
         else if is_upper c then
           if is_lower p then flush ()
           else if is_upper p && i + 1 < n && is_lower s.[i + 1] then flush ());
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
