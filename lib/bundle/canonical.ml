let rec normalize_at path (j : Yojson.Safe.t) : (Yojson.Safe.t, string) result =
  match j with
  | `Null | `Bool _ | `String _ | `Int _ -> Ok j
  | `Float _ -> Error (Printf.sprintf "%s: floating-point numbers are not allowed" path)
  | `Intlit _ -> Error (Printf.sprintf "%s: integer out of range" path)
  | `List l ->
      let rec go i acc = function
        | [] -> Ok (`List (List.rev acc))
        | x :: xs -> (
            match normalize_at (Printf.sprintf "%s[%d]" path i) x with
            | Ok y -> go (i + 1) (y :: acc) xs
            | Error _ as e -> e)
      in
      go 0 [] l
  | `Assoc kvs -> (
      let sorted = List.stable_sort (fun (a, _) (b, _) -> String.compare a b) kvs in
      let rec dup = function
        | (a, _) :: ((b, _) :: _ as rest) -> if String.equal a b then Some a else dup rest
        | _ -> None
      in
      match dup sorted with
      | Some k -> Error (Printf.sprintf "%s: duplicate key %S" path k)
      | None ->
          let rec go acc = function
            | [] -> Ok (`Assoc (List.rev acc))
            | (k, v) :: xs -> (
                match normalize_at (path ^ "." ^ k) v with
                | Ok y -> go ((k, y) :: acc) xs
                | Error _ as e -> e)
          in
          go [] sorted)

let normalize j = normalize_at "$" j

let to_string j =
  match normalize j with
  | Ok n -> Ok (Yojson.Safe.to_string ~std:true n)
  | Error _ as e -> e

let of_string s =
  let body =
    let n = String.length s in
    if n > 0 && s.[n - 1] = '\n' then String.sub s 0 (n - 1) else s
  in
  match Yojson.Safe.from_string body with
  | exception Yojson.Json_error e -> Error ("invalid JSON: " ^ e)
  | exception Stack_overflow -> Error "invalid JSON: nesting too deep"
  | j -> (
      match to_string j with
      | Error _ as e -> e
      | Ok c ->
          if String.equal c body then Ok j else Error "document is not in canonical form")
