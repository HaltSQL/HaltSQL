(* Recovers the object a reason names from its (rule, message). The message formats are
   those of lib/analyzer (rules.ml, walk.ml); test/report checks them end to end. *)

type t =
  | Column of { table : string; column : string }
  | Column_star of string
  | Function of string
  | Sql_value_function of string
  | Table of { schema : string option; name : string }
  | System_relation of string
  | Limit_value of int
  | Limit_non_constant
  | Unrecognized

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let ends_with ~suffix s =
  let n = String.length s and m = String.length suffix in
  n >= m && String.sub s (n - m) m = suffix

(* [between ~prefix ~suffix s]: the middle part when [s] has both. *)
let between ~prefix ~suffix s =
  if
    starts_with ~prefix s && ends_with ~suffix s
    && String.length s > String.length prefix + String.length suffix
  then
    Some
      (String.sub s (String.length prefix)
         (String.length s - String.length prefix - String.length suffix))
  else None

(* Last occurrence of [sub] in [s]. *)
let rfind ~sub s =
  let n = String.length s and m = String.length sub in
  let rec go i =
    if i < 0 then None else if String.sub s i m = sub then Some i else go (i - 1)
  in
  if m > n then None else go (n - m)

let first_word s =
  match String.index_opt s ' ' with Some i -> String.sub s 0 i | None -> s

let of_reason (r : Record.reason) =
  let m = r.message in
  match r.rule with
  | "columns.denied" -> (
      match between ~prefix:"column " ~suffix:" is not readable under this policy" m with
      | Some mid -> (
          match rfind ~sub:" of " mid with
          | Some i ->
              let column = String.sub mid 0 i in
              let table = String.sub mid (i + 4) (String.length mid - i - 4) in
              if column = "" || table = "" then Unrecognized else Column { table; column }
          | None -> Unrecognized)
      | None -> Unrecognized)
  | "columns.star" -> (
      match
        between ~prefix:"* or a whole-row reference to "
          ~suffix:
            " would read columns that are not readable (or not known to the catalog)"
          m
      with
      | Some t -> Column_star t
      | None -> Unrecognized)
  | "functions.allowlist" -> (
      match
        between ~prefix:"function " ~suffix:" is not in the policy's function allowlist" m
      with
      | Some f -> Function f
      | None -> Unrecognized)
  | "functions.sql_value" -> (
      match between ~prefix:"SQL value function " ~suffix:" is not allowed" m with
      | Some f -> Sql_value_function f
      | None -> Unrecognized)
  | "tables.allowlist" -> (
      match
        between ~prefix:"relation " ~suffix:" is not in the policy's table allowlist" m
      with
      | Some q -> (
          match String.index_opt q '.' with
          | Some i ->
              Table
                {
                  schema = Some (String.sub q 0 i);
                  name = String.sub q (i + 1) (String.length q - i - 1);
                }
          | None -> Table { schema = None; name = q })
      | None ->
          if starts_with ~prefix:"relation " m then
            let rest = String.sub m 9 (String.length m - 9) in
            let name = first_word rest in
            let after =
              String.sub rest (String.length name)
                (String.length rest - String.length name)
            in
            if
              starts_with
                ~prefix:" does not resolve to a policy table through search_path" after
            then Table { schema = None; name }
            else if starts_with ~prefix:" resolves to the system catalog" after then
              System_relation name
            else Unrecognized
          else Unrecognized)
  | "limit.max" -> (
      let all_digits w = w <> "" && String.for_all (fun c -> c >= '0' && c <= '9') w in
      match between ~prefix:"LIMIT " ~suffix:"" m with
      | None -> Unrecognized
      | Some rest ->
          let w = first_word rest in
          if w = "with" then Limit_non_constant
          else if all_digits w && starts_with ~prefix:(w ^ " is not allowed") rest then
            match int_of_string_opt w with
            | Some n -> Limit_value n
            | None -> Limit_value max_int
          else Limit_non_constant)
  | _ -> Unrecognized
