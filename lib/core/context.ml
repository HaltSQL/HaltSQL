(* Per-request caller context; see context.mli. *)

type value =
  | One of string  (** a single value, e.g. ["acme"] or ["42"] *)
  | Many of string list
      (** a set of allowed values, e.g. a parent org and its child orgs *)

type t = (string * value) list

let empty : t = []
let make (kvs : (string * value) list) : t = kvs
let find (t : t) key = List.assoc_opt key t

let value_to_json = function
  | One s -> `String s
  | Many l -> `List (List.map (fun s -> `String s) l)

let to_json (t : t) : Yojson.Safe.t =
  `Assoc (List.map (fun (k, v) -> (k, value_to_json v)) t)

let of_json (j : Yojson.Safe.t) : (t, string) result =
  let scalar = function
    | `String s -> Ok s
    | `Int i -> Ok (string_of_int i)
    | `Intlit s -> Ok s
    | _ -> Error "context values must be strings, integers, or arrays of those"
  in
  match j with
  | `Assoc kvs ->
      List.fold_left
        (fun acc (k, v) ->
          match acc with
          | Error _ as e -> e
          | Ok acc -> (
              match v with
              | `List items -> (
                  let rec all = function
                    | [] -> Ok []
                    | x :: xs -> (
                        match (scalar x, all xs) with
                        | Ok s, Ok ss -> Ok (s :: ss)
                        | (Error _ as e), _ | _, (Error _ as e) -> e)
                  in
                  match all items with
                  | Ok ss -> Ok ((k, Many ss) :: acc)
                  | Error e -> Error (k ^ ": " ^ e))
              | v -> (
                  match scalar v with
                  | Ok s -> Ok ((k, One s) :: acc)
                  | Error e -> Error (k ^ ": " ^ e))))
        (Ok []) kvs
      |> Result.map List.rev
  | _ -> Error "context must be a JSON object"
