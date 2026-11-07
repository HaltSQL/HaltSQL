open Haltsql_core
open Haltsql_load

let root = "../.."
let examples = Filename.concat root "examples"
let ex p = Filename.concat examples p
let json = Alcotest.testable Yojson.Safe.pp Yojson.Safe.equal
let errs_to_string errs = String.concat "\n" (List.map Load_error.to_string errs)

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let get_ok = function
  | Ok v -> v
  | Error errs -> Alcotest.failf "unexpected errors:\n%s" (errs_to_string errs)

let get_err = function Ok _ -> Alcotest.fail "expected an error" | Error errs -> errs

(* Assert some error has [path] (exact, when given) and a message containing [msg]. *)
let check_err ?path ~msg r =
  let errs = get_err r in
  let ok (e : Load_error.t) =
    (match path with Some p -> e.path = p | None -> true) && contains e.message msg
  in
  if not (List.exists ok errs) then
    Alcotest.failf "no error with path=%s message~%S; got:\n%s"
      (match path with Some p -> p | None -> "*")
      msg (errs_to_string errs)

let yaml s = Docload.of_string Docload.Yaml s
let jsn s = Docload.of_string Docload.Json s
let base = "apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: {name: t}\n"
let pol extra = Policy_load.of_string Docload.Yaml (base ^ extra)
let pol_ok extra = get_ok (pol extra)
let tc name f = Alcotest.test_case name `Quick f

module Str_replace = struct
  (* replace the first occurrence of [sub] in [s] by [by] *)
  let replace s sub by =
    let n = String.length s and m = String.length sub in
    let rec find i =
      if i + m > n then None else if String.sub s i m = sub then Some i else find (i + 1)
    in
    match find 0 with
    | None -> failwith ("Str_replace: not found: " ^ sub)
    | Some i -> String.sub s 0 i ^ by ^ String.sub s (i + m) (n - i - m)
end
