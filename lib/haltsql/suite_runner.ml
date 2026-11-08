(* Scenario-suite runner; see suite_runner.mli. *)

open Haltsql_core
module Ts = Haltsql_load.Test_suite

type case_result = {
  case : Ts.case;
  verdict : Verdict.t;
  passed : bool;
  failure : string option;
}

type result = { suite : Ts.t; results : case_result list; passed : int; failed : int }

let codes_str cs = String.concat ", " (List.map Reason.code_to_string cs)

let check (c : Ts.case) (v : Verdict.t) =
  (* Shadow-mode policies report denials in shadow_reasons; test against those. *)
  let reasons = v.reasons @ v.shadow_reasons in
  let denied = reasons <> [] in
  let got = List.map (fun (r : Reason.t) -> r.code) reasons in
  match c.expect with
  | Ts.Allow when denied ->
      Some
        (Printf.sprintf "expected allow, got deny [%s]: %s" (codes_str got)
           (String.concat "; " (List.map (fun (r : Reason.t) -> r.message) reasons)))
  | Ts.Allow -> (
      match c.bind with
      | Some expected when expected <> v.bind_params ->
          let show l =
            String.concat ", "
              (List.map
                 (fun (n, value) ->
                   Printf.sprintf "$%d=%s" n
                     (Yojson.Safe.to_string (Context.value_to_json value)))
                 l)
          in
          Some
            (Printf.sprintf "bind params differ: expected [%s], got [%s]" (show expected)
               (show v.bind_params))
      | _ -> None)
  | Ts.Deny when not denied -> Some "expected deny, got allow"
  | Ts.Deny ->
      let missing = List.filter (fun c -> not (List.mem c got)) c.codes in
      if missing = [] then None
      else
        Some
          (Printf.sprintf "denied, but missing codes [%s]; got [%s]" (codes_str missing)
             (codes_str got))

let run ~verify policy (suite : Ts.t) =
  let results =
    List.map
      (fun (c : Ts.case) ->
        let verdict = verify policy c.context c.sql in
        let failure = check c verdict in
        { case = c; verdict; passed = failure = None; failure })
      suite.cases
  in
  let passed = List.length (List.filter (fun (r : case_result) -> r.passed) results) in
  { suite; results; passed; failed = List.length results - passed }

let run_file ~verify file =
  match Ts.of_file file with
  | Error e -> Error e
  | Ok suite -> (
      match Haltsql_load.Policy_load.of_file suite.policy_path with
      | Error e -> Error e
      | Ok policy -> Ok (run ~verify policy suite))
