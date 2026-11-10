(* The facade's last line of defence. The parser and the analyzer are total, so no input
   reaches this handler in a correct build; these tests inject the failure. *)

open Haltsql

let policy mode =
  match
    Policy_load.of_string Docload.Yaml
      (Printf.sprintf
         {|apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: fc }
search_path: [app]
mode: %s
tenancy: { mode: bound, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.orders: { columns: [id, tenant_id], tenant_column: tenant_id }
|}
         mode)
  with
  | Ok p -> p
  | Error _ -> Alcotest.fail "policy"

let ctx = Context.make [ ("tenant_id", Context.One "acme") ]
let sql = "SELECT id FROM orders WHERE tenant_id = $1"
let codes rs = List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) rs

let raising exn () =
  let v = verify_with ~analyze:(fun _ _ _ -> raise exn) (policy "enforce") ctx sql in
  Alcotest.(check bool) "denied" false v.allowed;
  Alcotest.(check (list string)) "E_INTERNAL only" [ "E_INTERNAL" ] (codes v.reasons);
  Alcotest.(check int) "no bind_params" 0 (List.length v.bind_params)

(* An analysis that "allows" with a binding and then fails must leave nothing behind. *)
let no_partial_result () =
  let analyze p c s =
    let a = Analyzer.analyze p c s in
    if a.bind_params <> [] then failwith "after the proof" else a
  in
  let v = verify_with ~analyze (policy "enforce") ctx sql in
  Alcotest.(check bool) "denied" false v.allowed;
  Alcotest.(check int) "no bind_params" 0 (List.length v.bind_params)

(* Shadow mode reports the failure; it must not hide it, and it binds nothing. *)
let shadow () =
  let v = verify_with ~analyze:(fun _ _ _ -> raise Not_found) (policy "shadow") ctx sql in
  Alcotest.(check (list string)) "shadow reason" [ "E_INTERNAL" ] (codes v.shadow_reasons);
  Alcotest.(check int) "no bind_params" 0 (List.length v.bind_params)

(* The seam itself changes nothing. *)
let same_as_verify () =
  let a = verify (policy "enforce") ctx sql
  and b = verify_with ~analyze:Analyzer.analyze (policy "enforce") ctx sql in
  Alcotest.(check bool) "allowed" true (a.allowed && b.allowed);
  Alcotest.(check bool) "same bindings" true (a.bind_params = b.bind_params)

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run "haltsql-fail-closed"
    [
      ( "internal errors deny",
        [
          tc "Failure" (raising (Failure "boom"));
          tc "Not_found" (raising Not_found);
          tc "Stack_overflow" (raising Stack_overflow);
          tc "Out_of_memory" (raising Out_of_memory);
          tc "Invalid_argument" (raising (Invalid_argument "x"));
          tc "no partial result" no_partial_result;
          tc "shadow mode" shadow;
          tc "same as verify" same_as_verify;
        ] );
    ]
