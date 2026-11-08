(** The result of verifying one SQL string. Its JSON form is part of the public API (see
    docs/verdict.md): fields are never removed or renamed.

    Invariant: in enforce mode a caller may execute the SQL {b only} when [allowed] is
    true, and then must bind exactly [bind_params]. [bind_params] is empty whenever the
    statement was denied (or would be, in shadow mode). *)

type t = {
  allowed : bool;
      (** In enforce mode: true iff [reasons = []]. In shadow mode: always true; would-be
          denials are reported in [shadow_reasons]. *)
  reasons : Reason.t list;
  shadow_reasons : Reason.t list;  (** shadow mode only *)
  policy_name : string;
  policy_version : string;
  statement_kind : string option;  (** ["select"], ["insert"], ... when parsed *)
  tables : string list;  (** qualified relations read or written, sorted, unique *)
  columns : string list;  (** ["schema.table.column"] read, sorted, unique *)
  bind_params : (int * Context.value) list;
      (** bound tenancy mode: [$n] -> value the caller MUST bind *)
  fingerprint : string option;  (** normalized-query fingerprint for grouping *)
  sql_sha256 : string;  (** hash of the exact input string *)
  elapsed_us : int;
}

(** The stable JSON form of a verdict. *)
let to_json v : Yojson.Safe.t =
  let reasons rs = `List (List.map Reason.to_json rs) in
  `Assoc
    [
      ("allowed", `Bool v.allowed);
      ("reasons", reasons v.reasons);
      ("shadow_reasons", reasons v.shadow_reasons);
      ( "policy",
        `Assoc [ ("name", `String v.policy_name); ("version", `String v.policy_version) ]
      );
      ("statement_kind", match v.statement_kind with Some k -> `String k | None -> `Null);
      ("tables", `List (List.map (fun s -> `String s) v.tables));
      ("columns", `List (List.map (fun s -> `String s) v.columns));
      ( "bind_params",
        `List
          (List.map
             (fun (n, value) ->
               `Assoc [ ("param", `Int n); ("value", Context.value_to_json value) ])
             v.bind_params) );
      ("fingerprint", match v.fingerprint with Some f -> `String f | None -> `Null);
      ("sql_sha256", `String v.sql_sha256);
      ("elapsed_us", `Int v.elapsed_us);
    ]
