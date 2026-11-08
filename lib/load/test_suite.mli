(** Policy test-suite documents ([kind: TestSuite]), shared by [haltsql test], the attack
    corpus and conformance tests.

    {v
    apiVersion: haltsql.dev/v1
    kind: TestSuite
    metadata: { name: tenancy-basic, description: optional }
    policy: ../fixtures/policies/saas.yaml   # relative to this file
    defaults:
      context: { tenant_id: acme }
    cases:
      - name: filtered select is allowed
        sql: SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10
        expect: allow                         # allow | deny
        bind: [{ param: 1, value: acme }]     # optional, checked when present
      - name: missing tenant filter
        sql: SELECT id FROM orders LIMIT 10
        context: { tenant_id: globex }        # optional, replaces defaults.context
        expect: deny
        codes: [E_TENANT_MISSING]             # each must appear in the reasons
        tags: [tenancy]
    v} *)

open Haltsql_core

(** Expected outcome of a case. *)
type expect = Allow | Deny

type case = {
  case_name : string;
  sql : string;
  context : Context.t;
  expect : expect;
  codes : Reason.code list;  (** [deny] cases: codes that must all appear *)
  bind : (int * Context.value) list option;
      (** [allow] cases: exact expected [bind_params], when given *)
  tags : string list;
}
(** One test case. [context] is the case's own context, or [defaults.context]. *)

type t = {
  suite_name : string;
  description : string option;
  policy_path : string;  (** absolute path *)
  cases : case list;
}
(** A decoded suite. *)

val of_json :
  ?file:string -> ?base_dir:string -> Yojson.Safe.t -> (t, Load_error.t list) result
(** Decodes a suite document. [base_dir] (default: the directory of [file]) resolves the
    relative [policy] path; the policy itself is not loaded. *)

val of_file : string -> (t, Load_error.t list) result
(** Reads and decodes a suite file (YAML or JSON, by extension). *)
