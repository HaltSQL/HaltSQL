(** Runs a scenario suite ({!Haltsql_load.Test_suite.t}) against its policy.

    Used by [haltsql test] and by the conformance / corpus test runners. A case passes
    when the verdict matches its expectation: [allow] cases must be allowed (and, if the
    case lists [bind], bind exactly those parameters); [deny] cases must be denied with at
    least the listed codes. Shadow-mode policies are tested against their
    [shadow_reasons]. *)

open Haltsql_core

type case_result = {
  case : Haltsql_load.Test_suite.case;
  verdict : Verdict.t;
  passed : bool;
  failure : string option;  (** why it failed, when [passed = false] *)
}
(** Outcome of one case. *)

type result = {
  suite : Haltsql_load.Test_suite.t;
  results : case_result list;  (** in suite order *)
  passed : int;
  failed : int;
}
(** Outcome of a whole suite. *)

val run :
  verify:(Policy.t -> Context.t -> string -> Verdict.t) ->
  Policy.t ->
  Haltsql_load.Test_suite.t ->
  result
(** [run ~verify policy suite] runs every case with [verify] (normally [Haltsql.verify]; a
    parameter so tests can substitute it). *)

val run_file :
  verify:(Policy.t -> Context.t -> string -> Verdict.t) ->
  string ->
  (result, Load_error.t list) Stdlib.result
(** Loads the suite and its policy, then runs it. *)
