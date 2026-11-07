(** Runs a {!Haltsql_load.Test_suite.t} against its policy. *)

open Haltsql_core

type case_result = {
  case : Haltsql_load.Test_suite.case;
  verdict : Verdict.t;
  passed : bool;
  failure : string option;  (** why it failed, when [passed = false] *)
}

type result = {
  suite : Haltsql_load.Test_suite.t;
  results : case_result list;
  passed : int;
  failed : int;
}

val run :
  verify:(Policy.t -> Context.t -> string -> Verdict.t) ->
  Policy.t ->
  Haltsql_load.Test_suite.t ->
  result

val run_file :
  verify:(Policy.t -> Context.t -> string -> Verdict.t) ->
  string ->
  (result, Load_error.t list) Stdlib.result
(** Loads the suite and its policy, then runs it. *)
