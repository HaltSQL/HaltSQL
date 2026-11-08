(** What a detailed reason names, recovered from its rule id and message (both produced by
    HaltSQL's analyzer; the test suite checks this against the real verifier). *)

type t =
  | Column of { table : string; column : string }
      (** [columns.denied]: [table] is ["schema.name"] as the analyzer prints it *)
  | Column_star of string  (** [columns.star]: [*] / whole-row reference on a table *)
  | Function of string  (** [functions.allowlist]: ["f"] or ["schema.f"] *)
  | Sql_value_function of string  (** [functions.sql_value]: CURRENT_USER, ... *)
  | Table of { schema : string option; name : string }
      (** [tables.allowlist]: a relation outside the allowlist; [schema = None] when the
          query did not qualify it *)
  | System_relation of string  (** [tables.allowlist]: resolves to [pg_catalog] *)
  | Limit_value of int  (** [limit.max]: constant LIMIT above the maximum *)
  | Limit_non_constant  (** [limit.max]: LIMIT $n, LIMIT (SELECT ...) *)
  | Unrecognized  (** any other rule, or a message in an unknown format *)

val of_reason : Record.reason -> t
