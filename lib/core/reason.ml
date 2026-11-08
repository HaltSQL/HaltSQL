(** Stable, machine-readable reasons for a verdict.

    The string form of each [code] is part of HaltSQL's public API. Codes are never
    renamed or reused; new codes may be added in minor releases. Clients must treat an
    unknown code as a denial reason like any other. *)

(** Reason codes. Their string forms ({!code_to_string}) are a stable public contract. *)

type code =
  | E_PARSE  (** SQL did not parse *)
  | E_EMPTY  (** no statement *)
  | E_LIMIT  (** byte / depth / node-count limit exceeded *)
  | E_MULTI_STATEMENT  (** more than one statement *)
  | E_STATEMENT_KIND  (** statement kind not allowed *)
  | E_DATA_MODIFYING_CTE  (** write inside a CTE when writes are not allowed *)
  | E_TABLE_DENIED  (** relation not in the allowlist (includes system schemas) *)
  | E_COLUMN_DENIED  (** column not allowed, or [*] expands to a denied column *)
  | E_COLUMN_UNRESOLVED  (** ambiguous or unknown column *)
  | E_FUNCTION_DENIED  (** function not in the allowlist *)
  | E_OPERATOR_DENIED  (** operator not in the allowlist *)
  | E_CAST_DENIED  (** cast to a denied type ([regclass], ...) *)
  | E_TENANT_MISSING  (** tenant-scoped relation lacks a provable tenant predicate *)
  | E_TENANT_MISMATCH  (** tenant literal differs from the context value *)
  | E_TENANT_WRITE  (** write would set or change a tenant column incorrectly *)
  | E_CONTEXT_MISSING  (** a context value the policy needs was not supplied *)
  | E_PARAM_UNBOUND  (** query uses a [$n] parameter HaltSQL cannot bind *)
  | E_LIMIT_REQUIRED  (** LIMIT missing *)
  | E_LIMIT_TOO_HIGH  (** LIMIT larger than allowed, or not a constant *)
  | E_LOCKING_CLAUSE  (** FOR UPDATE / FOR SHARE *)
  | E_SELECT_INTO  (** SELECT ... INTO *)
  | E_JOIN_BUDGET  (** too many joins or an unconstrained cross join *)
  | E_WRITE_DENIED  (** write to a table or column the policy does not allow *)
  | E_UNSUPPORTED  (** syntax HaltSQL does not analyze; always denied *)
  | E_INTERNAL  (** analyzer bug; fails closed *)

(** Every code, in documentation order. *)
let all_codes =
  [
    E_PARSE;
    E_EMPTY;
    E_LIMIT;
    E_MULTI_STATEMENT;
    E_STATEMENT_KIND;
    E_DATA_MODIFYING_CTE;
    E_TABLE_DENIED;
    E_COLUMN_DENIED;
    E_COLUMN_UNRESOLVED;
    E_FUNCTION_DENIED;
    E_OPERATOR_DENIED;
    E_CAST_DENIED;
    E_TENANT_MISSING;
    E_TENANT_MISMATCH;
    E_TENANT_WRITE;
    E_CONTEXT_MISSING;
    E_PARAM_UNBOUND;
    E_LIMIT_REQUIRED;
    E_LIMIT_TOO_HIGH;
    E_LOCKING_CLAUSE;
    E_SELECT_INTO;
    E_JOIN_BUDGET;
    E_WRITE_DENIED;
    E_UNSUPPORTED;
    E_INTERNAL;
  ]

(** The stable string form, identical to the constructor name (e.g. ["E_PARSE"]). *)
let code_to_string = function
  | E_PARSE -> "E_PARSE"
  | E_EMPTY -> "E_EMPTY"
  | E_LIMIT -> "E_LIMIT"
  | E_MULTI_STATEMENT -> "E_MULTI_STATEMENT"
  | E_STATEMENT_KIND -> "E_STATEMENT_KIND"
  | E_DATA_MODIFYING_CTE -> "E_DATA_MODIFYING_CTE"
  | E_TABLE_DENIED -> "E_TABLE_DENIED"
  | E_COLUMN_DENIED -> "E_COLUMN_DENIED"
  | E_COLUMN_UNRESOLVED -> "E_COLUMN_UNRESOLVED"
  | E_FUNCTION_DENIED -> "E_FUNCTION_DENIED"
  | E_OPERATOR_DENIED -> "E_OPERATOR_DENIED"
  | E_CAST_DENIED -> "E_CAST_DENIED"
  | E_TENANT_MISSING -> "E_TENANT_MISSING"
  | E_TENANT_MISMATCH -> "E_TENANT_MISMATCH"
  | E_TENANT_WRITE -> "E_TENANT_WRITE"
  | E_CONTEXT_MISSING -> "E_CONTEXT_MISSING"
  | E_PARAM_UNBOUND -> "E_PARAM_UNBOUND"
  | E_LIMIT_REQUIRED -> "E_LIMIT_REQUIRED"
  | E_LIMIT_TOO_HIGH -> "E_LIMIT_TOO_HIGH"
  | E_LOCKING_CLAUSE -> "E_LOCKING_CLAUSE"
  | E_SELECT_INTO -> "E_SELECT_INTO"
  | E_JOIN_BUDGET -> "E_JOIN_BUDGET"
  | E_WRITE_DENIED -> "E_WRITE_DENIED"
  | E_UNSUPPORTED -> "E_UNSUPPORTED"
  | E_INTERNAL -> "E_INTERNAL"

(** Inverse of {!code_to_string}. *)
let code_of_string s =
  List.find_opt (fun c -> String.equal (code_to_string c) s) all_codes

type t = {
  code : code;
  message : string;  (** human-readable explanation *)
  loc : int option;  (** byte offset into the SQL, when known *)
  rule : string;  (** id of the rule that produced it, e.g. ["tenancy.predicate"] *)
  hint : string option;  (** short instruction an LLM agent can follow to fix its query *)
}
(** One reason a statement is (or, in shadow mode, would be) denied. *)

(** [make ?loc ?hint ~rule code message]. A negative [loc] (unknown) is dropped. *)
let make ?loc ?hint ~rule code message =
  let loc = match loc with Some l when l >= 0 -> Some l | _ -> None in
  { code; message; loc; rule; hint }

(** [{"code", "message", "rule", "loc"?, "hint"?}]: part of the verdict JSON contract
    (docs/verdict.md). *)
let to_json r : Yojson.Safe.t =
  `Assoc
    ([
       ("code", `String (code_to_string r.code));
       ("message", `String r.message);
       ("rule", `String r.rule);
     ]
    @ (match r.loc with Some l -> [ ("loc", `Int l) ] | None -> [])
    @ match r.hint with Some h -> [ ("hint", `String h) ] | None -> [])

(** [CODE: message (at byte N)], for humans. *)
let pp fmt r =
  Format.fprintf fmt "%s: %s%s" (code_to_string r.code) r.message
    (match r.loc with Some l -> Printf.sprintf " (at byte %d)" l | None -> "")
