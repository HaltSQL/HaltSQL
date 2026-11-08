(** Per-request values from the caller's authenticated session (tenant id, user id, ...).

    The context is the trust anchor of tenant isolation: a tenancy proof is only as good
    as the value it is checked against. Context values must therefore come from the host
    application's authenticated session (or from HaltSQL's own authentication layer),
    {b never} from the prompt, the model or the SQL text.

    A policy refers to context fields by name ([tenant: ${ctx.tenant_id}]); a field the
    policy needs but the context lacks denies the query ([E_CONTEXT_MISSING]). *)

(** A context value. *)
type value =
  | One of string  (** a single value, e.g. ["acme"] or ["42"] *)
  | Many of string list
      (** a set of allowed values, e.g. a parent org and its child orgs. [Many []] counts
          as missing. *)

type t = (string * value) list
(** Field name -> value, in the order given. If a field appears more than once, the first
    occurrence is the one {!find} returns (and therefore the one every tenancy proof
    uses). *)

val empty : t

val make : (string * value) list -> t
(** [make kvs] is the context with these fields. *)

val find : t -> string -> value option
(** [find t field] is the first value of [field]. *)

val value_to_json : value -> Yojson.Safe.t
(** [One s] -> a JSON string; [Many l] -> a JSON array of strings. *)

val to_json : t -> Yojson.Safe.t
(** A JSON object, fields in order. *)

val of_json : Yojson.Safe.t -> (t, string) result
(** Accepts a JSON object whose values are strings, integers, or arrays of those; integers
    become their decimal text (so [42] and ["42"] are the same value). Anything else
    (null, booleans, floats, nested objects) is an [Error] naming the field. *)
