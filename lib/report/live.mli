(** The report backend of haltsql-server's [GET /v1/admin/report] (see
    [bin/server/lib/report_api.ml], which keeps the bounded rolling window and passes the
    records here). *)

open Haltsql_core

type record = Record.t

val of_audit_fields : (string * Yojson.Safe.t) list -> record option
(** From the fields of an audit record as the server writes them. *)

val of_verdict :
  ts:float ->
  caller:string ->
  caller_type:string ->
  sql:string option ->
  Verdict.t ->
  record
(** With full detail. [sql] should be [Some] only when [audit.log_raw_sql] is on. *)

val policy : record -> string
val fingerprint : record -> string
val has_sql : record -> bool
val strip_sql : record -> record

val parse_since : now:float -> string -> (float, string) result
(** {!Rtime.parse_bound}. *)

val report :
  now:float ->
  since:float ->
  policy:string option ->
  suggest:bool ->
  top:int ->
  policies:(string * Policy.t) list ->
  verify:(Policy.t -> Context.t -> string -> Verdict.t) option ->
  record list ->
  Yojson.Safe.t
(** The report JSON ({!Render.to_json}) over the records with [ts >= since] (records
    without a timestamp are kept), optionally restricted to one policy. Records without
    detail but with SQL are re-verified against their (current) policy to name the denied
    objects; records of the same policy and fingerprint without SQL share those details
    (filtered to their own codes). PII: the column-name heuristic ({!Pii.name_heuristic}).
*)

val enrich :
  policies:(string * Policy.t) list ->
  verify:(Policy.t -> Context.t -> string -> Verdict.t) ->
  record ->
  record
(** Adds detailed reasons to a record without any, by re-verifying its SQL (if any)
    against the policy of the same name, with {!Suggest.probe_context}. *)
