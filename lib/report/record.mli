(** One audit record, normalized from either producer:

    - haltsql-server (file/stdout sinks, S3/GCS objects, streaming sinks):
      [{ts, request_id, caller, caller_type, subject, policy, policy_version, allowed,
       shadow, codes, sql_sha256, fingerprint, elapsed_us, [sql], prev_hash, hash}].
      [codes] holds the denial codes, or, when [allowed] and [shadow] are both true, the
      shadow-mode codes.
    - haltsql-proxy:
      [{ts, event: "statement", session, user, policy, policy_version, protocol, allowed,
       reasons, shadow_reasons, sql_sha256, fingerprint, tables, bind_params, [statement],
       [sql]}], and local denials
      [{ts, event: "parse"|"bind"|"function_call", session, user, policy, allowed: false,
       reasons, message, [statement]}].

    Records carry reason {e codes} only. The detailed reasons (rule and message, which
    name the denied column, function, table or LIMIT) are known when a record is built
    from a verdict ({!of_verdict}) or re-derived later from its SQL ({!with_details}). *)

type source = Server | Proxy

type outcome =
  | Allowed
  | Denied  (** enforce-mode denial *)
  | Shadow_denied  (** allowed, but the policy (shadow mode) would have denied it *)

type reason = { code : string; rule : string; message : string }
(** A detailed reason; [code] is the stable reason code string. *)

type t = {
  source : source;
  ts : float option;  (** Unix seconds; [None] when the record has no parsable [ts] *)
  event : string;  (** ["verify"] for the server, the proxy's [event] otherwise *)
  caller : string;  (** server [caller], proxy [user]; ["(unknown)"] if absent *)
  caller_type : string option;
  policy : string;
  policy_version : string option;
  outcome : outcome;
  codes : string list;  (** denial or shadow codes, de-duplicated, in record order *)
  details : reason list;  (** detailed reasons, when known (each [code] is in [codes]) *)
  tables : string list;  (** relations the statement touched, when the record says *)
  columns : string list;  (** ["schema.table.column"] read, when known *)
  fingerprint : string option;
  sql_sha256 : string option;
  sql : string option;  (** raw SQL, only when the producer logged it ([log_raw_sql]) *)
}

val outcome_to_string : outcome -> string
(** ["allowed"], ["denied"], ["shadow_denied"]. *)

val source_to_string : source -> string

val of_json : Yojson.Safe.t -> (t, string) result
(** Recognizes both formats; anything else (log lines, other JSON) is an [Error]. *)

val of_line : string -> (t, string) result

val is_execution : Yojson.Safe.t -> bool
(** A proxy [execute] record (one per forwarded Execute). It carries no verdict, so
    {!of_json} rejects it; callers should not count it as an unrecognised line. *)

val of_verdict :
  ts:float ->
  caller:string ->
  ?caller_type:string ->
  sql:string option ->
  Haltsql_core.Verdict.t ->
  t
(** A server-side record with full detail (reasons, tables, columns). *)

val with_details : t -> Haltsql_core.Verdict.t -> t
(** Adds the detailed reasons of a re-verification of the record's SQL, keeping only
    reasons whose code is among the record's own [codes] (the codes the producer actually
    recorded decide what happened; the re-verification only names the objects), and the
    verdict's tables and columns when the record had none. *)

val fingerprint_key : t -> string
(** The fingerprint, else ["sha256:" ^ sql_sha256], else ["(none)"]. *)
