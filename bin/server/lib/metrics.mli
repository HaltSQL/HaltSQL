(** In-process Prometheus metrics, served by [GET /metrics] (text exposition format
    0.0.4). Every observation is also mirrored into the OTLP exporter ({!Telemetry}).

    {b Label cardinality is bounded}: [route] is one of the known routes or ["other"];
    [status] an HTTP status the server produces; [policy] the name of a loaded policy
    (requests naming an unknown policy are not counted per policy); [code] a reason code
    from a fixed set; [method] and [result] fixed vocabularies. Nothing request-controlled
    (paths, callers, SQL) becomes a label.

    Exposed families: [haltsql_build_info], [haltsql_policies_loaded],
    [haltsql_verify_total{policy,result}], [haltsql_reasons_total{code}],
    [haltsql_verify_duration_seconds] (histogram), [haltsql_policy_reload_total{result}],
    [haltsql_audit_errors_total], [haltsql_http_open_connections],
    [haltsql_http_requests_total{route,status}], [haltsql_auth_total{method,result}],
    [haltsql_tls_reload_total{result}]. *)

val reset : unit -> unit
(** Clears every counter (tests). *)

val observe_verify :
  policy:string -> result:string -> codes:string list -> seconds:float -> unit
(** One verify request: [result] is ["allowed"], ["denied"] or ["shadow_denied"]; [codes]
    the reason codes of the verdict. *)

val observe_reload : ok:bool -> unit
(** One policy reload attempt. *)

val observe_http : path:string -> status:int -> unit
(** One HTTP response; [path] must already be a known route or ["other"]. *)

val observe_audit_error : unit -> unit
(** One failed audit write. *)

val set_policies_loaded : int -> unit
(** Mirrors the number of loaded policies to the OTLP exporter. *)

val set_open_connections : int -> unit
(** Current number of open connections on the main listener. *)

val observe_auth : meth:string -> result:string -> unit
(** One caller authentication: [meth] is ["token"], ["oidc"], ["mtls"], ["anonymous"] or
    ["none"]; [result] ["ok"], ["rejected"] or ["unavailable"]. *)

val observe_tls_reload : ok:bool -> unit
(** One TLS certificate reload attempt. *)

val observe_opa : outcome:string -> seconds:float -> unit
(** One OPA check: [outcome] is ["skipped"], ["allowed"], ["denied"], ["error_allowed"] or
    ["error_denied"]; [seconds] (time spent waiting for OPA) is recorded unless
    ["skipped"]. *)

val observe_admin : endpoint:string -> result:string -> unit
(** One admin API request: [result] is ["ok"], ["disabled"], ["unauthenticated"] or
    ["forbidden"]. *)

val escape_label : string -> string
(** Escapes a Prometheus label value (backslash, double quote, newline). *)

val render : version:string -> pg:string -> policies_loaded:int -> string
(** The exposition text. *)
