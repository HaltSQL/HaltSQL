(** [WWW-Authenticate] challenges (RFC 9110 section 11.6.1), as sent by OCI registries:

    {v
    Bearer realm="https://auth.example/token",service="registry.example",scope="repository:corp/p:pull"
    v}

    Several challenges may share one header ([Basic realm="r", Bearer realm="..."]). The
    parser is total: malformed input yields fewer (or no) challenges, never an exception.
*)

type challenge = {
  scheme : string;  (** lower-cased, e.g. ["bearer"] or ["basic"] *)
  params : (string * string) list;  (** names lower-cased, values unquoted *)
}

val parse : string -> challenge list
val param : challenge -> string -> string option
