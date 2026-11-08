(* Structured logs and audit sink; see plog.mli. *)

type level = Debug | Info | Warn | Error

let rank = function Debug -> 0 | Info -> 1 | Warn -> 2 | Error -> 3

let name = function
  | Debug -> "debug"
  | Info -> "info"
  | Warn -> "warn"
  | Error -> "error"

let current = ref Info

let set_level = function
  | "debug" -> current := Debug
  | "info" -> current := Info
  | "warn" -> current := Warn
  | "error" -> current := Error
  | _ -> ()

let now_rfc3339 () = Ptime.to_rfc3339 ~frac_s:3 ~tz_offset_s:0 (Ptime_clock.now ())

let log level msg fields =
  if rank level >= rank !current then
    let j =
      `Assoc
        ([
           ("ts", `String (now_rfc3339 ()));
           ("level", `String (name level));
           ("component", `String "haltsql-proxy");
           ("msg", `String msg);
         ]
        @ fields)
    in
    try
      prerr_string (Yojson.Safe.to_string j ^ "\n");
      flush stderr
    with _ -> ()

type audit = Null | Chan of out_channel * bool  (** channel, close on exit *)

let open_audit = function
  | Proxy_config.Audit_none -> Null
  | Proxy_config.Audit_stdout -> Chan (stdout, false)
  | Proxy_config.Audit_file path ->
      Chan
        ( open_out_gen [ Open_wronly; Open_append; Open_creat; Open_binary ] 0o600 path,
          true )

let audit a fields =
  match a with
  | Null -> ()
  | Chan (oc, _) -> (
      try
        output_string oc
          (Yojson.Safe.to_string (`Assoc (("ts", `String (now_rfc3339 ())) :: fields))
          ^ "\n");
        flush oc
      with _ -> ())

let close_audit = function
  | Null -> ()
  | Chan (oc, true) -> close_out_noerr oc
  | Chan (_, false) -> ()
