(** Structured logging to stderr. See log.mli. *)

type level = Debug | Info | Warn | Error

let level_of_string = function
  | "debug" -> Debug
  | "warn" | "warning" -> Warn
  | "error" -> Error
  | _ -> Info

let level_to_string = function
  | Debug -> "debug"
  | Info -> "info"
  | Warn -> "warn"
  | Error -> "error"

let rank = function Debug -> 0 | Info -> 1 | Warn -> 2 | Error -> 3
let min_level = ref Info
let json_format = ref true

let setup ~level ~format =
  min_level := level_of_string level;
  json_format := format <> "text"

let rfc3339 t =
  let tm = Unix.gmtime t in
  let ms = int_of_float ((t -. Float.of_int (int_of_float t)) *. 1000.) in
  Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" (tm.tm_year + 1900) (tm.tm_mon + 1)
    tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec
    (max 0 (min 999 ms))

let enabled lvl = rank lvl >= rank !min_level

(* Text format: values that could break the one-record-per-line framing or
   be mistaken for another key (spaces, '=', quotes, control characters, e.g.
   from a percent-decoded request path) are written as JSON strings. *)
let needs_quoting s =
  s = ""
  || String.exists
       (fun c ->
         c = ' ' || c = '=' || c = '"' || c = '\\' || Char.code c < 0x20 || c = '\x7f')
       s

let text_value = function
  | `String s when not (needs_quoting s) -> s
  | `String s -> Yojson.Safe.to_string (`String s)
  | j -> Yojson.Safe.to_string j

let text_msg msg =
  if String.exists (fun c -> Char.code c < 0x20) msg then
    let j = Yojson.Safe.to_string (`String msg) in
    String.sub j 1 (String.length j - 2)
  else msg

let emit lvl msg (fields : (string * Yojson.Safe.t) list) =
  if enabled lvl then begin
    let ts = rfc3339 (Unix.gettimeofday ()) in
    let line =
      if !json_format then
        Yojson.Safe.to_string
          (`Assoc
             ([
                ("ts", `String ts);
                ("level", `String (level_to_string lvl));
                ("msg", `String msg);
              ]
             @ fields))
      else
        String.concat " "
          (ts
          :: String.uppercase_ascii (level_to_string lvl)
          :: text_msg msg
          :: List.map (fun (k, v) -> k ^ "=" ^ text_value v) fields)
    in
    prerr_endline line
  end

let debug ?(fields = []) msg = emit Debug msg fields
let info ?(fields = []) msg = emit Info msg fields
let warn ?(fields = []) msg = emit Warn msg fields
let error ?(fields = []) msg = emit Error msg fields
