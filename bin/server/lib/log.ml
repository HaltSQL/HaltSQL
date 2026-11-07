(* Structured logging to stderr. Format: one JSON object per line ("json") or
   "ts LEVEL msg key=value ..." ("text"). *)

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
          :: msg
          :: List.map
               (fun (k, v) ->
                 k ^ "=" ^ match v with `String s -> s | j -> Yojson.Safe.to_string j)
               fields)
    in
    prerr_endline line
  end

let debug ?(fields = []) msg = emit Debug msg fields
let info ?(fields = []) msg = emit Info msg fields
let warn ?(fields = []) msg = emit Warn msg fields
let error ?(fields = []) msg = emit Error msg fields
