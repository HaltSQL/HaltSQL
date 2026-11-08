(** Errors from loading YAML/JSON policy, config, catalog and scenario documents. Always
    located as precisely as the input allows. *)

type t = {
  file : string option;
  line : int option;  (** 1-based *)
  column : int option;  (** 1-based *)
  path : string;
      (** key path, e.g. [tables."app.orders".tenant_column]; [""] for the root *)
  message : string;
}

(** [make ?file ?line ?column ?path message]; [path] defaults to the root ([""]). *)
let make ?file ?line ?column ?(path = "") message = { file; line; column; path; message }

(** [file:line:col: path: message], omitting the parts that are unknown. *)
let to_string e =
  let where =
    match (e.file, e.line, e.column) with
    | Some f, Some l, Some c -> Printf.sprintf "%s:%d:%d: " f l c
    | Some f, Some l, None -> Printf.sprintf "%s:%d: " f l
    | Some f, None, _ -> f ^ ": "
    | None, Some l, Some c -> Printf.sprintf "%d:%d: " l c
    | None, Some l, None -> Printf.sprintf "%d: " l
    | None, None, _ -> ""
  in
  let path = if e.path = "" then "" else e.path ^ ": " in
  where ^ path ^ e.message

(** [{"file", "line", "column", "path", "message"}]; unknown location fields are omitted.
*)
let to_json e : Yojson.Safe.t =
  let opt k = function Some v -> [ (k, v) ] | None -> [] in
  `Assoc
    (opt "file" (Option.map (fun s -> `String s) e.file)
    @ opt "line" (Option.map (fun i -> `Int i) e.line)
    @ opt "column" (Option.map (fun i -> `Int i) e.column)
    @ [ ("path", `String e.path); ("message", `String e.message) ])
