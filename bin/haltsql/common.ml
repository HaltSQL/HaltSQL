(* Shared helpers for the haltsql CLI subcommands. *)

open Haltsql

exception Usage of string
(** A usage or load error: printed to stderr, exit code 2. *)

let exit_allowed = 0
let exit_denied = 1
let exit_usage = 2
let usage fmt = Printf.ksprintf (fun s -> raise (Usage s)) fmt

let errors_to_string ?file (errs : Load_error.t list) =
  String.concat "\n"
    (List.map
       (fun (e : Load_error.t) ->
         let s = Load_error.to_string e in
         match (e.file, file) with None, Some f -> f ^ ": " ^ s | _ -> s)
       errs)

let load_policy file =
  if not (Sys.file_exists file) then usage "policy file not found: %s" file;
  match Policy_load.of_file file with
  | Ok p -> p
  | Error errs -> raise (Usage ("cannot load policy:\n" ^ errors_to_string ~file errs))

let context_of_json ~what (j : Yojson.Safe.t) =
  match Context.of_json j with Ok c -> c | Error e -> usage "invalid %s: %s" what e

let load_context ~context ~context_file =
  match (context, context_file) with
  | Some _, Some _ -> usage "--context and --context-file are mutually exclusive"
  | Some s, None -> (
      match Yojson.Safe.from_string s with
      | j -> context_of_json ~what:"--context" j
      | exception Yojson.Json_error e -> usage "--context is not valid JSON: %s" e)
  | None, Some f -> (
      if not (Sys.file_exists f) then usage "context file not found: %s" f;
      match Docload.of_file f with
      | Ok j -> context_of_json ~what:("context file " ^ f) j
      | Error errs ->
          usage "cannot read context file:\n%s" (errors_to_string ~file:f errs))
  | None, None -> Context.empty

let read_file f =
  match In_channel.with_open_bin f In_channel.input_all with
  | s -> s
  | exception Sys_error e -> usage "cannot read %s" e

let read_sql ~sql ~file =
  match (sql, file) with
  | Some _, Some _ -> usage "--sql and --file are mutually exclusive"
  | Some s, None -> s
  | None, Some f -> read_file f
  | None, None ->
      if Unix.isatty Unix.stdin then
        prerr_endline "haltsql: reading SQL from stdin (end with Ctrl-D)";
      In_channel.input_all stdin

let value_to_string (v : Context.value) = Yojson.Safe.to_string (Context.value_to_json v)
let mode_to_string = function Policy.Enforce -> "enforce" | Policy.Shadow -> "shadow"

let write_file path contents =
  Out_channel.with_open_bin path (fun oc -> Out_channel.output_string oc contents)

let rec mkdir_p dir =
  if dir <> "" && dir <> "." && dir <> "/" && not (Sys.file_exists dir) then begin
    mkdir_p (Filename.dirname dir);
    try Unix.mkdir dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ()
  end

let print_json j = print_endline (Yojson.Safe.pretty_to_string j)

(* Wraps a subcommand body: Usage errors print to stderr and give exit 2. *)
let run f =
  match f () with
  | code -> code
  | exception Usage msg ->
      prerr_endline ("haltsql: " ^ msg);
      exit_usage
