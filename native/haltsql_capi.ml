(* OCaml half of libhaltsql (see include/haltsql.h). Policies live in a table keyed by
   an integer handle, so the C side never holds OCaml values across calls and needs no
   GC roots. Every function here is total: errors come back as values, never as OCaml
   exceptions crossing into C.

   Several host threads can be inside these functions at once: each holds the runtime
   lock while it runs OCaml code, but OCaml 5 systhreads hand that lock over at
   safepoints. The handle table is therefore guarded by a mutex; verification itself
   needs no lock ([Haltsql.verify] is pure and safe to share a policy across threads). *)

open Haltsql

let policies : (int, Policy.t) Hashtbl.t = Hashtbl.create 8
let next_handle = ref 1
let table_lock = Mutex.create ()
let locked f = Mutex.protect table_lock f

let register p =
  locked (fun () ->
      let h = !next_handle in
      incr next_handle;
      Hashtbl.replace policies h p;
      h)

let find h = locked (fun () -> Hashtbl.find_opt policies h)

let errors_to_string ?file (errs : Load_error.t list) =
  String.concat "\n"
    (List.map
       (fun (e : Load_error.t) ->
         let s = Load_error.to_string e in
         match (e.file, file) with None, Some f -> f ^ ": " ^ s | _ -> s)
       errs)

(* Returns (handle, "") on success, (0, message) on failure. *)
let load_file path =
  match
    if not (Sys.file_exists path) then Error ("policy file not found: " ^ path)
    else
      match Policy_load.of_file path with
      | Ok p -> Ok p
      | Error errs -> Error ("cannot load policy:\n" ^ errors_to_string ~file:path errs)
  with
  | Ok p -> (register p, "")
  | Error e -> (0, e)
  | exception e -> (0, "internal error: " ^ Printexc.to_string e)

let load_string doc format base_dir =
  match
    match String.lowercase_ascii format with
    | ("yaml" | "yml" | "json") as f -> (
        let fmt = if f = "json" then Docload.Json else Docload.Yaml in
        let base_dir = if base_dir = "" then None else Some base_dir in
        match Policy_load.of_string ?base_dir fmt doc with
        | Ok p -> Ok p
        | Error errs -> Error ("cannot load policy:\n" ^ errors_to_string errs))
    | _ -> Error "format must be \"yaml\" or \"json\""
  with
  | Ok p -> (register p, "")
  | Error e -> (0, e)
  | exception e -> (0, "internal error: " ^ Printexc.to_string e)

let mode_to_string = function Policy.Enforce -> "enforce" | Policy.Shadow -> "shadow"

(* "" for an unknown handle (the C side turns that into NULL). *)
let info h =
  match find h with
  | None -> ""
  | Some (p : Policy.t) ->
      Yojson.Safe.to_string
        (`Assoc
           [
             ("name", `String p.name);
             ("version", `String p.version);
             ("mode", `String (mode_to_string p.mode));
           ])

let free h = locked (fun () -> Hashtbl.remove policies h)
let error msg = Yojson.Safe.to_string (`Assoc [ ("error", `String msg) ])

let verify h sql ctx_json =
  match find h with
  | None -> error "unknown policy handle"
  | Some policy -> (
      let ctx =
        if
          String.for_all
            (function ' ' | '\t' | '\r' | '\n' -> true | _ -> false)
            ctx_json
        then Ok Context.empty
        else
          match Yojson.Safe.from_string ctx_json with
          | `Null -> Ok Context.empty
          | j -> Context.of_json j |> Result.map_error (fun e -> "invalid context: " ^ e)
          | exception Yojson.Json_error e -> Error ("invalid context JSON: " ^ e)
      in
      match ctx with
      | Error e -> error e
      | Ok ctx -> (
          (* Haltsql.verify is total, but keep the boundary airtight. *)
          match Haltsql.verify policy ctx sql with
          | v -> Yojson.Safe.to_string (Verdict.to_json v)
          | exception e -> error ("internal error: " ^ Printexc.to_string e)))

let () =
  Callback.register "haltsql_version" (fun () -> Haltsql.version);
  Callback.register "haltsql_load_file" load_file;
  Callback.register "haltsql_load_string" load_string;
  Callback.register "haltsql_info" info;
  Callback.register "haltsql_free" free;
  Callback.register "haltsql_verify" verify
