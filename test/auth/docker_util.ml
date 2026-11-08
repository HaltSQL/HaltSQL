(* Minimal docker CLI helpers for integration tests: real containers only.
   Every container this module starts is removed by [cleanup] (also at exit). *)

let run_capture args =
  let ic, oc, ec =
    Unix.open_process_args_full "docker"
      (Array.of_list ("docker" :: args))
      (Unix.environment ())
  in
  close_out oc;
  let out = In_channel.input_all ic in
  let err = In_channel.input_all ec in
  let st = Unix.close_process_full (ic, oc, ec) in
  match st with
  | Unix.WEXITED 0 -> Ok (String.trim out)
  | _ -> Error (String.trim (out ^ err))

let available () =
  match Sys.getenv_opt "HALTSQL_SKIP_DOCKER" with
  | Some ("1" | "true" | "yes") -> Error "HALTSQL_SKIP_DOCKER is set"
  | _ -> (
  match run_capture [ "info"; "--format"; "{{.ServerVersion}}" ] with
  | Ok v when v <> "" -> Ok ()
  | Ok _ -> Error "docker info returned nothing"
  | Error e -> Error ("docker is not available: " ^ e)
  | exception Unix.Unix_error (e, _, _) ->
      Error ("docker is not available: " ^ Unix.error_message e))

let ensure_image image =
  match run_capture [ "image"; "inspect"; "--format"; "{{.Id}}"; image ] with
  | Ok _ -> Ok ()
  | Error _ -> (
      match run_capture [ "pull"; image ] with
      | Ok _ -> Ok ()
      | Error e -> Error (Printf.sprintf "cannot pull %s: %s" image e))

let started : string list ref = ref []
let rm name = ignore (run_capture [ "rm"; "-f"; "-v"; name ])

let cleanup () =
  List.iter rm !started;
  started := []

let () = at_exit cleanup

(* [docker run -d --name NAME ARGS]; removes a stale container of the same name first. *)
let start ~name args =
  rm name;
  match run_capture ([ "run"; "-d"; "--name"; name ] @ args) with
  | Ok _ ->
      started := name :: !started;
      Ok ()
  | Error e -> Error (Printf.sprintf "docker run %s failed: %s" name e)

let logs name =
  match run_capture [ "logs"; "--tail"; "50"; name ] with Ok s | Error s -> s
