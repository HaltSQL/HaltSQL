module Config = Haltsql_load.Config

let describe what = function
  | Config.Pem_path p -> Printf.sprintf "%s (%s)" what p
  | Config.Pem_inline _ -> Printf.sprintf "%s (inline PEM)" what

let read ~what = function
  | Config.Pem_inline s -> Ok s
  | Config.Pem_path p as pem -> (
      match In_channel.with_open_bin p In_channel.input_all with
      | s -> Ok s
      | exception Sys_error m ->
          Error (Printf.sprintf "%s: cannot read: %s" (describe what pem) m))

let certificates ~what pem =
  Result.bind (read ~what pem) (fun s ->
      match X509.Certificate.decode_pem_multiple s with
      | Ok [] -> Error (describe what pem ^ ": no certificate found")
      | Ok l -> Ok l
      | Error (`Msg _) -> Error (describe what pem ^ ": not a valid PEM certificate"))

let private_key ~what pem =
  Result.bind (read ~what pem) (fun s ->
      match X509.Private_key.decode_pem s with
      | Ok k -> Ok k
      | Error (`Msg _) -> Error (describe what pem ^ ": not a valid PEM private key"))
