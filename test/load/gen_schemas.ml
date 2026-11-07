(* Writes Haltsql_load.Schemas.all into the directory given as argument. *)
let () =
  let dir = if Array.length Sys.argv > 1 then Sys.argv.(1) else "schemas" in
  if not (Sys.file_exists dir) then Sys.mkdir dir 0o755;
  List.iter
    (fun (name, schema) ->
      let path = Filename.concat dir name in
      let oc = open_out_bin path in
      output_string oc (Yojson.Safe.pretty_to_string schema ^ "\n");
      close_out oc;
      print_endline ("wrote " ^ path))
    Haltsql_load.Schemas.all
