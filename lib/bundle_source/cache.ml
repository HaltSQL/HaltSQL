module B = Haltsql_bundle

type entry = {
  source : string;
  bundle : string;
  signature : string;
  revision : string option;
}

let ( let* ) = Result.bind
let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let dir_for ~cache_dir ~source =
  Filename.concat cache_dir ("source-" ^ String.sub (sha256_hex source) 0 16)

let state_file dir = Filename.concat dir "state.json"
let max_state_bytes = 64 * 1024
let unix_msg e = Unix.error_message e

let rec mkdir_p dir =
  if dir <> "" && dir <> "/" && dir <> "." && not (Sys.file_exists dir) then begin
    mkdir_p (Filename.dirname dir);
    try Unix.mkdir dir 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ()
  end

let fsync_dir dir =
  match Unix.openfile dir [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 with
  | exception Unix.Unix_error _ -> ()
  | fd -> (
      (try Unix.fsync fd with Unix.Unix_error _ -> ());
      try Unix.close fd with Unix.Unix_error _ -> ())

let tmp_counter = ref 0

let write_atomic ?(perm = 0o600) path contents =
  let dir = Filename.dirname path in
  incr tmp_counter;
  let tmp =
    Filename.concat dir
      (Printf.sprintf ".%s.tmp.%d.%d" (Filename.basename path) (Unix.getpid ())
         !tmp_counter)
  in
  match
    let fd =
      Unix.openfile tmp [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL; Unix.O_CLOEXEC ] perm
    in
    Fun.protect
      ~finally:(fun () -> try Unix.close fd with Unix.Unix_error _ -> ())
      (fun () ->
        let b = Bytes.unsafe_of_string contents in
        let n = Bytes.length b in
        let rec go off = if off < n then go (off + Unix.write fd b off (n - off)) in
        go 0;
        Unix.fsync fd);
    Unix.rename tmp path;
    fsync_dir dir
  with
  | () -> Ok ()
  | exception Unix.Unix_error (e, _, _) ->
      (try Unix.unlink tmp with Unix.Unix_error _ -> ());
      Error (Printf.sprintf "cannot write %s: %s" path (unix_msg e))

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let valid_bundle_file f =
  String.length f = 64 + String.length ".haltsqlbundle"
  && String.ends_with ~suffix:".haltsqlbundle" f
  && String.for_all
       (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
       (String.sub f 0 64)

let read ~max ~what path =
  Result.map_error B.error_to_string (B.read_file ~max_bytes:max ~what path)

let load ~dir ~source =
  let sf = state_file dir in
  if not (Sys.file_exists sf) then Ok None
  else
    let* text = read ~max:max_state_bytes ~what:"cache state" sf in
    match Yojson.Safe.from_string text with
    | exception Yojson.Json_error _ -> Error ("corrupt cache state " ^ sf)
    | `Assoc kvs -> (
        let str k =
          match List.assoc_opt k kvs with Some (`String s) -> Some s | _ -> None
        in
        match (List.assoc_opt "format" kvs, str "source", str "bundle") with
        | Some (`Int 1), Some s, _ when s <> source -> Ok None
        | Some (`Int 1), Some _, Some f when valid_bundle_file f ->
            let bpath = Filename.concat dir f in
            let* bundle = read ~max:B.default_max_bytes ~what:"cached bundle" bpath in
            let* signature =
              read ~max:B.max_signature_bytes ~what:"cached signature"
                (B.signature_path bpath)
            in
            if sha256_hex bundle ^ ".haltsqlbundle" <> f then
              Error
                ("cached bundle " ^ bpath
               ^ " does not match its file name (corrupt cache)")
            else Ok (Some { source; bundle; signature; revision = str "revision" })
        | _ -> Error ("corrupt cache state " ^ sf))
    | _ -> Error ("corrupt cache state " ^ sf)

let store ~dir e =
  match mkdir_p dir with
  | exception Unix.Unix_error (err, _, _) ->
      Error (Printf.sprintf "cannot create cache directory %s: %s" dir (unix_msg err))
  | () ->
      let f = sha256_hex e.bundle ^ ".haltsqlbundle" in
      let bpath = Filename.concat dir f in
      let* () = write_atomic bpath e.bundle in
      let* () = write_atomic (B.signature_path bpath) e.signature in
      let state =
        `Assoc
          ([ ("format", `Int 1); ("source", `String e.source); ("bundle", `String f) ]
          @ match e.revision with Some r -> [ ("revision", `String r) ] | None -> [])
      in
      let* () = write_atomic (state_file dir) (Yojson.Safe.to_string state ^ "\n") in
      (* Remove superseded bundles and leftover temporary files. *)
      (match Sys.readdir dir with
      | exception Sys_error _ -> ()
      | names ->
          Array.iter
            (fun n ->
              let stale =
                (String.ends_with ~suffix:".haltsqlbundle" n && n <> f)
                || (String.ends_with ~suffix:".haltsqlbundle.sig" n && n <> f ^ ".sig")
                || String.length n > 0
                   && n.[0] = '.'
                   && contains n ".tmp."
                   &&
                   (* another process may be writing it: only old leftovers *)
                   match Unix.stat (Filename.concat dir n) with
                   | st -> Unix.gettimeofday () -. st.st_mtime > 600.
                   | exception Unix.Unix_error _ -> false
              in
              if stale then
                try Unix.unlink (Filename.concat dir n) with Unix.Unix_error _ -> ())
            names);
      Ok ()
