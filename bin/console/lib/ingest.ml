(* Audit ingestion: polls every audit.sources entry (files, directories, globs, S3, GCS)
   and adds new records to the Index. Owner: PR console/02-records.

   Files are tailed by byte offset: only complete lines are consumed, a file that shrinks
   or is replaced (new inode) is read again from the start. Objects in S3/GCS are
   immutable, so each object key is read exactly once. Each verifier's records get
   consecutive [seq] numbers in the order they are read (files in sorted order, objects in
   key order), which is the order the chain check in [Chain] walks. *)

open Lwt.Syntax
module Config = Console_config
module Http = Haltsql_cloud.Http

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"component\":\"ingest\",\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

(* ---- verifier names ---- *)

let strip_ext name =
  match String.rindex_opt name '.' with
  | Some i when i > 0 -> String.sub name 0 i
  | _ -> name

(** The host of an object-sink object name [<host>-<run>-<seq>-<sha256>.jsonl] (see
    {!Haltsql_cloud.Object_sink}), or [None] when the name does not have that shape. *)
let host_of_object_name key =
  let base = strip_ext (Filename.basename key) in
  let parts = String.split_on_char '-' base in
  let n = List.length parts in
  if n < 4 then None
  else
    let rev = List.rev parts in
    match rev with
    | sha :: seq :: run :: rest_rev ->
        let is_hex c = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') in
        let is_digit c = c >= '0' && c <= '9' in
        if
          String.length sha = 64
          && String.for_all is_hex sha && seq <> "" && String.for_all is_digit seq
          && run <> "" && rest_rev <> []
        then Some (String.concat "-" (List.rev rest_rev))
        else None
    | _ -> None

(** The verifier name for records read from [name] (a file path or object key): the
    configured name, or with [auto] the object-sink host, else the file's basename without
    its extension. *)
let infer_verifier ~configured name =
  if configured <> "auto" then configured
  else
    match host_of_object_name name with
    | Some h -> h
    | None -> strip_ext (Filename.basename name)

(* ---- per-source state ---- *)

type file_pos = {
  mutable offset : int;
  mutable line : int;  (** lines consumed so far (the next line is [line + 1]) *)
  mutable inode : int;
}

type obj = {
  list : unit -> (string list, string) result Lwt.t;
  get : string -> (string, string) result Lwt.t;
}

type kind = File of string | Objects of { uri : string; client : obj Lazy.t }

type source = {
  configured : string;  (** verifier name, or ["auto"] *)
  label : string;  (** the path or URI, for status *)
  kind : kind;
  files : (string, file_pos) Hashtbl.t;
  seen : (string, unit) Hashtbl.t;  (** object keys already read *)
  mutable records : int;
  mutable last_read : float option;
  mutable error : string option;
  mutable verifiers_seen : string list;
}

type t = { sources : source list; next_seq : (string, int) Hashtbl.t }

(* ---- S3 ---- *)

let split_on s sep =
  let n = String.length sep in
  let rec go acc i =
    let rec find j =
      if j + n > String.length s then None
      else if String.sub s j n = sep then Some j
      else find (j + 1)
    in
    match find i with
    | Some j -> go (String.sub s i (j - i) :: acc) (j + n)
    | None -> List.rev (String.sub s i (String.length s - i) :: acc)
  in
  go [] 0

let parse_bucket_url ~scheme u =
  let lp = String.length scheme in
  if String.length u <= lp || String.sub u 0 lp <> scheme then None
  else
    let rest = String.sub u lp (String.length u - lp) in
    let bucket, prefix =
      match String.index_opt rest '/' with
      | Some i ->
          (String.sub rest 0 i, String.sub rest (i + 1) (String.length rest - i - 1))
      | None -> (rest, "")
    in
    if bucket = "" then None else Some (bucket, prefix)

let max_object_bytes = 256 * 1024 * 1024

let s3_client ~env ~uri ~region ~endpoint : obj =
  let fail m =
    let e = Lwt.return (Error m) in
    { list = (fun () -> e); get = (fun _ -> e) }
  in
  match parse_bucket_url ~scheme:"s3://" uri with
  | None -> fail (Printf.sprintf "%s: expected s3://bucket/prefix" uri)
  | Some (bucket, prefix) -> (
      let endpoint_ok =
        match endpoint with
        | None -> Ok None
        | Some e -> (
            match Http.check_endpoint ~what:"audit.sources[].endpoint" e with
            | Ok _ ->
                let e =
                  if String.length e > 0 && e.[String.length e - 1] = '/' then
                    String.sub e 0 (String.length e - 1)
                  else e
                in
                Ok (Some e)
            | Error m -> Error m)
      in
      match endpoint_ok with
      | Error m -> fail m
      | Ok endpoint ->
          let region =
            match region with
            | Some r -> r
            | None -> Option.value ~default:"us-east-1" (env "AWS_REGION")
          in
          let base =
            match endpoint with
            | Some e -> Printf.sprintf "%s/%s" e bucket
            | None -> Printf.sprintf "https://%s.s3.%s.amazonaws.com" bucket region
          in
          let creds =
            Haltsql_cloud.Aws_creds.create ~env ~region
              Haltsql_cloud.Aws_creds.default_chain
          in
          let signed_get ?(max_body = 8 * 1024 * 1024) uri =
            let* c = Haltsql_cloud.Aws_creds.get creds in
            match c with
            | Error m -> Lwt.return (Error ("credentials: " ^ m))
            | Ok c -> (
                let headers =
                  Haltsql_cloud.Sigv4.sign ~s3:true c ~service:"s3" ~region
                    ~time:(Unix.gettimeofday ()) ~meth:"GET" ~uri ~headers:[] ~payload:""
                in
                let* r = Http.request ~timeout:60. ~max_body ~headers `GET uri in
                match r with
                | Error m -> Lwt.return (Error m)
                | Ok r when r.status >= 200 && r.status < 300 -> Lwt.return (Ok r.body)
                | Ok r ->
                    let code =
                      Option.value ~default:""
                        (Haltsql_cloud.Cloud_util.xml_tag r.body "Code")
                    in
                    Lwt.return
                      (Error (Printf.sprintf "S3 GET returned HTTP %d %s" r.status code)))
          in
          let list () =
            let rec go acc token pages =
              let q =
                [ ("list-type", [ "2" ]); ("prefix", [ prefix ]) ]
                @
                match token with
                | Some k -> [ ("continuation-token", [ k ]) ]
                | None -> []
              in
              let* r = signed_get (Uri.with_query (Uri.of_string (base ^ "/")) q) in
              match r with
              | Error e -> Lwt.return (Error ("listing " ^ uri ^ ": " ^ e))
              | Ok body -> (
                  let keys =
                    match split_on body "<Contents>" with
                    | [] | [ _ ] -> []
                    | _ :: chunks ->
                        List.filter_map
                          (fun ch -> Haltsql_cloud.Cloud_util.xml_tag ch "Key")
                          chunks
                  in
                  let acc = List.rev_append keys acc in
                  match
                    ( Haltsql_cloud.Cloud_util.xml_tag body "IsTruncated",
                      Haltsql_cloud.Cloud_util.xml_tag body "NextContinuationToken" )
                  with
                  | Some "true", Some k when pages < 100_000 -> go acc (Some k) (pages + 1)
                  | Some "true", _ ->
                      Lwt.return
                        (Error "S3 listing is truncated without a continuation token")
                  | _ -> Lwt.return (Ok (List.rev acc)))
            in
            go [] None 0
          in
          let get key =
            signed_get ~max_body:max_object_bytes
              (Uri.of_string (base ^ "/" ^ Http.pct_encode ~keep_slash:true key))
          in
          { list; get })

(* ---- GCS (JSON API) ---- *)

let gcs_client ~env ~uri : obj =
  let fail m =
    let e = Lwt.return (Error m) in
    { list = (fun () -> e); get = (fun _ -> e) }
  in
  match parse_bucket_url ~scheme:"gs://" uri with
  | None -> fail (Printf.sprintf "%s: expected gs://bucket/prefix" uri)
  | Some (bucket, prefix) -> (
      let base =
        match env "STORAGE_EMULATOR_HOST" with
        | Some h when String.trim h <> "" ->
            let h = String.trim h in
            if String.length h > 4 && String.sub h 0 4 = "http" then h else "http://" ^ h
        | _ -> "https://storage.googleapis.com"
      in
      match Haltsql_cloud.Gcp_auth.default ~env () with
      | Error m -> fail ("gcp credentials: " ^ m)
      | Ok auth ->
          let authed_get ?(max_body = 8 * 1024 * 1024) u =
            let* tok = Haltsql_cloud.Gcp_auth.token auth in
            match tok with
            | Error m -> Lwt.return (Error ("gcp auth: " ^ m))
            | Ok tok -> (
                let* r =
                  Http.request ~timeout:60. ~max_body
                    ~headers:[ ("authorization", "Bearer " ^ tok) ]
                    `GET u
                in
                match r with
                | Error m -> Lwt.return (Error m)
                | Ok r when r.status >= 200 && r.status < 300 -> Lwt.return (Ok r.body)
                | Ok r ->
                    if r.status = 401 then Haltsql_cloud.Gcp_auth.invalidate auth;
                    Lwt.return (Error (Printf.sprintf "GCS returned HTTP %d" r.status)))
          in
          let list () =
            let rec go acc token pages =
              let q =
                [ ("prefix", [ prefix ]) ]
                @ match token with Some k -> [ ("pageToken", [ k ]) ] | None -> []
              in
              let u =
                Uri.with_query
                  (Uri.of_string
                     (Printf.sprintf "%s/storage/v1/b/%s/o" base (Http.pct_encode bucket)))
                  q
              in
              let* r = authed_get u in
              match r with
              | Error e -> Lwt.return (Error ("listing " ^ uri ^ ": " ^ e))
              | Ok body -> (
                  match Yojson.Safe.from_string body with
                  | exception _ -> Lwt.return (Error "GCS listing is not JSON")
                  | j -> (
                      let names =
                        match Api.member "items" j with
                        | Some (`List items) ->
                            List.filter_map
                              (fun i ->
                                match Api.member "name" i with
                                | Some (`String n) -> Some n
                                | _ -> None)
                              items
                        | _ -> []
                      in
                      let acc = List.rev_append names acc in
                      match Api.member "nextPageToken" j with
                      | Some (`String k) when k <> "" && pages < 100_000 ->
                          go acc (Some k) (pages + 1)
                      | _ -> Lwt.return (Ok (List.rev acc))))
            in
            go [] None 0
          in
          let get name =
            authed_get ~max_body:max_object_bytes
              (Uri.of_string
                 (Printf.sprintf "%s/storage/v1/b/%s/o/%s?alt=media" base
                    (Http.pct_encode bucket) (Http.pct_encode name)))
          in
          { list; get })

(* ---- creating the state ---- *)

let create ?(env = Sys.getenv_opt) (cfg : Config.t) =
  let source (configured, src) =
    let kind, label =
      match src with
      | Config.Src_file f -> (File f, f)
      | Config.Src_s3 { uri; region; endpoint } ->
          (Objects { uri; client = lazy (s3_client ~env ~uri ~region ~endpoint) }, uri)
      | Config.Src_gcs { uri } ->
          (Objects { uri; client = lazy (gcs_client ~env ~uri) }, uri)
    in
    {
      configured;
      label;
      kind;
      files = Hashtbl.create 8;
      seen = Hashtbl.create 64;
      records = 0;
      last_read = None;
      error = None;
      verifiers_seen = [];
    }
  in
  { sources = List.map source cfg.audit.sources; next_seq = Hashtbl.create 8 }

(* ---- adding records ---- *)

let next_seq t verifier =
  let n = Option.value (Hashtbl.find_opt t.next_seq verifier) ~default:0 in
  Hashtbl.replace t.next_seq verifier (n + 1);
  n

(** Parses one line and adds it to the index; returns true when it was an audit record. *)
let add_line (ctx : Ctx.t) t src ~verifier ~location line =
  let line = String.trim line in
  if line = "" || line.[0] <> '{' then false
  else
    match Yojson.Safe.from_string line with
    | exception _ -> false
    | j -> (
        let now = Ctx.now () in
        (* Only audit records consume a seq. *)
        let seq = Option.value (Hashtbl.find_opt t.next_seq verifier) ~default:0 in
        match Index.entry_of_json ~verifier ~location ~seq ~now j with
        | None -> false
        | Some e ->
            ignore (next_seq t verifier);
            Index.add ctx.index e;
            src.records <- src.records + 1;
            if not (List.mem verifier src.verifiers_seen) then
              src.verifiers_seen <- src.verifiers_seen @ [ verifier ];
            true)

(* ---- files ---- *)

let is_audit_file name =
  Filename.check_suffix name ".jsonl" || Filename.check_suffix name ".log"

(* A glob in the basename only: '*' matches any run of characters, '?' one character. *)
let glob_match pat s =
  let n = String.length pat and m = String.length s in
  let rec go i j =
    if i = n then j = m
    else
      match pat.[i] with
      | '*' -> go (i + 1) j || (j < m && go i (j + 1))
      | '?' -> j < m && go (i + 1) (j + 1)
      | c -> j < m && s.[j] = c && go (i + 1) (j + 1)
  in
  go 0 0

let readdir_sorted d =
  match Sys.readdir d with
  | a ->
      Array.sort compare a;
      Array.to_list a
  | exception Sys_error _ -> []

(** The files a [file:] source names right now, sorted. *)
let expand_files path =
  let base = Filename.basename path in
  if String.contains base '*' || String.contains base '?' then
    let dir = Filename.dirname path in
    if not (Sys.file_exists dir && Sys.is_directory dir) then
      Error (Printf.sprintf "%s: no such directory" dir)
    else
      Ok
        (readdir_sorted dir
        |> List.filter (glob_match base)
        |> List.map (Filename.concat dir)
        |> List.filter (fun p -> try not (Sys.is_directory p) with Sys_error _ -> false))
  else if not (Sys.file_exists path) then Error (Printf.sprintf "%s: no such file" path)
  else if Sys.is_directory path then
    Ok
      (readdir_sorted path |> List.filter is_audit_file
      |> List.map (Filename.concat path)
      |> List.filter (fun p -> try not (Sys.is_directory p) with Sys_error _ -> false))
  else Ok [ path ]

let chunk = 4 * 1024 * 1024

(** Reads the new complete lines of [path] from its last offset. *)
let read_file (ctx : Ctx.t) t src path =
  let st = Unix.stat path in
  let pos =
    match Hashtbl.find_opt src.files path with
    | Some p -> p
    | None ->
        let p = { offset = 0; line = 0; inode = st.Unix.st_ino } in
        Hashtbl.replace src.files path p;
        p
  in
  if st.Unix.st_ino <> pos.inode || st.Unix.st_size < pos.offset then begin
    (* Rotated (replaced) or truncated: start over. *)
    pos.offset <- 0;
    pos.line <- 0;
    pos.inode <- st.Unix.st_ino
  end;
  let verifier = infer_verifier ~configured:src.configured path in
  let fd = Unix.openfile path [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 in
  Lwt.finalize
    (fun () ->
      let buf = Bytes.create chunk in
      let rec loop carry =
        ignore (Unix.lseek fd (pos.offset + String.length carry) Unix.SEEK_SET);
        let n = Unix.read fd buf 0 chunk in
        if n = 0 then Lwt.return_unit
        else
          let data = carry ^ Bytes.sub_string buf 0 n in
          match String.rindex_opt data '\n' with
          | None ->
              (* No complete line yet; keep reading unless the line is absurdly long. *)
              if String.length data > 64 * 1024 * 1024 then begin
                pos.offset <- pos.offset + String.length data;
                Lwt.return_unit
              end
              else loop data
          | Some last ->
              let complete = String.sub data 0 last in
              List.iter
                (fun l ->
                  pos.line <- pos.line + 1;
                  ignore
                    (add_line ctx t src ~verifier
                       ~location:(Printf.sprintf "%s#L%d" path pos.line)
                       l))
                (String.split_on_char '\n' complete);
              pos.offset <- pos.offset + last + 1;
              let rest = String.sub data (last + 1) (String.length data - last - 1) in
              let* () = Lwt.pause () in
              loop rest
      in
      loop "")
    (fun () ->
      (try Unix.close fd with _ -> ());
      Lwt.return_unit)

let poll_files ctx t src path =
  match expand_files path with
  | Error m -> Lwt.return (Error m)
  | Ok files ->
      let rec go = function
        | [] -> Lwt.return (Ok ())
        | f :: rest ->
            let* r =
              Lwt.catch
                (fun () ->
                  let* () = read_file ctx t src f in
                  Lwt.return (Ok ()))
                (fun e ->
                  Lwt.return
                    (Error
                       (match e with
                       | Unix.Unix_error (err, _, _) ->
                           Printf.sprintf "%s: %s" f (Unix.error_message err)
                       | e -> Printf.sprintf "%s: %s" f (Printexc.to_string e))))
            in
            (match r with Error m -> src.error <- Some m | Ok () -> ());
            go rest
      in
      go files

(* ---- objects ---- *)

let poll_objects ctx t src ~uri (client : obj) =
  let* keys = client.list () in
  match keys with
  | Error m -> Lwt.return (Error m)
  | Ok keys ->
      let fresh =
        List.filter
          (fun k -> Filename.check_suffix k ".jsonl" && not (Hashtbl.mem src.seen k))
          keys
        |> List.sort compare
      in
      let bucket_root =
        match String.index_from_opt uri 5 '/' with
        | Some i -> String.sub uri 0 (i + 1)
        | None -> uri ^ "/"
      in
      let rec go = function
        | [] -> Lwt.return (Ok ())
        | k :: rest -> (
            let* body = client.get k in
            match body with
            | Error m -> Lwt.return (Error (Printf.sprintf "reading %s: %s" k m))
            | Ok body ->
                let verifier = infer_verifier ~configured:src.configured k in
                List.iteri
                  (fun i l ->
                    ignore
                      (add_line ctx t src ~verifier
                         ~location:(Printf.sprintf "%s%s#L%d" bucket_root k (i + 1))
                         l))
                  (String.split_on_char '\n' body);
                Hashtbl.replace src.seen k ();
                let* () = Lwt.pause () in
                go rest)
      in
      go fresh

(* ---- status ---- *)

(* The per-source status published by the loop; private, read through [status]. *)
let status_key : Yojson.Safe.t Ctx.Key.t = Ctx.Key.create "ingest.status"

(** Per-source ingestion state ([`List] of objects with [source], [verifier], [verifiers],
    [records], [last_read], [error]); [`List []] before the loop starts. *)
let status (ctx : Ctx.t) = Option.value (Ctx.get ctx status_key) ~default:(`List [])

(** For tests only: replaces the published status without polling. *)
module Testing = struct
  let set_status (ctx : Ctx.t) j = Ctx.set ctx status_key j
end

let status_json t : Yojson.Safe.t =
  `List
    (List.map
       (fun s ->
         `Assoc
           [
             ("source", `String s.label);
             ("verifier", `String s.configured);
             ("verifiers", Api.strings s.verifiers_seen);
             ("records", `Int s.records);
             ("last_read", Api.opt_time s.last_read);
             ("error", Api.opt_string s.error);
           ])
       t.sources)

(** One pass over every source; then expires old entries and publishes status. *)
let poll_once (ctx : Ctx.t) t =
  let* () =
    Lwt_list.iter_s
      (fun src ->
        src.error <- None;
        let* r =
          Lwt.catch
            (fun () ->
              match src.kind with
              | File path -> poll_files ctx t src path
              | Objects { uri; client } -> poll_objects ctx t src ~uri (Lazy.force client))
            (fun e -> Lwt.return (Error (Printexc.to_string e)))
        in
        (match r with
        | Ok () -> if src.error = None then src.last_read <- Some (Ctx.now ())
        | Error m ->
            if src.error = None then src.error <- Some m;
            log "warning" "audit source %s: %s" src.label m);
        Lwt.return_unit)
      t.sources
  in
  Index.expire ctx.index ~now:(Ctx.now ());
  Ctx.set ctx status_key (status_json t);
  Lwt.return_unit

let routes : Router.route list = []

(** Polls every [audit.poll_seconds] forever; errors are logged per iteration. *)
let start (ctx : Ctx.t) : unit Lwt.t =
  if ctx.config.audit.sources = [] then Lwt.return_unit
  else
    let t = create ctx.config in
    Ctx.set ctx status_key (status_json t);
    let period = float_of_int (max 1 ctx.config.audit.poll_seconds) in
    let rec loop () =
      let* () =
        Lwt.catch
          (fun () -> poll_once ctx t)
          (fun e ->
            log "error" "ingest poll failed: %s" (Printexc.to_string e);
            Lwt.return_unit)
      in
      let* () = Lwt_unix.sleep period in
      loop ()
    in
    loop ()
