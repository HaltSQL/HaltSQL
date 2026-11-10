(* Audit ingestion: polls every audit.sources entry (files, directories, globs, S3, GCS)
   and adds new records to the Index. Owner: PR console/02-records.

   Files are tracked by inode, not by path, and tailed by byte offset through a
   descriptor kept open between polls: only complete lines are consumed. Each poll first
   drains every tracked file through its own descriptor (so the unread tail of a file
   that was renamed away by rotation is still read, under the path it was first seen
   at), then looks for files it does not know yet. A file that shrinks, or whose first
   line changed (copytruncate followed by new writes), is read again from the start and
   a gap is recorded for the chain check ({!is_gap}): records may have been lost. A file
   that is already tracked (by this or an earlier source) is never read twice, so a glob
   that also matches rotated names, or two sources naming the same file, do not
   duplicate records; a record identical to one already indexed for the same verifier is
   skipped too. File I/O runs through Lwt_unix jobs and directory listing in a
   preemptive thread, so a slow mount does not block the event loop.

   Objects in S3/GCS are immutable, so each object key is read once. Listings start at
   the [YYYY/MM/DD/HH/] partition of the retention start every [relist_minutes], and at
   the partition of an hour ago in between, so neither the listing nor the set of keys
   already read grows beyond the retention window. An object that cannot be read is
   retried on later polls while the objects of other hosts are still read; after
   [object_attempts] failures it is skipped, reported in status, and a gap is recorded.
   A failing source backs off exponentially; object sources are polled concurrently.

   Each verifier's records get consecutive [seq] numbers in the order they are read
   (files in name order, objects in key order). *)

open Lwt.Syntax
module Config = Console_config
module Http = Haltsql_cloud.Http

(** A JSON log line on stderr for [component]. *)
let log_component component level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"component\":%S,\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level component
        (Yojson.Safe.to_string (`String m)))
    fmt

let log level fmt = log_component "ingest" level fmt

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

(* ---- limits ---- *)

type limits = {
  max_object_bytes : int;
  max_line_bytes : int;
  timeout : float;
  relist : float;  (** seconds between full listings *)
  attempts : int;
  retention : float;
}

let limits_of (cfg : Config.t) =
  let mb n = max 1 n * 1024 * 1024 in
  {
    max_object_bytes = mb cfg.audit.max_object_mb;
    max_line_bytes = mb cfg.audit.max_line_mb;
    timeout = float_of_int (max 1 cfg.audit.request_timeout_seconds);
    relist = 60. *. float_of_int (max 1 cfg.audit.relist_minutes);
    attempts = max 1 cfg.audit.object_attempts;
    retention = 3600. *. float_of_int cfg.audit.retention_hours;
  }

let max_pages = 100_000

(* ---- per-source state ---- *)

type file_pos = {
  path : string;  (** where the file was first seen; locations use it *)
  key : int * int;  (** (device, inode) *)
  verifier : string;
  mutable fd : Lwt_unix.file_descr option;
  mutable offset : int;  (** end of the last consumed line *)
  mutable line : int;  (** lines consumed so far (the next line is [line + 1]) *)
  mutable head : string;  (** the first line (up to 4 KiB), to detect copytruncate *)
  mutable skipping : bool;  (** inside a line longer than [max_line_bytes] *)
  mutable missing : int;  (** consecutive polls the inode was not found *)
}

type obj = {
  list : start_after:string option -> (string list, string) result Lwt.t;
  get : string -> (string, string) result Lwt.t;
}

type kind =
  | File of string
  | Objects of {
      uri : string;
      make : unit -> (obj, string) result;
      stamp : unit -> string option;  (** changes when the credentials should be re-read *)
    }

type source = {
  configured : string;  (** verifier name, or ["auto"] *)
  label : string;  (** the path or URI, for status *)
  kind : kind;
  files : (int * int, file_pos) Hashtbl.t;
  mutable tracked : file_pos list;  (** in discovery order *)
  seen : (string, unit) Hashtbl.t;  (** object keys already read, within retention *)
  failures : (string, int) Hashtbl.t;  (** object key -> failed reads *)
  mutable skipped : (string * string) list;  (** objects given up on, newest first *)
  mutable client : (obj * string option) option;
  mutable last_full_list : float;
  mutable failing : int;  (** consecutive failed polls *)
  mutable next_poll : float;
  mutable overlaps : string list;  (** files left to an earlier source *)
  mutable records : int;
  mutable last_read : float option;
  mutable error : string option;
  mutable verifiers_seen : string list;
}

type t = {
  sources : source list;
  next_seq : (string, int) Hashtbl.t;
  gaps : (string, (int, unit) Hashtbl.t) Hashtbl.t;  (** verifier -> seqs after a gap *)
  claims : (int * int, string) Hashtbl.t;  (** file -> label of the source reading it *)
  limits : limits;
}

(* ---- gaps ---- *)

let gaps_key : (string, (int, unit) Hashtbl.t) Hashtbl.t Ctx.Key.t =
  Ctx.Key.create "ingest.gaps"

(** [is_gap ctx verifier seq]: ingestion may have lost records right before [seq]. *)
let is_gap (ctx : Ctx.t) verifier =
  match Option.bind (Ctx.get ctx gaps_key) (fun g -> Hashtbl.find_opt g verifier) with
  | None -> fun _ -> false
  | Some h -> Hashtbl.mem h

let mark_gap t verifier =
  let seq = Option.value (Hashtbl.find_opt t.next_seq verifier) ~default:0 in
  let h =
    match Hashtbl.find_opt t.gaps verifier with
    | Some h -> h
    | None ->
        let h = Hashtbl.create 4 in
        Hashtbl.replace t.gaps verifier h;
        h
  in
  Hashtbl.replace h seq ()

(* ---- S3 ---- *)

(* Index of [sep] in [s] at or after [from], without allocating. *)
let find_sub s sep from =
  let n = String.length sep and m = String.length s in
  let rec at i j = j = n || (s.[i + j] = sep.[j] && at i (j + 1)) in
  let rec go i = if i + n > m then None else if at i 0 then Some i else go (i + 1) in
  go from

let split_on s sep =
  let n = String.length sep in
  let rec go acc i =
    match find_sub s sep i with
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

let page_cap uri =
  Error (Printf.sprintf "listing %s stopped after %d pages" uri max_pages)

let s3_client ~env ~limits ~uri ~region ~endpoint : (obj, string) result =
  match parse_bucket_url ~scheme:"s3://" uri with
  | None -> Error (Printf.sprintf "%s: expected s3://bucket/prefix" uri)
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
      | Error m -> Error m
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
                let* r =
                  Http.request ~timeout:limits.timeout ~max_body ~headers `GET uri
                in
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
          let list ~start_after =
            let rec go acc token pages =
              let q =
                [ ("list-type", [ "2" ]); ("prefix", [ prefix ]) ]
                @ (match (token, start_after) with
                  | None, Some k -> [ ("start-after", [ k ]) ]
                  | _ -> [])
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
                  | Some "true", Some _ when pages + 1 >= max_pages ->
                      Lwt.return (page_cap uri)
                  | Some "true", Some k -> go acc (Some k) (pages + 1)
                  | Some "true", None ->
                      Lwt.return
                        (Error "S3 listing is truncated without a continuation token")
                  | _ -> Lwt.return (Ok (List.rev acc)))
            in
            go [] None 0
          in
          let get key =
            signed_get ~max_body:limits.max_object_bytes
              (Uri.of_string (base ^ "/" ^ Http.pct_encode ~keep_slash:true key))
          in
          Ok { list; get })

(* ---- GCS (JSON API) ---- *)

let gcs_client ~env ~limits ~uri : (obj, string) result =
  match parse_bucket_url ~scheme:"gs://" uri with
  | None -> Error (Printf.sprintf "%s: expected gs://bucket/prefix" uri)
  | Some (bucket, prefix) -> (
      (* With an emulator, its address is checked like any other endpoint (http only on
         loopback) and no credentials are sent to it. *)
      let target =
        match env "STORAGE_EMULATOR_HOST" with
        | Some h when String.trim h <> "" -> (
            let h = String.trim h in
            let h =
              if
                String.starts_with ~prefix:"http://" h
                || String.starts_with ~prefix:"https://" h
              then h
              else "http://" ^ h
            in
            let h =
              if String.ends_with ~suffix:"/" h then String.sub h 0 (String.length h - 1)
              else h
            in
            match Http.check_endpoint ~what:"STORAGE_EMULATOR_HOST" h with
            | Ok _ -> Ok (h, None)
            | Error m -> Error m)
        | _ -> (
            match Haltsql_cloud.Gcp_auth.default ~env () with
            | Error m -> Error ("gcp credentials: " ^ m)
            | Ok auth -> Ok ("https://storage.googleapis.com", Some auth))
      in
      match target with
      | Error m -> Error m
      | Ok (base, auth) ->
          let authed_get ?(max_body = 8 * 1024 * 1024) u =
            let* headers =
              match auth with
              | None -> Lwt.return (Ok [])
              | Some a -> (
                  let* tok = Haltsql_cloud.Gcp_auth.token a in
                  match tok with
                  | Error m -> Lwt.return (Error ("gcp auth: " ^ m))
                  | Ok tok -> Lwt.return (Ok [ ("authorization", "Bearer " ^ tok) ]))
            in
            match headers with
            | Error m -> Lwt.return (Error m)
            | Ok headers -> (
                let* r = Http.request ~timeout:limits.timeout ~max_body ~headers `GET u in
                match r with
                | Error m -> Lwt.return (Error m)
                | Ok r when r.status >= 200 && r.status < 300 -> Lwt.return (Ok r.body)
                | Ok r ->
                    (if r.status = 401 then
                       match auth with
                       | Some a -> Haltsql_cloud.Gcp_auth.invalidate a
                       | None -> ());
                    Lwt.return (Error (Printf.sprintf "GCS returned HTTP %d" r.status)))
          in
          let list ~start_after =
            let rec go acc token pages =
              let q =
                [ ("prefix", [ prefix ]) ]
                @ (match start_after with
                  | Some k -> [ ("startOffset", [ k ]) ]
                  | None -> [])
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
                      | Some (`String k) when k <> "" && pages + 1 >= max_pages ->
                          Lwt.return (page_cap uri)
                      | Some (`String k) when k <> "" -> go acc (Some k) (pages + 1)
                      | _ -> Lwt.return (Ok (List.rev acc))))
            in
            go [] None 0
          in
          let get name =
            authed_get ~max_body:limits.max_object_bytes
              (Uri.of_string
                 (Printf.sprintf "%s/storage/v1/b/%s/o/%s?alt=media" base
                    (Http.pct_encode bucket) (Http.pct_encode name)))
          in
          Ok { list; get })

(* The identity of the file named by [var], so a rotated key file is re-read. *)
let file_stamp env var =
  match env var with
  | Some f when String.trim f <> "" -> (
      match Unix.stat f with
      | st -> Some (Printf.sprintf "%s:%.0f:%d" f st.Unix.st_mtime st.Unix.st_size)
      | exception Unix.Unix_error _ -> Some (f ^ ":missing"))
  | _ -> None

(* ---- creating the state ---- *)

let create ?(env = Sys.getenv_opt) (cfg : Config.t) =
  let limits = limits_of cfg in
  let source (configured, src) =
    let kind, label =
      match src with
      | Config.Src_file f -> (File f, f)
      | Config.Src_s3 { uri; region; endpoint } ->
          ( Objects
              {
                uri;
                make = (fun () -> s3_client ~env ~limits ~uri ~region ~endpoint);
                stamp = (fun () -> None);
              },
            uri )
      | Config.Src_gcs { uri } ->
          ( Objects
              {
                uri;
                make = (fun () -> gcs_client ~env ~limits ~uri);
                stamp =
                  (fun () ->
                    Some
                      (Option.value (env "STORAGE_EMULATOR_HOST") ~default:""
                      ^ "|"
                      ^ Option.value
                          (file_stamp env "GOOGLE_APPLICATION_CREDENTIALS")
                          ~default:""));
              },
            uri )
    in
    {
      configured;
      label;
      kind;
      files = Hashtbl.create 8;
      tracked = [];
      seen = Hashtbl.create 64;
      failures = Hashtbl.create 4;
      skipped = [];
      client = None;
      last_full_list = neg_infinity;
      failing = 0;
      next_poll = neg_infinity;
      overlaps = [];
      records = 0;
      last_read = None;
      error = None;
      verifiers_seen = [];
    }
  in
  {
    sources = List.map source cfg.audit.sources;
    next_seq = Hashtbl.create 8;
    gaps = Hashtbl.create 4;
    claims = Hashtbl.create 16;
    limits;
  }

(* ---- adding records ---- *)

(** Parses one line and adds it to the index; returns true when it was a new audit record.
    A record identical to one already indexed for the same verifier (a rotated copy read
    again) is skipped and consumes no [seq]. *)
let add_line (ctx : Ctx.t) t src ~verifier ~location line =
  let line = String.trim line in
  if line = "" || line.[0] <> '{' then false
  else
    match Yojson.Safe.from_string line with
    | exception _ -> false
    | j -> (
        let now = Ctx.now () in
        let seq = Option.value (Hashtbl.find_opt t.next_seq verifier) ~default:0 in
        match Index.entry_of_json ~verifier ~location ~seq ~now j with
        | None -> false
        | Some e -> (
            match Index.find ctx.index e.request_id with
            | Some old when old.verifier = verifier && old.raw = e.raw -> false
            | _ ->
                Hashtbl.replace t.next_seq verifier (seq + 1);
                Index.add ctx.index e;
                src.records <- src.records + 1;
                if not (List.mem verifier src.verifiers_seen) then
                  src.verifiers_seen <- src.verifiers_seen @ [ verifier ];
                true))

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

(** The files a [file:] source names right now, sorted. Blocking: the poll calls it
    through {!expand_files_lwt}. *)
let expand_files path =
  let base = Filename.basename path in
  let regular p = try not (Sys.is_directory p) with Sys_error _ -> false in
  if String.contains base '*' || String.contains base '?' then
    let dir = Filename.dirname path in
    if not (Sys.file_exists dir && Sys.is_directory dir) then
      Error (Printf.sprintf "%s: no such directory" dir)
    else
      Ok
        (readdir_sorted dir
        |> List.filter (glob_match base)
        |> List.map (Filename.concat dir)
        |> List.filter regular)
  else if not (Sys.file_exists path) then Error (Printf.sprintf "%s: no such file" path)
  else if Sys.is_directory path then
    Ok
      (readdir_sorted path |> List.filter is_audit_file
      |> List.map (Filename.concat path)
      |> List.filter regular)
  else Ok [ path ]

(** {!expand_files} in a preemptive thread, off the event loop. *)
let expand_files_lwt path =
  Lwt.catch
    (fun () -> Lwt_preemptive.detach expand_files path)
    (fun e -> Lwt.return (Error (Printf.sprintf "%s: %s" path (Printexc.to_string e))))

let chunk = 256 * 1024
let head_bytes = 4096

(* Index of the first '\n' in [buf] within [i, n). *)
let find_nl buf i n =
  let rec go j =
    if j >= n then None else if Bytes.get buf j = '\n' then Some j else go (j + 1)
  in
  go i

let rec really_read fd buf off len =
  if len = 0 then Lwt.return off
  else
    let* n = Lwt_unix.read fd buf off len in
    if n = 0 then Lwt.return off else really_read fd buf (off + n) (len - n)

(* The first [n] bytes of the file. *)
let read_head fd n =
  let* _ = Lwt_unix.lseek fd 0 Unix.SEEK_SET in
  let buf = Bytes.create n in
  let* got = really_read fd buf 0 n in
  Lwt.return (Bytes.sub_string buf 0 got)

(** Reads the complete lines of [pos] after its offset, yielding after every [chunk]
    bytes. A line longer than [max_line_bytes] is skipped (and still counted). *)
let read_lines (ctx : Ctx.t) t src pos fd =
  let max_line = t.limits.max_line_bytes in
  let* _ = Lwt_unix.lseek fd pos.offset Unix.SEEK_SET in
  let buf = Bytes.create chunk in
  let carry = Buffer.create 256 in
  let abs = ref pos.offset in
  let rec loop () =
    let* n = Lwt_unix.read fd buf 0 chunk in
    if n = 0 then Lwt.return_unit
    else begin
      let i = ref 0 in
      while !i < n do
        match find_nl buf !i n with
        | Some j ->
            if pos.skipping then begin
              pos.skipping <- false;
              pos.line <- pos.line + 1
            end
            else begin
              Buffer.add_subbytes carry buf !i (j - !i);
              let l = Buffer.contents carry in
              Buffer.clear carry;
              if pos.offset = 0 && pos.line = 0 then
                pos.head <- String.sub (l ^ "\n") 0 (min head_bytes (String.length l + 1));
              pos.line <- pos.line + 1;
              ignore
                (add_line ctx t src ~verifier:pos.verifier
                   ~location:(Printf.sprintf "%s#L%d" pos.path pos.line)
                   l)
            end;
            abs := !abs + (j - !i) + 1;
            pos.offset <- !abs;
            i := j + 1
        | None ->
            abs := !abs + (n - !i);
            if pos.skipping then pos.offset <- !abs
            else begin
              Buffer.add_subbytes carry buf !i (n - !i);
              if Buffer.length carry > max_line then begin
                log "warning" "%s: line %d is longer than %d bytes; skipped" pos.path
                  (pos.line + 1) max_line;
                pos.skipping <- true;
                pos.offset <- !abs;
                Buffer.clear carry
              end
            end;
            i := n
      done;
      let* () = Lwt.pause () in
      loop ()
    end
  in
  loop ()

(* Reads what was appended to a tracked file; starts over (and records a gap) when it
   was truncated or rewritten in place. *)
let drain ctx t src pos =
  match pos.fd with
  | None -> Lwt.return_unit
  | Some fd ->
      let* st = Lwt_unix.fstat fd in
      let* rewritten =
        if st.Unix.st_size < pos.offset then Lwt.return true
        else if pos.offset > 0 && pos.head <> "" then
          let* h = read_head fd (String.length pos.head) in
          Lwt.return (h <> pos.head)
        else Lwt.return false
      in
      if rewritten then begin
        log "info" "%s was truncated or rewritten; reading it again from the start"
          pos.path;
        pos.offset <- 0;
        pos.line <- 0;
        pos.head <- "";
        pos.skipping <- false;
        mark_gap t pos.verifier
      end;
      if st.Unix.st_size > pos.offset then read_lines ctx t src pos fd
      else Lwt.return_unit

let close_pos t src pos =
  (match pos.fd with
  | Some fd ->
      Lwt.async (fun () ->
          Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit))
  | None -> ());
  pos.fd <- None;
  Hashtbl.remove src.files pos.key;
  (match Hashtbl.find_opt t.claims pos.key with
  | Some l when l = src.label -> Hashtbl.remove t.claims pos.key
  | _ -> ());
  src.tracked <- List.filter (fun p -> p != pos) src.tracked

let describe_exn path = function
  | Unix.Unix_error (err, _, _) -> Printf.sprintf "%s: %s" path (Unix.error_message err)
  | e -> Printf.sprintf "%s: %s" path (Printexc.to_string e)

let poll_files ctx t src pattern =
  let guard path f =
    Lwt.catch f (fun e ->
        if src.error = None then src.error <- Some (describe_exn path e);
        Lwt.return_unit)
  in
  (* 1. Every tracked file, through its own descriptor, in name order. *)
  let* () =
    Lwt_list.iter_s
      (fun pos -> guard pos.path (fun () -> drain ctx t src pos))
      (List.stable_sort (fun a b -> compare a.path b.path) src.tracked)
  in
  (* 2. Files not seen before. *)
  let* expanded = expand_files_lwt pattern in
  match expanded with
  | Error m -> Lwt.return (Error m)
  | Ok paths ->
      let present = Hashtbl.create 16 in
      let* () =
        Lwt_list.iter_s
          (fun path ->
            guard path (fun () ->
                let* st = Lwt_unix.stat path in
                let key = (st.Unix.st_dev, st.Unix.st_ino) in
                Hashtbl.replace present key ();
                if Hashtbl.mem src.files key then Lwt.return_unit
                else
                  match Hashtbl.find_opt t.claims key with
                  | Some other when other <> src.label ->
                      if not (List.mem path src.overlaps) then begin
                        log "warning" "%s is already read by audit source %s; skipped"
                          path other;
                        src.overlaps <- src.overlaps @ [ path ]
                      end;
                      Lwt.return_unit
                  | _ ->
                      let* fd =
                        Lwt_unix.openfile path [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0
                      in
                      let pos =
                        {
                          path;
                          key;
                          verifier = infer_verifier ~configured:src.configured path;
                          fd = Some fd;
                          offset = 0;
                          line = 0;
                          head = "";
                          skipping = false;
                          missing = 0;
                        }
                      in
                      Hashtbl.replace src.files key pos;
                      Hashtbl.replace t.claims key src.label;
                      src.tracked <- src.tracked @ [ pos ];
                      read_lines ctx t src pos fd))
          paths
      in
      (* A file gone from every matching path for two polls (renamed away or deleted) is
         closed; the extra poll catches writes that land just after a rotation. *)
      List.iter
        (fun pos ->
          if Hashtbl.mem present pos.key then pos.missing <- 0
          else begin
            pos.missing <- pos.missing + 1;
            if pos.missing >= 2 then close_pos t src pos
          end)
        src.tracked;
      Lwt.return (Ok ())

(* ---- objects ---- *)

(** [prefix] followed by the [YYYY/MM/DD/HH/] partition of [time]: object-sink keys sort
    by the hour they were written. [None] when the prefix does not end at a path segment
    (the partition would not follow it directly). *)
let partition_start ~prefix time =
  if prefix <> "" && not (String.ends_with ~suffix:"/" prefix) then None
  else
    let tm = Unix.gmtime (Float.max 0. time) in
    Some
      (Printf.sprintf "%s%04d/%02d/%02d/%02d/" prefix (tm.tm_year + 1900) (tm.tm_mon + 1)
         tm.tm_mday tm.tm_hour)

(* Adds the lines of an object body, yielding every 1000 lines. *)
let add_object_lines ctx t src ~verifier ~location_of body =
  let n = String.length body in
  let rec go i lineno =
    if i >= n then Lwt.return_unit
    else
      let j = match String.index_from_opt body i '\n' with Some j -> j | None -> n in
      ignore
        (add_line ctx t src ~verifier ~location:(location_of lineno)
           (String.sub body i (j - i)));
      if lineno mod 1000 = 0 then
        let* () = Lwt.pause () in
        go (j + 1) (lineno + 1)
      else go (j + 1) (lineno + 1)
  in
  go 0 1

let object_origin k =
  match host_of_object_name k with Some h -> h | None -> Filename.dirname k

let poll_objects ctx t src ~uri (client : obj) =
  let now = Ctx.now () in
  let full = now -. src.last_full_list >= t.limits.relist in
  let bucket_root, prefix =
    match String.index_from_opt uri 5 '/' with
    | Some i ->
        (String.sub uri 0 (i + 1), String.sub uri (i + 1) (String.length uri - i - 1))
    | None -> (uri ^ "/", "")
  in
  let boundary =
    partition_start ~prefix (if full then now -. t.limits.retention else now -. 3600.)
  in
  let* keys = client.list ~start_after:boundary in
  match keys with
  | Error m -> Lwt.return (Error m)
  | Ok keys ->
      if full then begin
        src.last_full_list <- now;
        (* keys before the retention start are not listed again *)
        match boundary with
        | Some b ->
            Hashtbl.filter_map_inplace
              (fun k () -> if String.compare k b < 0 then None else Some ())
              src.seen
        | None -> ()
      end;
      let fresh =
        List.filter
          (fun k -> Filename.check_suffix k ".jsonl" && not (Hashtbl.mem src.seen k))
          keys
        |> List.sort compare
      in
      (* An object that fails holds back the later objects of the same host (to keep
         each chain in order) but not those of other hosts. *)
      let blocked = Hashtbl.create 4 in
      let first_error = ref None in
      let rec go = function
        | [] -> Lwt.return_unit
        | k :: rest when Hashtbl.mem blocked (object_origin k) -> go rest
        | k :: rest -> (
            let verifier = infer_verifier ~configured:src.configured k in
            let* body = client.get k in
            match body with
            | Ok body ->
                Hashtbl.remove src.failures k;
                let* () =
                  add_object_lines ctx t src ~verifier
                    ~location_of:(Printf.sprintf "%s%s#L%d" bucket_root k)
                    body
                in
                Hashtbl.replace src.seen k ();
                let* () = Lwt.pause () in
                go rest
            | Error m ->
                let n = 1 + Option.value (Hashtbl.find_opt src.failures k) ~default:0 in
                if n >= t.limits.attempts then begin
                  Hashtbl.remove src.failures k;
                  Hashtbl.replace src.seen k ();
                  src.skipped <- List.filteri (fun i _ -> i < 20) ((k, m) :: src.skipped);
                  mark_gap t verifier;
                  log "error" "skipping %s%s after %d failed reads: %s" bucket_root k n m;
                  if !first_error = None then
                    first_error :=
                      Some (Printf.sprintf "skipped %s after %d failed reads: %s" k n m)
                end
                else begin
                  Hashtbl.replace src.failures k n;
                  Hashtbl.replace blocked (object_origin k) ();
                  if !first_error = None then
                    first_error := Some (Printf.sprintf "reading %s: %s" k m)
                end;
                go rest)
      in
      let* () = go fresh in
      Lwt.return (match !first_error with Some m -> Error m | None -> Ok ())

(* ---- status ---- *)

(* The per-source status published by the loop; private, read through [status]. *)
let status_key : Yojson.Safe.t Ctx.Key.t = Ctx.Key.create "ingest.status"

(** Per-source ingestion state ([`List] of objects with [source], [verifier], [verifiers],
    [records], [last_read], [error], [skipped_objects], [overlaps], [next_poll]);
    [`List []] before the loop starts. *)
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
             ( "skipped_objects",
               `List
                 (List.map
                    (fun (k, m) -> `Assoc [ ("key", `String k); ("error", `String m) ])
                    s.skipped) );
             ("overlaps", Api.strings s.overlaps);
             ( "next_poll",
               if s.failing > 0 then Api.opt_time (Some s.next_poll) else `Null );
           ])
       t.sources)

(* The object client, rebuilt when missing or when its credentials changed; a failure to
   build one is not remembered. *)
let client_of src ~make ~stamp =
  let st = stamp () in
  match src.client with
  | Some (c, st') when st' = st -> Ok c
  | _ -> (
      match make () with
      | Ok c ->
          src.client <- Some (c, st);
          Ok c
      | Error m ->
          src.client <- None;
          Error m)

let poll_source (ctx : Ctx.t) t ~period src =
  if Ctx.now () < src.next_poll then Lwt.return_unit
  else begin
    src.error <- None;
    let* r =
      Lwt.catch
        (fun () ->
          match src.kind with
          | File path -> poll_files ctx t src path
          | Objects { uri; make; stamp } -> (
              match client_of src ~make ~stamp with
              | Error m -> Lwt.return (Error m)
              | Ok client -> poll_objects ctx t src ~uri client))
        (fun e -> Lwt.return (Error (Printexc.to_string e)))
    in
    (match r with
    | Ok () when src.error = None ->
        src.last_read <- Some (Ctx.now ());
        src.failing <- 0;
        src.next_poll <- neg_infinity
    | Ok () -> ()
    | Error m ->
        if src.error = None then src.error <- Some m;
        log "warning" "audit source %s: %s" src.label m;
        (* exponential backoff, capped at 5 minutes *)
        src.failing <- src.failing + 1;
        let delay =
          Float.min 300. (period *. (2. ** float_of_int (min 16 (src.failing - 1))))
        in
        src.next_poll <- Ctx.now () +. delay);
    Lwt.return_unit
  end

let concurrency = 4

(** One pass over every source; then expires old entries and publishes status. File
    sources are read in order (so the earlier of two sources naming one file reads it);
    object sources run concurrently with them, at most [concurrency] at a time. A source
    that failed is skipped until its backoff ([period] doubled per failure, at most 5
    minutes) has passed. *)
let poll_once ?(period = 0.) (ctx : Ctx.t) t =
  Ctx.set ctx gaps_key t.gaps;
  let files, objects =
    List.partition (fun s -> match s.kind with File _ -> true | _ -> false) t.sources
  in
  let pool = Lwt_pool.create concurrency (fun () -> Lwt.return_unit) in
  let* () =
    Lwt.join
      [
        Lwt_list.iter_s (poll_source ctx t ~period) files;
        Lwt_list.iter_p
          (fun s -> Lwt_pool.use pool (fun () -> poll_source ctx t ~period s))
          objects;
      ]
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
          (fun () -> poll_once ~period ctx t)
          (fun e ->
            log "error" "ingest poll failed: %s" (Printexc.to_string e);
            Lwt.return_unit)
      in
      let* () = Lwt_unix.sleep period in
      loop ()
    in
    loop ()
