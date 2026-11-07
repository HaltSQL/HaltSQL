(* Tamper-evident audit log.

   One JSON line per verify request, per sink:
     {ts, request_id, caller, policy, policy_version, allowed, shadow, codes,
      sql_sha256, fingerprint, elapsed_us, [sql], prev_hash, hash}
   where
     hash = sha256_hex (prev_hash ^ L)
   and L is the compact JSON serialization of the same object without the
   "hash" field (keys in exactly the order written). The first line of a new
   chain has prev_hash = 64 zeros. Appending to an existing file continues its
   chain from the last line's hash. Each sink keeps its own chain. *)

let genesis = String.make 64 '0'
let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

type sink = {
  name : string;  (** "stdout" or the file path *)
  fd : Unix.file_descr;
  mutable prev : string;
}

let rec write_all fd s off len =
  if len > 0 then begin
    let n = Unix.write_substring fd s off len in
    write_all fd s (off + n) (len - n)
  end

(* Last non-empty line of a file, reading only its tail. *)
let last_line path =
  match Unix.openfile path [ Unix.O_RDONLY ] 0 with
  | exception Unix.Unix_error _ -> None
  | fd ->
      Fun.protect
        ~finally:(fun () -> Unix.close fd)
        (fun () ->
          let size = (Unix.fstat fd).st_size in
          let rec try_tail chunk =
            let start = max 0 (size - chunk) in
            ignore (Unix.lseek fd start Unix.SEEK_SET);
            let len = size - start in
            let buf = Bytes.create len in
            let rec rd off =
              if off < len then
                let n = Unix.read fd buf off (len - off) in
                if n = 0 then off else rd (off + n)
              else off
            in
            let got = rd 0 in
            let s = Bytes.sub_string buf 0 got in
            let lines =
              String.split_on_char '\n' s |> List.filter (fun l -> String.trim l <> "")
            in
            (* With start > 0 the first piece may be a partial line: we need
               at least two pieces to trust the last one. *)
            match List.rev lines with
            | l :: _ :: _ -> Some l
            | [ l ] when start = 0 -> Some l
            | [] when start = 0 -> None
            | _ -> try_tail (chunk * 4)
          in
          if size = 0 then None else try_tail 65536)

let hash_of_line line =
  match Yojson.Safe.from_string line with
  | `Assoc kv -> (
      match List.assoc_opt "hash" kv with Some (`String h) -> Some h | _ -> None)
  | _ -> None
  | exception _ -> None

let open_stdout () = { name = "stdout"; fd = Unix.stdout; prev = genesis }

let open_file path =
  let prev =
    match last_line path with
    | None -> genesis
    | Some l -> (
        match hash_of_line l with
        | Some h -> h
        | None ->
            failwith
              (Printf.sprintf
                 "audit file %s: last line is not a valid audit record; refusing to \
                  continue the chain (rotate the file)"
                 path))
  in
  let fd =
    Unix.openfile path
      [ Unix.O_WRONLY; Unix.O_APPEND; Unix.O_CREAT; Unix.O_CLOEXEC ]
      0o640
  in
  { name = path; fd; prev }

let close s = if s.fd <> Unix.stdout then try Unix.close s.fd with _ -> ()

(* Builds the sealed line for [fields] chained after [prev]. Returns (line, hash). *)
let seal ~prev (fields : (string * Yojson.Safe.t) list) =
  let body = fields @ [ ("prev_hash", `String prev) ] in
  let unsealed = Yojson.Safe.to_string (`Assoc body) in
  let hash = sha256_hex (prev ^ unsealed) in
  (Yojson.Safe.to_string (`Assoc (body @ [ ("hash", `String hash) ])), hash)

let record_fields ~ts ~request_id ~caller ~(verdict : Haltsql.Verdict.t) ~sql ~log_raw_sql
    =
  let codes =
    List.map
      (fun (r : Haltsql.Reason.t) -> `String (Haltsql.Reason.code_to_string r.code))
      (verdict.reasons @ verdict.shadow_reasons)
  in
  [
    ("ts", `String ts);
    ("request_id", `String request_id);
    ("caller", `String caller);
    ("policy", `String verdict.policy_name);
    ("policy_version", `String verdict.policy_version);
    ("allowed", `Bool verdict.allowed);
    ("shadow", `Bool (verdict.shadow_reasons <> []));
    ("codes", `List codes);
    ("sql_sha256", `String verdict.sql_sha256);
    ("fingerprint", match verdict.fingerprint with Some f -> `String f | None -> `Null);
    ("elapsed_us", `Int verdict.elapsed_us);
  ]
  @ if log_raw_sql then [ ("sql", `String sql) ] else []

(* Appends one record to the sink. The chain only advances if the write
   succeeded. Raises [Unix.Unix_error] on failure. *)
let append sink fields =
  let line, hash = seal ~prev:sink.prev fields in
  let data = line ^ "\n" in
  write_all sink.fd data 0 (String.length data);
  sink.prev <- hash

(* ---- verification ---- *)

type chain_error = { line_no : int; problem : string }

(* Verifies a sequence of audit lines. [initial_prev]: the expected prev_hash
   of the first line (default: genesis; pass [None] to accept whatever the
   first line claims, e.g. for a rotated file). *)
(* Returns the number of verified records. *)
let verify_lines ?(initial_prev = Some genesis) (lines : string list) :
    (int, chain_error) result =
  let records = ref 0 in
  let rec go n prev = function
    | [] -> Ok !records
    | l :: rest when String.trim l = "" -> go (n + 1) prev rest
    | l :: rest -> (
        let err problem = Error { line_no = n; problem } in
        match Yojson.Safe.from_string l with
        | exception Yojson.Json_error e -> err ("invalid JSON: " ^ e)
        | `Assoc kv -> (
            match List.rev kv with
            | ("hash", `String h) :: rev_body -> (
                let body = List.rev rev_body in
                match List.assoc_opt "prev_hash" body with
                | Some (`String p) ->
                    let expected_prev_ok =
                      match prev with None -> true | Some e -> e = p
                    in
                    if not expected_prev_ok then
                      err "prev_hash does not match the previous record's hash"
                    else
                      let computed =
                        sha256_hex (p ^ Yojson.Safe.to_string (`Assoc body))
                      in
                      if computed <> h then err "hash mismatch (record was modified)"
                      else (
                        incr records;
                        go (n + 1) (Some h) rest)
                | _ -> err "missing prev_hash")
            | _ -> err "missing trailing \"hash\" field")
        | _ -> err "record is not a JSON object")
  in
  go 1 initial_prev lines

let verify_file ?initial_prev path =
  let lines =
    In_channel.with_open_bin path In_channel.input_all |> String.split_on_char '\n'
  in
  verify_lines ?initial_prev lines
