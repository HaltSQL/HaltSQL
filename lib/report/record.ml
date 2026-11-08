(* Normalized audit records; see record.mli for both input formats. *)

open Haltsql_core

type source = Server | Proxy
type outcome = Allowed | Denied | Shadow_denied
type reason = { code : string; rule : string; message : string }

type t = {
  source : source;
  ts : float option;
  event : string;
  caller : string;
  caller_type : string option;
  policy : string;
  policy_version : string option;
  outcome : outcome;
  codes : string list;
  details : reason list;
  tables : string list;
  columns : string list;
  fingerprint : string option;
  sql_sha256 : string option;
  sql : string option;
}

let outcome_to_string = function
  | Allowed -> "allowed"
  | Denied -> "denied"
  | Shadow_denied -> "shadow_denied"

let source_to_string = function Server -> "server" | Proxy -> "proxy"

let dedup l =
  List.rev (List.fold_left (fun acc x -> if List.mem x acc then acc else x :: acc) [] l)

(* Bounds on what one record may contribute (records come from files anyone with
   write access to the audit directory could have edited). *)
let max_field = 4096
let max_list = 1024
let clip s = if String.length s > max_field then String.sub s 0 max_field else s

let str kv k =
  match List.assoc_opt k kv with Some (`String s) -> Some (clip s) | _ -> None

let strings kv k : (string list, string) result =
  match List.assoc_opt k kv with
  | None | Some `Null -> Ok []
  | Some (`List l) ->
      if List.length l > max_list then Error (Printf.sprintf "%S has too many entries" k)
      else
        List.fold_right
          (fun x acc ->
            match (x, acc) with
            | `String s, Ok rest -> Ok (clip s :: rest)
            | _, (Error _ as e) -> e
            | _, Ok _ -> Error (Printf.sprintf "%S must be a list of strings" k))
          l (Ok [])
  | Some _ -> Error (Printf.sprintf "%S must be a list of strings" k)

let bool kv k = match List.assoc_opt k kv with Some (`Bool b) -> Some b | _ -> None

let common kv ~source ~event ~caller_key ~outcome ~codes ~tables =
  let ts = Option.bind (str kv "ts") Rtime.parse_rfc3339 in
  let caller =
    match str kv caller_key with Some c when c <> "" -> c | _ -> "(unknown)"
  in
  {
    source;
    ts;
    event;
    caller;
    caller_type = str kv "caller_type";
    policy = Option.value (str kv "policy") ~default:"(unknown)";
    policy_version = str kv "policy_version";
    outcome;
    codes = dedup codes;
    details = [];
    tables = dedup tables;
    columns = [];
    fingerprint = str kv "fingerprint";
    sql_sha256 = str kv "sql_sha256";
    sql = (match List.assoc_opt "sql" kv with Some (`String s) -> Some s | _ -> None);
  }

let ( let* ) = Result.bind

let of_server kv =
  match (bool kv "allowed", bool kv "shadow") with
  | Some allowed, shadow ->
      let* codes = strings kv "codes" in
      let shadow = Option.value shadow ~default:false in
      let outcome =
        if not allowed then Denied
        else if codes <> [] || shadow then Shadow_denied
        else Allowed
      in
      Ok
        (common kv ~source:Server ~event:"verify" ~caller_key:"caller" ~outcome ~codes
           ~tables:[])
  | None, _ -> Error "server audit record without a boolean \"allowed\""

let of_proxy kv event =
  match bool kv "allowed" with
  | None -> Error "proxy audit record without a boolean \"allowed\""
  | Some allowed ->
      let* reasons = strings kv "reasons" in
      let* shadow = strings kv "shadow_reasons" in
      let* tables = strings kv "tables" in
      let outcome, codes =
        if not allowed then (Denied, reasons @ shadow)
        else if shadow <> [] then (Shadow_denied, shadow)
        else (Allowed, [])
      in
      Ok (common kv ~source:Proxy ~event ~caller_key:"user" ~outcome ~codes ~tables)

let of_json (j : Yojson.Safe.t) =
  match j with
  | `Assoc kv -> (
      match (List.assoc_opt "codes" kv, List.assoc_opt "event" kv) with
      | Some _, _ when List.mem_assoc "allowed" kv -> of_server kv
      | None, Some (`String event) when List.mem_assoc "reasons" kv -> of_proxy kv event
      | _ -> Error "not a HaltSQL audit record")
  | _ -> Error "not a JSON object"

let of_line line =
  match Yojson.Safe.from_string line with
  | j -> of_json j
  | exception Yojson.Json_error e -> Error ("invalid JSON: " ^ e)

let reason_of (r : Reason.t) =
  { code = Reason.code_to_string r.code; rule = r.rule; message = r.message }

let of_verdict ~ts ~caller ?caller_type ~sql (v : Verdict.t) =
  let codes =
    List.map
      (fun (r : Reason.t) -> Reason.code_to_string r.code)
      (v.reasons @ v.shadow_reasons)
  in
  let outcome =
    if not v.allowed then Denied
    else if v.shadow_reasons <> [] then Shadow_denied
    else Allowed
  in
  {
    source = Server;
    ts = Some ts;
    event = "verify";
    caller = (if caller = "" then "(unknown)" else caller);
    caller_type;
    policy = v.policy_name;
    policy_version = Some v.policy_version;
    outcome;
    codes = dedup codes;
    details = List.map reason_of (v.reasons @ v.shadow_reasons);
    tables = v.tables;
    columns = v.columns;
    fingerprint = v.fingerprint;
    sql_sha256 = Some v.sql_sha256;
    sql;
  }

let with_details t (v : Verdict.t) =
  let details =
    List.filter_map
      (fun r ->
        let r = reason_of r in
        if List.mem r.code t.codes then Some r else None)
      (v.reasons @ v.shadow_reasons)
  in
  {
    t with
    details = (if details = [] then t.details else details);
    tables = (if t.tables = [] then v.tables else t.tables);
    columns = (if t.columns = [] then v.columns else t.columns);
  }

let fingerprint_key t =
  match (t.fingerprint, t.sql_sha256) with
  | Some f, _ when f <> "" -> f
  | _, Some h -> "sha256:" ^ h
  | _ -> "(none)"
