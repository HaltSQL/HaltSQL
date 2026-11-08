(* Open Policy Agent check after verify. OPA can only further deny. *)

open Lwt.Infix
module Config = Haltsql.Config
module Verdict = Haltsql.Verdict
module Reason = Haltsql.Reason
module Context = Haltsql.Context
module Policy = Haltsql.Policy
module Http = Haltsql_cloud.Http

type caller = { caller_name : string; caller_type : string }

type input = {
  caller : caller;
  policy : string;
  policy_version : string;
  statement_kind : string option;
  tables : string list;
  columns : string list;
  reasons : string list;
  shadow_reasons : string list;
  allowed : bool;
  sql_sha256 : string;
  fingerprint : string option;
  context_keys : string list;
}

let codes rs = List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) rs

let input_of_verdict ~caller ~(context : Context.t) (v : Verdict.t) =
  {
    caller;
    policy = v.policy_name;
    policy_version = v.policy_version;
    statement_kind = v.statement_kind;
    tables = v.tables;
    columns = v.columns;
    reasons = codes v.reasons;
    shadow_reasons = codes v.shadow_reasons;
    allowed = v.allowed;
    sql_sha256 = v.sql_sha256;
    fingerprint = v.fingerprint;
    context_keys = List.sort_uniq String.compare (List.map fst context);
  }

let strings l = `List (List.map (fun s -> `String s) l)
let opt = function Some s -> `String s | None -> `Null

let input_to_json i : Yojson.Safe.t =
  `Assoc
    [
      ( "caller",
        `Assoc
          [
            ("name", `String i.caller.caller_name); ("type", `String i.caller.caller_type);
          ] );
      ("policy", `String i.policy);
      ("policy_version", `String i.policy_version);
      ("statement_kind", opt i.statement_kind);
      ("tables", strings i.tables);
      ("columns", strings i.columns);
      ("reasons", strings i.reasons);
      ("shadow_reasons", strings i.shadow_reasons);
      ("allowed", `Bool i.allowed);
      ("sql_sha256", `String i.sql_sha256);
      ("fingerprint", opt i.fingerprint);
      ("context_keys", strings i.context_keys);
    ]

(* ---- response parsing ---- *)

type decision = Allow | Deny of string list

let max_reasons = 16
let max_reason_bytes = 200

let sanitize s =
  let s = String.map (fun c -> if Char.code c < 0x20 || c = '\x7f' then ' ' else c) s in
  let s = String.trim s in
  if String.length s <= max_reason_bytes then s
  else
    (* do not cut a UTF-8 sequence in half *)
    let n = ref max_reason_bytes in
    while !n > 0 && Char.code s.[!n] land 0xC0 = 0x80 do
      decr n
    done;
    String.sub s 0 !n ^ "..."

let rec take n = function
  | [] -> []
  | x :: xs -> if n <= 0 then [] else x :: take (n - 1) xs

let parse_result (r : Yojson.Safe.t) =
  match r with
  | `Bool true -> Ok Allow
  | `Bool false -> Ok (Deny [])
  | `Assoc kv -> (
      let unknown = List.filter (fun (k, _) -> k <> "allow" && k <> "reasons") kv in
      let dup k = List.length (List.filter (fun (k', _) -> k' = k) kv) > 1 in
      if unknown <> [] then
        Error
          (Printf.sprintf
             "decision object has unexpected key(s): %s (allowed: allow, reasons)"
             (String.concat ", " (List.map (fun (k, _) -> sanitize k) (take 5 unknown))))
      else if dup "allow" || dup "reasons" then Error "decision object has duplicate keys"
      else
        let reasons =
          match List.assoc_opt "reasons" kv with
          | None | Some `Null -> Ok []
          | Some (`List l) ->
              let strs = List.filter_map (function `String s -> Some s | _ -> None) l in
              if List.length strs <> List.length l then
                Error "decision \"reasons\" must contain only strings"
              else
                Ok (List.filter (( <> ) "") (List.map sanitize (take max_reasons strs)))
          | Some _ -> Error "decision \"reasons\" must be an array of strings"
        in
        match (List.assoc_opt "allow" kv, reasons) with
        | _, Error e -> Error e
        | Some (`Bool true), Ok _ -> Ok Allow
        | Some (`Bool false), Ok rs -> Ok (Deny rs)
        | None, Ok _ -> Error "decision object has no \"allow\""
        | Some _, Ok _ -> Error "decision \"allow\" must be a boolean")
  | `Null -> Error "decision is null"
  | _ -> Error "decision must be a boolean or an object {allow, reasons}"

let parse_response ~status body =
  if status <> 200 then Error (Printf.sprintf "OPA answered HTTP %d" status)
  else
    match Yojson.Safe.from_string body with
    | exception Yojson.Json_error _ -> Error "OPA response is not valid JSON"
    | `Assoc kv -> (
        match List.filter (fun (k, _) -> k = "result") kv with
        | [] ->
            Error
              "OPA decision is undefined (no \"result\"): check decision_path and that \
               the policy is loaded"
        | [ (_, r) ] -> parse_result r
        | _ -> Error "OPA response has duplicate \"result\" keys")
    | _ -> Error "OPA response is not a JSON object"

let decision_url (cfg : Config.opa) =
  match Http.check_endpoint ~what:"opa.url" cfg.opa_url with
  | Error e -> Error e
  | Ok _ ->
      let base = cfg.opa_url in
      let base =
        if String.length base > 0 && base.[String.length base - 1] = '/' then
          String.sub base 0 (String.length base - 1)
        else base
      in
      let ok_segment s =
        s <> ""
        && String.for_all
             (fun c ->
               (c >= 'a' && c <= 'z')
               || (c >= 'A' && c <= 'Z')
               || (c >= '0' && c <= '9')
               || c = '_')
             s
      in
      if not (List.for_all ok_segment (String.split_on_char '/' cfg.decision_path)) then
        Error "opa.decision_path must be Rego identifiers separated by /"
      else Ok (Uri.of_string (base ^ "/v1/data/" ^ cfg.decision_path))

(* ---- outcome and verdict combination ---- *)

type outcome =
  | Skipped
  | Allowed
  | Denied of string list
  | Failed_open of string
  | Failed_closed of string

let outcome_of_result (cfg : Config.opa) = function
  | Ok Allow -> Allowed
  | Ok (Deny rs) -> Denied rs
  | Error e -> (
      match cfg.opa_on_error with
      | Config.Opa_deny -> Failed_closed e
      | Config.Opa_allow_haltsql_verdict -> Failed_open e)

let outcome_label = function
  | Skipped -> "skipped"
  | Allowed -> "allowed"
  | Denied _ -> "denied"
  | Failed_open _ -> "error_allowed"
  | Failed_closed _ -> "error_denied"

let rule = "opa.decision"

let reasons_of_outcome ~code (cfg : Config.opa) = function
  | Skipped | Allowed | Failed_open _ -> []
  | Denied [] ->
      [
        Reason.make ~rule code
          (Printf.sprintf "denied by the external policy %s (OPA)" cfg.decision_path);
      ]
  | Denied rs ->
      List.map
        (fun r ->
          Reason.make ~rule code
            (Printf.sprintf "denied by the external policy %s (OPA): %s" cfg.decision_path
               r))
        rs
  | Failed_closed e ->
      [
        Reason.make ~rule code
          ~hint:"the external policy service is unavailable; retry later"
          (Printf.sprintf "the external policy check %s failed and on_error is deny: %s"
             cfg.decision_path e);
      ]

let apply ~code ~(mode : Policy.mode) cfg (v : Verdict.t) outcome =
  match reasons_of_outcome ~code cfg outcome with
  | [] -> v
  | _ when not v.allowed -> v
  | added -> (
      match mode with
      | Policy.Enforce ->
          (* a denied verdict never carries bind_params (like every other denial) *)
          { v with allowed = false; reasons = v.reasons @ added; bind_params = [] }
      | Policy.Shadow -> { v with shadow_reasons = v.shadow_reasons @ added })

(* ---- IO ---- *)

let max_response_bytes = 1024 * 1024

(* TLS contexts are cached by CA content or (path, file stat) so on-disk CA
   rotation invalidates the cached context. *)
type ca_cache_key =
  | Key_inline of string
  | Key_path of string * (float * int * int) option

let stat_fingerprint p =
  try
    let st = Unix.stat p in
    Some (st.Unix.st_mtime, st.Unix.st_size, st.Unix.st_ino)
  with Unix.Unix_error _ -> None

let cache_key = function
  | Config.Pem_inline s -> Key_inline s
  | Config.Pem_path p -> Key_path (p, stat_fingerprint p)

let ctx_cache : (ca_cache_key, Http.ctx) Hashtbl.t = Hashtbl.create 4

let ctx_for (cfg : Config.opa) : (Http.ctx, string) result Lwt.t =
  match cfg.opa_ca with
  | None -> Lwt.return (Ok Http.default_ctx)
  | Some pem -> (
      let key = cache_key pem in
      match Hashtbl.find_opt ctx_cache key with
      | Some c -> Lwt.return (Ok c)
      | None -> (
          let build : (Http.ctx, string) result Lwt.t =
            match pem with
            | Config.Pem_path p -> Http.ctx_of_ca_file p
            | Config.Pem_inline s -> Http.ctx_of_ca_pem s
          in
          build >|= function
          | Ok c ->
              Hashtbl.replace ctx_cache key c;
              Ok c
          | Error e -> Error e))

let request_decision (cfg : Config.opa) input =
  match decision_url cfg with
  | Error e -> Lwt.return (Error e)
  | Ok uri -> (
      ctx_for cfg >>= function
      | Error e -> Lwt.return (Error e)
      | Ok ctx -> (
          let body = Yojson.Safe.to_string (`Assoc [ ("input", input_to_json input) ]) in
          let headers =
            [ ("content-type", "application/json"); ("accept", "application/json") ]
            @ cfg.opa_headers
          in
          Http.request ~ctx
            ~timeout:(float_of_int cfg.opa_timeout_ms /. 1000.)
            ~max_body:max_response_bytes ~headers ~body `POST uri
          >|= function
          | Error e -> Error e
          | Ok (r : Http.response) -> parse_response ~status:r.status r.body))

let check ~cfg ~input =
  if not input.allowed then Lwt.return Skipped
  else
    Lwt.catch
      (fun () -> request_decision cfg input)
      (fun e -> Lwt.return (Error ("OPA check failed: " ^ Printexc.to_string e)))
    >|= outcome_of_result cfg

let enforce ~code ~mode ~cfg ~caller ~context (v : Verdict.t) =
  let input = input_of_verdict ~caller ~context v in
  check ~cfg ~input >|= fun outcome -> (apply ~code ~mode cfg v outcome, outcome)
