(** Enforcement decisions; see enforce.mli. *)

open Haltsql

type deny = {
  sqlstate : string;
  message : string;
  detail : string option;
  hint : string option;
  codes : string list;
}

let deny_fields d =
  [ ('S', "ERROR"); ('V', "ERROR"); ('C', d.sqlstate); ('M', d.message) ]
  @ (match d.detail with Some s -> [ ('D', s) ] | None -> [])
  @ match d.hint with Some s -> [ ('H', s) ] | None -> []

let dedup l =
  List.rev (List.fold_left (fun acc x -> if List.mem x acc then acc else x :: acc) [] l)

let detail_of codes = Some ("HaltSQL reasons: " ^ String.concat ", " codes)

let of_verdict ~sqlstate (v : Verdict.t) =
  let codes =
    dedup (List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) v.reasons)
  in
  let codes = if codes = [] then [ "E_INTERNAL" ] else codes in
  let message =
    match v.reasons with
    | r :: _ ->
        Printf.sprintf "haltsql: query denied by policy %S: %s" v.policy_name r.message
    | [] -> Printf.sprintf "haltsql: query denied by policy %S" v.policy_name
  in
  let hint = List.find_map (fun (r : Reason.t) -> r.hint) v.reasons in
  { sqlstate; message; detail = detail_of codes; hint; codes }

let local_deny ~sqlstate ?hint ~code message =
  {
    sqlstate;
    message = "haltsql: " ^ message;
    detail = detail_of [ code ];
    hint;
    codes = [ code ];
  }

(* Exact-token allowlist for plain transaction control, so that drivers running
   outside autocommit work. Anything else (comments, quotes, savepoints, AND CHAIN,
   PREPARE TRANSACTION, SET ...) is not matched and goes through Haltsql.verify. *)
let transaction_control sql =
  let s = String.uppercase_ascii (String.trim sql) in
  let s =
    if String.length s > 0 && s.[String.length s - 1] = ';' then
      String.trim (String.sub s 0 (String.length s - 1))
    else s
  in
  if
    not
      (String.for_all
         (function 'A' .. 'Z' | ' ' | '\t' | '\n' | '\r' | ',' -> true | _ -> false)
         s)
  then false
  else
    let toks =
      String.split_on_char ' '
        (String.map (function '\t' | '\n' | '\r' -> ' ' | ',' -> ' ' | c -> c) s)
      |> List.filter (fun t -> t <> "")
    in
    let rec modes = function
      | [] -> true
      | "ISOLATION" :: "LEVEL" :: rest -> (
          match rest with
          | "SERIALIZABLE" :: r -> modes r
          | "REPEATABLE" :: "READ" :: r -> modes r
          | "READ" :: ("COMMITTED" | "UNCOMMITTED") :: r -> modes r
          | _ -> false)
      | "READ" :: ("ONLY" | "WRITE") :: r -> modes r
      | "NOT" :: "DEFERRABLE" :: r -> modes r
      | "DEFERRABLE" :: r -> modes r
      | _ -> false
    in
    let opt_work = function ("WORK" | "TRANSACTION") :: r -> r | r -> r in
    match toks with
    | "BEGIN" :: r -> modes (opt_work r)
    | "START" :: "TRANSACTION" :: r -> modes r
    | ("COMMIT" | "END" | "ROLLBACK" | "ABORT") :: r -> opt_work r = []
    | _ -> false

let tx_verdict (b : Proxy_config.binding) sql : Verdict.t =
  {
    allowed = true;
    reasons = [];
    shadow_reasons = [];
    policy_name = b.policy.name;
    policy_version = b.policy.version;
    statement_kind = Some "transaction";
    tables = [];
    columns = [];
    bind_params = [];
    fingerprint = None;
    sql_sha256 = Haltsql.sha256_hex sql;
    elapsed_us = 0;
  }

let verify ~allow_tx (b : Proxy_config.binding) sql =
  if allow_tx && transaction_control sql then tx_verdict b sql
  else Haltsql.verify b.policy b.context sql

let simple ~sqlstate ?(allow_tx = false) b sql =
  let v = verify ~allow_tx b sql in
  if not v.allowed then (v, Error (of_verdict ~sqlstate v))
  else if v.bind_params <> [] then
    let ps =
      String.concat ", " (List.map (fun (n, _) -> "$" ^ string_of_int n) v.bind_params)
    in
    ( v,
      Error
        (local_deny ~sqlstate ~code:"E_PARAM_UNBOUND"
           ~hint:
             "Send the query with the extended query protocol (a prepared statement); \
              the proxy binds tenancy parameters itself."
           (Printf.sprintf
              "query uses bound tenancy parameter(s) %s, which the simple query protocol \
               cannot bind"
              ps)) )
  else (v, Ok ())

let parse ~sqlstate ?(allow_tx = false) b sql =
  let v = verify ~allow_tx b sql in
  if v.allowed then (v, Ok ()) else (v, Error (of_verdict ~sqlstate v))

let context_text = function
  | Context.One s -> s
  | Context.Many vs ->
      let esc s =
        let b = Buffer.create (String.length s + 2) in
        Buffer.add_char b '"';
        String.iter
          (fun c ->
            if c = '"' || c = '\\' then Buffer.add_char b '\\';
            Buffer.add_char b c)
          s;
        Buffer.add_char b '"';
        Buffer.contents b
      in
      "{" ^ String.concat "," (List.map esc vs) ^ "}"

let bind ~sqlstate (v : Verdict.t) (b : Wire.bind) =
  match v.bind_params with
  | [] -> Ok b
  | bps -> (
      let n = List.length b.params in
      let problem =
        List.find_map
          (fun (k, value) ->
            if k < 1 || k > n then
              Some
                (Printf.sprintf
                   "statement needs tenancy parameter $%d but the Bind message supplies \
                    %d parameter(s)"
                   k n)
            else if List.exists (fun (k', value') -> k' = k && value' <> value) bps then
              Some (Printf.sprintf "conflicting tenancy values for parameter $%d" k)
            else
              match Wire.param_format b (k - 1) with
              | 0 -> None
              | _ ->
                  Some
                    (Printf.sprintf
                       "tenancy parameter $%d must use text format, not binary" k)
              | exception Wire.Malformed m -> Some m)
          bps
      in
      match problem with
      | Some m -> Error (local_deny ~sqlstate ~code:"E_PARAM_UNBOUND" m)
      | None ->
          let params =
            List.mapi
              (fun i p ->
                match List.assoc_opt (i + 1) bps with
                | Some value -> Some (context_text value)
                | None -> p)
              b.params
          in
          Ok { b with params })

(* PostgreSQL decodes a Bind value with the type the client declared for that
   parameter in Parse. A declared type such as float8, name or "char" would
   change how the injected tenant value is read (rounding, truncation), so every
   tenancy parameter's declared type is reset to 0 (unspecified) and the server
   infers it from the tenant predicate. Other parameters are left alone. *)
let reset_tenancy_param_types (v : Verdict.t) (p : Wire.parse) =
  match v.bind_params with
  | [] -> p
  | bps ->
      let param_types =
        List.mapi (fun i ty -> if List.mem_assoc (i + 1) bps then 0 else ty) p.param_types
      in
      if param_types = p.param_types then p else { p with param_types }
