open Lwt.Infix
module Config = Haltsql_load.Config
module Http = Haltsql_cloud.Http

type t = {
  cfg : Config.es_sink;
  urls : Uri.t array;
  ctx : Http.ctx;
  auth : (string * string) list;
  timeout : float;
  max_response : int;
  mutable cur : int;
}

let target_name = function Config.Es_index s | Config.Es_data_stream s -> s

let name (cfg : Config.es_sink) =
  let host =
    match cfg.es_urls with u :: _ -> Http.host_header (Uri.of_string u) | [] -> "?"
  in
  Printf.sprintf "elasticsearch://%s/%s" host (target_name cfg.es_target)

let now_rfc3339 () = Ptime.to_rfc3339 ~frac_s:3 ~tz_offset_s:0 (Ptime_clock.now ())

let prepare fields =
  (* [event] carries event.original in the document *)
  let fields =
    List.map (fun (k, v) -> if k = "event" then ("haltsql_event", v) else (k, v)) fields
  in
  if List.mem_assoc "@timestamp" fields then fields
  else
    let ts =
      match List.assoc_opt "ts" fields with Some (`String s) -> s | _ -> now_rfc3339 ()
    in
    ("@timestamp", `String ts) :: fields

let ca_ctx = function
  | None -> Lwt.return (Ok Http.default_ctx)
  | Some (Config.Pem_path p) -> (
      Http.ctx_of_ca_file p >|= function
      | Ok c -> Ok c
      | Error m -> Error ("elasticsearch tls.ca_file: " ^ m))
  | Some (Config.Pem_inline pem) -> (
      Http.ctx_of_ca_pem pem >|= function
      | Ok c -> Ok c
      | Error _ -> Error "elasticsearch tls.ca_file (inline PEM): invalid CA bundle")

let create ?(max_response = 64 * 1024 * 1024) (cfg : Config.es_sink) =
  let urls =
    List.fold_right
      (fun u acc ->
        Result.bind acc (fun l ->
            Result.map (fun x -> x :: l) (Http.check_endpoint ~what:"elasticsearch url" u)))
      cfg.es_urls (Ok [])
  in
  match urls with
  | Error m -> Lwt.return (Error m)
  | Ok [] -> Lwt.return (Error "elasticsearch sink: no urls")
  | Ok urls -> (
      ca_ctx cfg.es_ca >|= function
      | Error m -> Error m
      | Ok ctx ->
          let auth =
            match cfg.es_auth with
            | None -> []
            | Some (Config.Es_api_key k) -> [ ("Authorization", "ApiKey " ^ k) ]
            | Some (Config.Es_basic { username; password }) ->
                [
                  ( "Authorization",
                    "Basic " ^ Base64.encode_string (username ^ ":" ^ password) );
                ]
          in
          Ok
            {
              cfg;
              urls = Array.of_list urls;
              ctx;
              auth;
              timeout = float_of_int cfg.es_timeout_ms /. 1000.;
              max_response;
              cur = 0;
            })

(* The document: the record's own fields (searchable) plus the exact sealed line
   as ECS [event.original]. Ingest pipelines and synthetic _source (the default
   for logs-*-* data streams) re-serialize documents, so verification always
   starts from event.original. *)
let document line =
  let n = String.length line in
  if n < 2 || line.[0] <> '{' || line.[n - 1] <> '}' then invalid_arg "Es_sink.document";
  String.sub line 0 (n - 1)
  ^ {|,"event":{"original":|}
  ^ Yojson.Safe.to_string (`String line)
  ^ "}}"

let bulk_body target (entries : Stream_sink.entry array) =
  let b =
    Buffer.create
      (Array.fold_left
         (fun n (e : Stream_sink.entry) -> n + (2 * String.length e.line) + 160)
         0 entries)
  in
  let index = target_name target in
  Array.iter
    (fun (e : Stream_sink.entry) ->
      Buffer.add_string b
        (Yojson.Safe.to_string
           (`Assoc
              [
                ("create", `Assoc [ ("_index", `String index); ("_id", `String e.hash) ]);
              ]));
      Buffer.add_char b '\n';
      Buffer.add_string b (document e.line);
      Buffer.add_char b '\n')
    entries;
  Buffer.contents b

let mapping_errors =
  [
    "mapper_parsing_exception";
    "document_parsing_exception";
    "strict_dynamic_mapping_exception";
    "mapper_exception";
  ]

let safe_type s =
  let s = String.map (fun c -> if c < ' ' || c > '~' then '?' else c) s in
  if String.length s > 100 then String.sub s 0 100 else s

let classify_items n body =
  match Yojson.Safe.from_string body with
  | exception Yojson.Json_error _ -> Error "malformed _bulk response"
  | `Assoc kv -> (
      match List.assoc_opt "items" kv with
      | Some (`List items) when List.length items = n ->
          let item = function
            | `Assoc [ (_op, `Assoc fields) ] -> (
                let status =
                  match List.assoc_opt "status" fields with Some (`Int s) -> s | _ -> 0
                in
                let etype =
                  match List.assoc_opt "error" fields with
                  | Some (`Assoc e) -> (
                      match List.assoc_opt "type" e with
                      | Some (`String s) -> safe_type s
                      | _ -> "unknown_error")
                  | _ -> "unknown_error"
                in
                match status with
                | s when s >= 200 && s < 300 -> Stream_sink.Delivered
                | 409 -> Stream_sink.Delivered
                | 400 when List.mem etype mapping_errors ->
                    Stream_sink.Rejected { reason = "mapping"; detail = etype }
                | 0 -> Stream_sink.Retry "item without a status"
                | s -> Stream_sink.Retry (Printf.sprintf "item HTTP %d %s" s etype))
            | _ -> Stream_sink.Retry "malformed item"
          in
          Ok (Array.of_list (List.map item items))
      | Some (`List items) ->
          Error
            (Printf.sprintf "_bulk response has %d items for %d records"
               (List.length items) n)
      | _ -> Error "_bulk response has no items")
  | _ -> Error "malformed _bulk response"

let error_type body =
  match Yojson.Safe.from_string body with
  | `Assoc kv -> (
      match List.assoc_opt "error" kv with
      | Some (`Assoc e) -> (
          match List.assoc_opt "type" e with
          | Some (`String s) -> " " ^ safe_type s
          | _ -> "")
      | _ -> "")
  | _ -> ""
  | exception _ -> ""

let bulk_uri t base =
  let path = Uri.path base in
  let path =
    if path <> "" && path.[String.length path - 1] = '/' then path ^ "_bulk"
    else path ^ "/_bulk"
  in
  let q =
    (match t.cfg.es_pipeline with Some p -> [ ("pipeline", [ p ]) ] | None -> [])
    @ [ ("filter_path", [ "errors,items.*.status,items.*.error.type" ]) ]
  in
  Uri.with_query (Uri.with_path base path) q

let deliver t entries =
  let n = Array.length entries in
  let base = t.urls.(t.cur mod Array.length t.urls) in
  let rotate () = t.cur <- (t.cur + 1) mod Array.length t.urls in
  let where = Http.host_header base in
  Http.request ~ctx:t.ctx ~timeout:t.timeout ~max_body:t.max_response
    ~headers:
      (("Content-Type", "application/x-ndjson")
      :: ("Accept", "application/json")
      :: t.auth)
    ~body:(bulk_body t.cfg.es_target entries)
    `POST (bulk_uri t base)
  >|= function
  | Error m ->
      rotate ();
      Error m
  | Ok r when r.status >= 200 && r.status < 300 -> classify_items n r.body
  | Ok r -> (
      let et = error_type r.body in
      match r.status with
      | 401 | 403 ->
          Error (Printf.sprintf "%s: _bulk not authorized (HTTP %d%s)" where r.status et)
      | 413 ->
          Error
            (Printf.sprintf
               "%s: _bulk request too large (HTTP 413); lower batch.max_bytes" where)
      | s when s = 429 || s >= 500 ->
          rotate ();
          Error (Printf.sprintf "%s: _bulk failed (HTTP %d%s)" where s et)
      | s -> Error (Printf.sprintf "%s: _bulk failed (HTTP %d%s)" where s et))
