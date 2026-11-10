(* JSON responses, errors, parameters and bodies shared by every handler. *)

module S = Cohttp_lwt_unix.Server

type response = Cohttp.Response.t * Cohttp_lwt.Body.t

exception Error of Cohttp.Code.status_code * string * string
(** [Error (status, code, message)]: raised by helpers, turned into an error response by
    the router. Messages must never contain secrets. *)

let fail status code fmt = Printf.ksprintf (fun m -> raise (Error (status, code, m))) fmt
let bad_request fmt = fail `Bad_request "BAD_REQUEST" fmt
let not_found fmt = fail `Not_found "NOT_FOUND" fmt
let forbidden fmt = fail `Forbidden "FORBIDDEN" fmt
let conflict fmt = fail `Conflict "CONFLICT" fmt
let not_configured fmt = fail `Service_unavailable "NOT_CONFIGURED" fmt
let upstream fmt = fail `Bad_gateway "UPSTREAM" fmt
let not_implemented fmt = fail `Not_implemented "NOT_IMPLEMENTED" fmt

let base_headers =
  [
    ("cache-control", "no-store");
    ("x-content-type-options", "nosniff");
    ("referrer-policy", "no-referrer");
  ]

let json ?(status = `OK) ?(headers = []) (body : Yojson.Safe.t) =
  let headers =
    Cohttp.Header.of_list
      ((("content-type", "application/json") :: base_headers) @ headers)
  in
  S.respond_string ~headers ~status ~body:(Yojson.Safe.to_string body ^ "\n") ()

let error_body code message =
  `Assoc [ ("error", `Assoc [ ("code", `String code); ("message", `String message) ]) ]

let error status code message = json ~status (error_body code message)

let bytes ?(status = `OK) ?(headers = []) ~content_type body =
  let headers =
    Cohttp.Header.of_list ((("content-type", content_type) :: base_headers) @ headers)
  in
  S.respond_string ~headers ~status ~body ()

(* ---- time ---- *)

let iso8601 (t : float) =
  match Ptime.of_float_s t with
  | None -> "1970-01-01T00:00:00.000Z"
  | Some p ->
      Ptime.to_rfc3339 ~frac_s:3 ~tz_offset_s:0 p |> fun s ->
      (* Ptime writes "+00:00" for UTC with tz_offset_s:0 on some versions; normalise. *)
      if String.length s > 6 && String.sub s (String.length s - 6) 6 = "+00:00" then
        String.sub s 0 (String.length s - 6) ^ "Z"
      else s

let parse_time s =
  match Ptime.of_rfc3339 s with
  | Ok (t, _, _) -> Some (Ptime.to_float_s t)
  | Error _ -> None

let opt_time = function None -> `Null | Some t -> `String (iso8601 t)
let opt_string = function None -> `Null | Some s -> `String s
let opt_int = function None -> `Null | Some i -> `Int i
let opt_float = function None -> `Null | Some f -> `Float f
let strings l = `List (List.map (fun s -> `String s) l)

(* ---- query parameters ---- *)

let query (req : Cohttp.Request.t) name =
  Uri.get_query_param (Cohttp.Request.uri req) name

let query_int req name ~default ~min ~max =
  match query req name with
  | None | Some "" -> default
  | Some s -> (
      match int_of_string_opt s with
      | Some n when n >= min && n <= max -> n
      | _ -> bad_request "parameter %s must be an integer in %d..%d" name min max)

let limit req = query_int req "limit" ~default:50 ~min:1 ~max:500

type range = { since : float; until : float }

(** [range=1h|24h|7d] (default [24h]) or explicit [since]/[until]. *)
let range ?(default = "24h") ?(now = Unix.gettimeofday ()) req =
  let span = function
    | "1h" -> 3600.
    | "24h" -> 86400.
    | "7d" -> 7. *. 86400.
    | "30d" -> 30. *. 86400.
    | s -> bad_request "range must be one of 1h, 24h, 7d, 30d (got %S)" s
  in
  let r = Option.value (query req "range") ~default in
  let until =
    match query req "until" with
    | None -> now
    | Some s -> (
        match parse_time s with
        | Some t -> t
        | None -> bad_request "until is not RFC 3339")
  in
  let since =
    match query req "since" with
    | None -> until -. span r
    | Some s -> (
        match parse_time s with
        | Some t -> t
        | None -> bad_request "since is not RFC 3339")
  in
  if since > until then bad_request "since is after until";
  { since; until }

let range_to_json r =
  `Assoc [ ("since", `String (iso8601 r.since)); ("until", `String (iso8601 r.until)) ]

(* Opaque cursors are base64url-encoded keys (see [page_desc]). *)
let encode_cursor n = Haltsql_auth.B64url.encode (string_of_int n)

(** Keyset paging over [items] sorted by strictly descending, unique [key] (e.g. a
    sequence number). The cursor is the key of the last item returned; the next page holds
    the items whose key is below it, so new items never shift a page. Returns the page,
    the next cursor ([`Null] at the end) and the total number of [items]. *)
let page_desc req ~(key : 'a -> int) (items : 'a list) =
  let lim = limit req in
  let after =
    match query req "cursor" with
    | None | Some "" -> None
    | Some c -> (
        match Haltsql_auth.B64url.decode c with
        | Ok s -> (
            match int_of_string_opt s with
            | Some n -> Some n
            | None -> bad_request "invalid cursor")
        | Error _ -> bad_request "invalid cursor")
  in
  let rest =
    match after with None -> items | Some k -> List.filter (fun x -> key x < k) items
  in
  let rec take n acc = function
    | x :: t when n > 0 -> take (n - 1) (x :: acc) t
    | l -> (List.rev acc, l)
  in
  let page, more = take lim [] rest in
  let next =
    match (more, List.rev page) with
    | _ :: _, last :: _ -> `String (encode_cursor (key last))
    | _ -> `Null
  in
  (page, next, List.length items)

(* ---- bodies ---- *)

let max_body_bytes = 1024 * 1024

let too_large max =
  fail `Request_entity_too_large "TOO_LARGE" "request body exceeds %d bytes" max

(** Reads [body] as a stream and fails with 413 TOO_LARGE as soon as it passes [max] bytes
    (default {!max_body_bytes}), without buffering the rest. *)
let read_body ?(max = max_body_bytes) body =
  let open Lwt.Syntax in
  let stream = Cohttp_lwt.Body.to_stream body in
  let buf = Buffer.create 1024 in
  let rec go () =
    let* chunk = Lwt_stream.get stream in
    match chunk with
    | None -> Lwt.return (Buffer.contents buf)
    | Some s ->
        if Buffer.length buf + String.length s > max then too_large max
        else (
          Buffer.add_string buf s;
          go ())
  in
  go ()

(** True when the request announces a body: a non-zero Content-Length or a
    Transfer-Encoding. *)
let request_has_body (req : Cohttp.Request.t) =
  let h = Cohttp.Request.headers req in
  match Cohttp.Header.get h "content-length" with
  | Some l -> Int64.of_string_opt (String.trim l) <> Some 0L
  | None -> Cohttp.Header.get h "transfer-encoding" <> None

(** [Content-Type: application/json], with optional parameters (e.g. charset). *)
let is_json_content_type (req : Cohttp.Request.t) =
  match Cohttp.Header.get (Cohttp.Request.headers req) "content-type" with
  | None -> false
  | Some ct ->
      let media =
        match String.index_opt ct ';' with Some i -> String.sub ct 0 i | None -> ct
      in
      String.lowercase_ascii (String.trim media) = "application/json"

(** Parses a JSON object body (empty body = [{}]). With [req], a non-empty body must be
    sent as [application/json] (415 otherwise). *)
let json_body ?req body =
  let open Lwt.Syntax in
  let* s = read_body body in
  if String.trim s = "" then Lwt.return (`Assoc [])
  else (
    (match req with
    | Some r when not (is_json_content_type r) ->
        fail `Unsupported_media_type "UNSUPPORTED_MEDIA_TYPE"
          "request body must be application/json"
    | _ -> ());
    match Yojson.Safe.from_string s with
    | `Assoc _ as j -> Lwt.return j
    | _ -> bad_request "body must be a JSON object"
    | exception Yojson.Json_error m -> bad_request "invalid JSON: %s" m)

let member name (j : Yojson.Safe.t) =
  match j with `Assoc l -> List.assoc_opt name l | _ -> None

let str_field ?(required = false) name j =
  match member name j with
  | Some (`String s) -> Some s
  | None | Some `Null ->
      if required then bad_request "field %s is required" name else None
  | Some _ -> bad_request "field %s must be a string" name

let int_field name j =
  match member name j with
  | Some (`Int i) -> Some i
  | None | Some `Null -> None
  | Some _ -> bad_request "field %s must be an integer" name

let bool_field name j =
  match member name j with
  | Some (`Bool b) -> Some b
  | None | Some `Null -> None
  | Some _ -> bad_request "field %s must be a boolean" name

let str_list_field name j =
  match member name j with
  | None | Some `Null -> []
  | Some (`List l) ->
      List.map
        (function
          | `String s -> s | _ -> bad_request "field %s must be a list of strings" name)
        l
  | Some _ -> bad_request "field %s must be a list of strings" name
