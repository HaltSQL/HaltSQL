(* HTTP plumbing for the live catalog fetchers (see fetch_client.mli).

   SECURITY: the bearer token only ever goes into the Authorization header of requests
   whose origin is the configured base URL's; it is never part of an error message. Error
   messages never include response bodies either (a catalog can echo the request, and
   Yojson parse errors quote the offending input). *)

open Lwt.Infix
module Http = Haltsql_cloud.Http

type auth = No_auth | Bearer of string

type t = {
  ctx : Http.ctx;
  timeout : float;
  max_pages : int;
  max_body : int;
  base : Uri.t;
  prefix : string;  (** base URL without trailing '/' *)
  auth : auth;
  mutable requests : int;
}

let ( let* ) = Result.bind

let valid_token tok =
  tok <> "" && String.for_all (fun c -> Char.code c > 0x20 && Char.code c < 0x7f) tok

let create ?(ctx = Http.default_ctx) ?(timeout = 30.) ?(max_pages = 1000)
    ?(max_body = 32 * 1024 * 1024) ~base_url auth =
  let* base = Http.check_endpoint ~what:"catalog URL" base_url in
  let* () =
    if Float.is_nan timeout || timeout <= 0. then Error "timeout must be positive"
    else Ok ()
  in
  let* () = if max_pages < 1 then Error "max_pages must be at least 1" else Ok () in
  let* () = if max_body < 1 then Error "max_body must be at least 1" else Ok () in
  let* () =
    match auth with
    | Bearer tok when not (valid_token tok) ->
        (* Never echo the token, even a malformed one. *)
        Error "the token is empty or contains whitespace or control characters"
    | _ -> Ok ()
  in
  let s = Uri.to_string base in
  let prefix =
    let n = ref (String.length s) in
    while !n > 0 && s.[!n - 1] = '/' do
      decr n
    done;
    String.sub s 0 !n
  in
  Ok { ctx; timeout; max_pages; max_body; base; prefix; auth; requests = 0 }

let base_url t = t.base
let request_count t = t.requests

let same_origin a b =
  Uri.scheme a = Uri.scheme b
  && Option.map String.lowercase_ascii (Uri.host a)
     = Option.map String.lowercase_ascii (Uri.host b)
  && Uri.port a = Uri.port b
  && Uri.userinfo b = None

(* [prefix ^ path], with [path] used as given (already percent-encoded). The result must
   stay on the base URL's origin, so the token cannot be sent anywhere else. *)
let target t ?(query = []) path =
  if path = "" || path.[0] <> '/' then
    Error (Printf.sprintf "request path %S must start with '/'" path)
  else if String.length path > 1 && path.[1] = '/' then
    Error (Printf.sprintf "request path %S must not start with '//'" path)
  else if String.contains path '#' then
    Error (Printf.sprintf "request path %S must not contain '#'" path)
  else
    let u = Uri.of_string (t.prefix ^ path) in
    let u = if query = [] then u else Uri.add_query_params' u query in
    if same_origin t.base u then Ok u
    else Error (Printf.sprintf "request path %S leaves the catalog URL's origin" path)

(* The path as shown in error messages: no query (it may carry cursors or filters). *)
let shown path =
  match String.index_opt path '?' with Some i -> String.sub path 0 i | None -> path

let send t meth ?query ?body path =
  let mname = Cohttp.Code.string_of_method meth in
  let where = Printf.sprintf "%s %s" mname (shown path) in
  match target t ?query path with
  | Error e -> Lwt.return (Error e)
  | Ok uri -> (
      let headers =
        [ ("Accept", "application/json"); ("User-Agent", "haltsql-schema-fetch") ]
        @ (match body with
          | Some _ -> [ ("Content-Type", "application/json") ]
          | None -> [])
        @
        match t.auth with
        | Bearer tok -> [ ("Authorization", "Bearer " ^ tok) ]
        | No_auth -> []
      in
      t.requests <- t.requests + 1;
      Http.request ~ctx:t.ctx ~timeout:t.timeout ~max_body:t.max_body ~headers ?body meth
        uri
      >|= function
      | Error e -> Error (Printf.sprintf "%s: %s" where e)
      | Ok r when r.status < 200 || r.status > 299 ->
          Error (Printf.sprintf "%s: HTTP %d" where r.status)
      | Ok r -> (
          if String.trim r.body = "" then Ok `Null
          else
            match Yojson.Safe.from_string r.body with
            | j -> Ok j
            | exception Yojson.Json_error _ ->
                (* Not the parser's message: it quotes the body. *)
                Error (Printf.sprintf "%s: the response is not valid JSON" where)))

let get_json t ?query path = send t `GET ?query path

let post_json t ?query path body =
  send t `POST ?query ~body:(Yojson.Safe.to_string body) path

let paginate t ~what page =
  let seen = Hashtbl.create 16 in
  let rec loop n cursor acc =
    if n >= t.max_pages then
      Lwt.return
        (Error
           (Printf.sprintf "%s: more than %d pages; stopping (raise --max-pages?)" what
              t.max_pages))
    else
      page cursor >>= function
      | Error e -> Lwt.return (Error e)
      | Ok (items, (None | Some "")) ->
          Lwt.return (Ok (List.rev (List.rev_append items acc)))
      | Ok (items, Some c) ->
          if Hashtbl.mem seen c then
            Lwt.return
              (Error
                 (Printf.sprintf "%s: the server returned the same page cursor twice" what))
          else begin
            Hashtbl.add seen c ();
            loop (n + 1) (Some c) (List.rev_append items acc)
          end
  in
  loop 0 None []
