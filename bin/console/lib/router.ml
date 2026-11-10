(* Method + path-pattern routing. Patterns are split on '/', and a segment starting with
   ':' captures that segment (percent-decoded) as a parameter. Features build their
   routes with [get], [post], [patch]; [Routes] collects them all. [lookup] is pure and
   returns the decoded captures as they are; Console_server rejects (400) any capture
   that fails [safe_param] before a handler runs. *)

type req = {
  http : Cohttp.Request.t;
  body : Cohttp_lwt.Body.t;
  params : (string * string) list;
}

type handler = Ctx.t -> Ctx.principal -> req -> Api.response Lwt.t
type route = { meth : Cohttp.Code.meth; pattern : string list; handler : handler }

let split path = String.split_on_char '/' path |> List.filter (( <> ) "")
let route meth path handler = { meth; pattern = split path; handler }
let get path h = route `GET path h
let post path h = route `POST path h
let patch path h = route `PATCH path h
let delete path h = route `DELETE path h

let param (r : req) name =
  match List.assoc_opt name r.params with
  | Some v -> v
  | None -> invalid_arg ("Router.param: no parameter " ^ name)

let query (r : req) name = Api.query r.http name
let json_body (r : req) = Api.json_body ~req:r.http r.body

let match_pattern pattern segments =
  let rec go acc p s =
    match (p, s) with
    | [], [] -> Some (List.rev acc)
    | ph :: pt, sh :: st when String.length ph > 0 && ph.[0] = ':' ->
        go ((String.sub ph 1 (String.length ph - 1), Uri.pct_decode sh) :: acc) pt st
    | ph :: pt, sh :: st when ph = sh -> go acc pt st
    | _ -> None
  in
  go [] pattern segments

(** False for captures that decode to a path separator, NUL or a dot segment (e.g. from
    [%2F]): handlers may use parameters as names. *)
let safe_param v =
  not
    (v = "." || v = ".." || String.contains v '/' || String.contains v '\\'
   || String.contains v '\000')

type lookup = Found of route * (string * string) list | Method_not_allowed | No_route

let lookup routes meth path =
  let segments = split path in
  let candidates =
    List.filter_map
      (fun r ->
        match match_pattern r.pattern segments with
        | Some ps -> Some (r, ps)
        | None -> None)
      routes
  in
  match List.find_opt (fun (r, _) -> r.meth = meth) candidates with
  | Some (r, ps) -> Found (r, ps)
  | None -> if candidates = [] then No_route else Method_not_allowed
