(* A small GitHub REST client for policy pull requests (integrations.github). Owner: PR
   console/05-build.

   Only what the Policies feature needs: refs, the git data API (one commit with several
   files), raw file contents, pull requests, check runs and reviews. Works against
   GitHub Enterprise and test fakes through [api]. The token is only ever sent in the
   [authorization] header; error messages never contain it or response bodies beyond
   GitHub's own [message] field. *)

open Lwt.Syntax

type cfg = {
  api : string;  (** base URL, default https://api.github.com, no trailing slash *)
  repo : string;  (** owner/name *)
  token : string;  (** resolved secret *)
  base : string;  (** base branch, default main *)
  path : string;  (** directory of policy files in the repo, default "policies" *)
  tests_path : string;  (** directory of test suites, default "tests" *)
  branch_prefix : string;  (** default "haltsql-console/" *)
  required_approvals : int;  (** shown with the PR state, default 1 *)
  policy_paths : (string * string) list;
      (** policy name -> file path in the repo, for policies whose file is not
          [path/<basename>] *)
}

let trim_slashes s =
  let n = String.length s in
  let i = ref 0 and j = ref n in
  while !i < n && s.[!i] = '/' do
    incr i
  done;
  while !j > !i && s.[!j - 1] = '/' do
    decr j
  done;
  String.sub s !i (!j - !i)

let valid_repo s =
  match String.split_on_char '/' s with
  | [ o; r ] ->
      let ok c =
        match c with
        | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '_' | '.' -> true
        | _ -> false
      in
      o <> "" && r <> "" && String.for_all ok o && String.for_all ok r
  | _ -> false

let keys =
  [
    "repo";
    "token";
    "base";
    "path";
    "tests_path";
    "api";
    "branch_prefix";
    "required_approvals";
    "policy_paths";
  ]

(* [config] before the token is resolved: [token] is the value as written (it may hold
   ${...} placeholders). *)
let parse (ctx : Ctx.t) : (cfg, string) result option =
  match Api.member "github" ctx.config.integrations with
  | None | Some `Null -> None
  | Some (`Assoc kv as j) -> (
      let str k =
        match Api.member k j with Some (`String s) when s <> "" -> Some s | _ -> None
      in
      match List.find_opt (fun (k, _) -> not (List.mem k keys)) kv with
      | Some (k, _) -> Some (Error (Printf.sprintf "unknown key %S" k))
      | None -> (
          match (str "repo", str "token") with
          | None, _ -> Some (Error "repo is required")
          | _, None -> Some (Error "token is required")
          | Some repo, _ when not (valid_repo repo) ->
              Some (Error "repo must be owner/name")
          | Some repo, Some token -> (
              let policy_paths =
                match Api.member "policy_paths" j with
                | None | Some `Null -> Ok []
                | Some (`Assoc l) ->
                    List.fold_left
                      (fun acc (n, v) ->
                        match (acc, v) with
                        | Error _, _ -> acc
                        | Ok l, `String p when trim_slashes p <> "" ->
                            Ok (l @ [ (n, trim_slashes p) ])
                        | Ok _, _ ->
                            Error
                              (Printf.sprintf "policy_paths.%s must be a repository path"
                                 n))
                      (Ok []) l
                | Some _ -> Error "policy_paths must be a mapping of policy name to path"
              in
              let api =
                Option.value (str "api") ~default:"https://api.github.com" |> fun s ->
                if String.ends_with ~suffix:"/" s then String.sub s 0 (String.length s - 1)
                else s
              in
              match
                ( Haltsql_cloud.Http.check_endpoint ~what:"integrations.github.api" api,
                  policy_paths )
              with
              | Error e, _ | _, Error e -> Some (Error e)
              | Ok _, Ok policy_paths ->
                  Some
                    (Ok
                       {
                         api;
                         repo;
                         token;
                         base = Option.value (str "base") ~default:"main";
                         path =
                           trim_slashes (Option.value (str "path") ~default:"policies");
                         tests_path =
                           trim_slashes (Option.value (str "tests_path") ~default:"tests");
                         branch_prefix =
                           Option.value (str "branch_prefix") ~default:"haltsql-console/";
                         required_approvals =
                           (match Api.member "required_approvals" j with
                           | Some (`Int n) when n >= 0 -> n
                           | _ -> 1);
                         policy_paths;
                       }))))
  | Some _ -> Some (Error "must be a mapping")

(** [None] when [integrations.github] is absent; [Some (Error why)] when it is unusable,
    including when its token cannot be resolved. Placeholders in [token] are resolved on
    every call ({!Console_config.resolve}, cached for at most five minutes), so a rotated
    token is picked up without a restart. *)
let config (ctx : Ctx.t) : (cfg, string) result option Lwt.t =
  match parse ctx with
  | (None | Some (Error _)) as r -> Lwt.return r
  | Some (Ok c) -> (
      let+ token = Console_config.resolve ctx.config c.token in
      match token with
      | Ok token -> Some (Ok { c with token })
      | Error m -> Some (Error ("token: " ^ m)))

(* ---- requests ---- *)

let enc s = Haltsql_cloud.Http.pct_encode ~keep_slash:true s

(* Idempotent GETs are retried (at most [max_attempts] tries) on a transport error, a 5xx,
   a 429 or a rate-limit 403, waiting for [Retry-After] or [x-ratelimit-reset] when GitHub
   sends them and otherwise a jittered exponential backoff from [retry_base]. A wait
   longer than [max_retry_wait] is not taken: the call fails with GitHub's answer instead,
   so one request never outlives the console's request timeout. Writes are never
   retried. *)
let max_attempts = 3
let retry_base = 0.25
let max_retry_wait = 5.

let rate_limited (resp : Haltsql_cloud.Http.response) =
  resp.status = 429
  || resp.status = 403
     && (Haltsql_cloud.Http.header resp "x-ratelimit-remaining" = Some "0"
        || Haltsql_cloud.Http.header resp "retry-after" <> None)

let retryable (resp : Haltsql_cloud.Http.response) =
  resp.status >= 500 || rate_limited resp

(** Seconds to wait before retry [attempt] (1-based). *)
let retry_wait ?resp attempt =
  let header h = Option.bind resp (fun r -> Haltsql_cloud.Http.header r h) in
  let after =
    Option.bind (header "retry-after") (fun s -> float_of_string_opt (String.trim s))
  in
  let reset =
    match (header "x-ratelimit-remaining", header "x-ratelimit-reset") with
    | Some "0", Some r ->
        Option.map
          (fun t -> t -. Unix.gettimeofday ())
          (float_of_string_opt (String.trim r))
    | _ -> None
  in
  match (after, reset) with
  | Some s, _ | None, Some s -> Float.max 0. s
  | None, None ->
      retry_base *. Float.pow 2. (float_of_int (attempt - 1)) *. (0.5 +. Random.float 0.5)

let call ?(accept = "application/vnd.github+json") ?body cfg meth path =
  let uri = Uri.of_string (cfg.api ^ path) in
  let headers =
    [
      ("authorization", "Bearer " ^ cfg.token);
      ("accept", accept);
      ("user-agent", "haltsql-console");
      ("x-github-api-version", "2022-11-28");
    ]
    @ match body with Some _ -> [ ("content-type", "application/json") ] | None -> []
  in
  let once () =
    Haltsql_cloud.Http.request ~timeout:15. ~headers
      ?body:(Option.map Yojson.Safe.to_string body)
      meth uri
  in
  let rec go attempt =
    let* r = once () in
    let retry ?resp () =
      let wait = retry_wait ?resp attempt in
      if meth = `GET && attempt < max_attempts && wait <= max_retry_wait then
        let* () = Lwt_unix.sleep wait in
        go (attempt + 1)
      else
        match (r, resp) with
        | Ok resp, _ | _, Some resp -> Lwt.return resp
        | Error e, None ->
            Api.upstream "GitHub %s %s failed: %s"
              (Cohttp.Code.string_of_method meth)
              path e
    in
    match r with
    | Error _ -> retry ()
    | Ok resp when retryable resp -> retry ~resp ()
    | Ok resp -> Lwt.return resp
  in
  go 1

let json_of (resp : Haltsql_cloud.Http.response) =
  try Yojson.Safe.from_string resp.body with _ -> `Null

let fail_status meth path (resp : Haltsql_cloud.Http.response) =
  let msg =
    match Api.member "message" (json_of resp) with
    | Some (`String m) -> ": " ^ m
    | _ -> ""
  in
  Api.upstream "GitHub %s %s returned HTTP %d%s"
    (Cohttp.Code.string_of_method meth)
    path resp.status msg

(* JSON request that must succeed with 2xx. *)
let ok_json ?body cfg meth path =
  let* resp = call ?body cfg meth path in
  if resp.status >= 200 && resp.status < 300 then Lwt.return (json_of resp)
  else fail_status meth path resp

let str_at path j =
  let rec go j = function
    | [] -> ( match j with `String s -> Some s | _ -> None)
    | k :: rest -> ( match Api.member k j with Some v -> go v rest | None -> None)
  in
  go j path

let repo_path cfg rest = Printf.sprintf "/repos/%s%s" cfg.repo rest

(** The [rel="next"] URL of a [Link] header. *)
let next_link (resp : Haltsql_cloud.Http.response) =
  match Haltsql_cloud.Http.header resp "link" with
  | None -> None
  | Some l ->
      List.find_map
        (fun part ->
          match (String.index_opt part '<', String.index_opt part '>') with
          | Some i, Some j when j > i ->
              let rest = String.sub part (j + 1) (String.length part - j - 1) in
              let rels =
                String.split_on_char ';' rest |> List.map String.trim
                |> List.filter_map (fun kv ->
                    match String.index_opt kv '=' with
                    | Some k when String.trim (String.sub kv 0 k) = "rel" ->
                        Some
                          (String.split_on_char ' '
                             (String.trim
                                (String.map
                                   (fun c -> if c = '"' then ' ' else c)
                                   (String.sub kv (k + 1) (String.length kv - k - 1)))))
                    | _ -> None)
                |> List.concat
              in
              if List.mem "next" rels then Some (String.sub part (i + 1) (j - i - 1))
              else None
          | _ -> None)
        (String.split_on_char ',' l)

let max_pages = 10

(** Every item of a paginated GET ([per_page=100], following [Link: rel="next"] for at
    most [max_pages] pages). [items] extracts one page's items from its JSON. A next link
    to another host is not followed: the token is only ever sent to [cfg.api]. *)
let get_all cfg path ~items =
  let sep = if String.contains path '?' then "&" else "?" in
  let rec go page path acc =
    let* resp = call cfg `GET path in
    if resp.status < 200 || resp.status >= 300 then fail_status `GET path resp
    else
      let acc = acc @ items (json_of resp) in
      match next_link resp with
      | Some url when page < max_pages && String.starts_with ~prefix:(cfg.api ^ "/") url
        ->
          go (page + 1)
            (String.sub url (String.length cfg.api)
               (String.length url - String.length cfg.api))
            acc
      | _ -> Lwt.return acc
  in
  go 1 (path ^ sep ^ "per_page=100") []

(* ---- refs and commits ---- *)

(** The commit sha of a branch, [None] when it does not exist. *)
let get_ref cfg branch =
  let path = repo_path cfg ("/git/ref/heads/" ^ enc branch) in
  let* resp = call cfg `GET path in
  if resp.status = 404 then Lwt.return None
  else if resp.status >= 200 && resp.status < 300 then
    Lwt.return (str_at [ "object"; "sha" ] (json_of resp))
  else fail_status `GET path resp

let create_ref cfg branch sha =
  let* _ =
    ok_json cfg `POST (repo_path cfg "/git/refs")
      ~body:(`Assoc [ ("ref", `String ("refs/heads/" ^ branch)); ("sha", `String sha) ])
  in
  Lwt.return_unit

let update_ref ?(force = false) cfg branch sha =
  let* _ =
    ok_json cfg `PATCH
      (repo_path cfg ("/git/refs/heads/" ^ enc branch))
      ~body:(`Assoc [ ("sha", `String sha); ("force", `Bool force) ])
  in
  Lwt.return_unit

(** A file's text at [ref_], [None] when it does not exist. *)
let get_file cfg ~ref_ file =
  let path = repo_path cfg (Printf.sprintf "/contents/%s?ref=%s" (enc file) (enc ref_)) in
  let* resp = call ~accept:"application/vnd.github.raw+json" cfg `GET path in
  if resp.status = 404 then Lwt.return None
  else if resp.status >= 200 && resp.status < 300 then Lwt.return (Some resp.body)
  else fail_status `GET path resp

(** A commit's message, [None] when the commit does not exist. *)
let commit_message cfg sha =
  let path = repo_path cfg ("/git/commits/" ^ enc sha) in
  let* resp = call cfg `GET path in
  if resp.status = 404 then Lwt.return None
  else if resp.status >= 200 && resp.status < 300 then
    Lwt.return (Some (Option.value (str_at [ "message" ] (json_of resp)) ~default:""))
  else fail_status `GET path resp

(** Paths of the files under [dir] at [ref_] (one recursive tree read; a tree GitHub
    truncates is searched as far as it goes). *)
let list_files cfg ~ref_ ~dir =
  let* j = ok_json cfg `GET (repo_path cfg ("/git/trees/" ^ enc ref_ ^ "?recursive=1")) in
  let prefix = if dir = "" then "" else dir ^ "/" in
  let entries = match Api.member "tree" j with Some (`List l) -> l | _ -> [] in
  Lwt.return
    (List.filter_map
       (fun e ->
         match (str_at [ "type" ] e, str_at [ "path" ] e) with
         | Some "blob", Some p when String.starts_with ~prefix p -> Some p
         | _ -> None)
       entries)

(** Commits [files] (path, text) on top of [parent] in one commit and moves [branch] to
    it. Returns the new commit sha. *)
let commit_files cfg ~branch ~parent ~message files =
  let* parent_commit = ok_json cfg `GET (repo_path cfg ("/git/commits/" ^ enc parent)) in
  let base_tree =
    match str_at [ "tree"; "sha" ] parent_commit with
    | Some s -> s
    | None -> Api.upstream "GitHub returned a commit without a tree"
  in
  let* tree =
    ok_json cfg `POST (repo_path cfg "/git/trees")
      ~body:
        (`Assoc
           [
             ("base_tree", `String base_tree);
             ( "tree",
               `List
                 (List.map
                    (fun (p, content) ->
                      `Assoc
                        [
                          ("path", `String p);
                          ("mode", `String "100644");
                          ("type", `String "blob");
                          ("content", `String content);
                        ])
                    files) );
           ])
  in
  let tree_sha =
    match str_at [ "sha" ] tree with
    | Some s -> s
    | None -> Api.upstream "GitHub returned a tree without a sha"
  in
  let* commit =
    ok_json cfg `POST
      (repo_path cfg "/git/commits")
      ~body:
        (`Assoc
           [
             ("message", `String message);
             ("tree", `String tree_sha);
             ("parents", `List [ `String parent ]);
           ])
  in
  let sha =
    match str_at [ "sha" ] commit with
    | Some s -> s
    | None -> Api.upstream "GitHub returned a commit without a sha"
  in
  let* () = update_ref cfg branch sha in
  Lwt.return sha

(* ---- pull requests ---- *)

type pr = { number : int; url : string; state : string; head_sha : string option }

let pr_of_json j =
  let number = match Api.member "number" j with Some (`Int n) -> n | _ -> 0 in
  let merged = match Api.member "merged" j with Some (`Bool b) -> b | _ -> false in
  let state =
    if merged then "merged" else Option.value (str_at [ "state" ] j) ~default:"unknown"
  in
  {
    number;
    url = Option.value (str_at [ "html_url" ] j) ~default:"";
    state;
    head_sha = str_at [ "head"; "sha" ] j;
  }

let update_pr cfg number ~title ~body =
  let* j =
    ok_json cfg `PATCH
      (repo_path cfg (Printf.sprintf "/pulls/%d" number))
      ~body:(`Assoc [ ("title", `String title); ("body", `String body) ])
  in
  Lwt.return (pr_of_json j)

(** [None] when the PR does not exist (deleted repo, wrong number). *)
let get_pr cfg number =
  let path = repo_path cfg (Printf.sprintf "/pulls/%d" number) in
  let* resp = call cfg `GET path in
  if resp.status = 404 then Lwt.return None
  else if resp.status >= 200 && resp.status < 300 then
    Lwt.return (Some (pr_of_json (json_of resp)))
  else fail_status `GET path resp

let list_of = function `List l -> l | _ -> []

(** The open PR whose head is [branch] of this repository, if any. *)
let find_open_pr cfg branch =
  let owner = List.hd (String.split_on_char '/' cfg.repo) in
  let* j =
    ok_json cfg `GET
      (repo_path cfg
         (Printf.sprintf "/pulls?state=open&head=%s&per_page=100"
            (Haltsql_cloud.Http.pct_encode (owner ^ ":" ^ branch))))
  in
  Lwt.return
    (List.find_map
       (fun p ->
         let pr = pr_of_json p in
         if pr.state = "open" && str_at [ "head"; "ref" ] p = Some branch then Some pr
         else None)
       (list_of j))

(** Opens a PR, or, when GitHub answers 422 because an open PR for [head] already exists,
    adopts that PR and updates its title and body. The flag is true when a PR was created.
*)
let create_pr cfg ~title ~head ~base ~body =
  let path = repo_path cfg "/pulls" in
  let* resp =
    call cfg `POST path
      ~body:
        (`Assoc
           [
             ("title", `String title);
             ("head", `String head);
             ("base", `String base);
             ("body", `String body);
           ])
  in
  if resp.status >= 200 && resp.status < 300 then
    Lwt.return (pr_of_json (json_of resp), true)
  else if resp.status = 422 then
    let* open_pr = find_open_pr cfg head in
    match open_pr with
    | Some pr ->
        let* pr = update_pr cfg pr.number ~title ~body in
        Lwt.return (pr, false)
    | None -> fail_status `POST path resp
  else fail_status `POST path resp

(** Check runs of a commit: [{name, state, detail}] (every page). *)
let checks cfg sha =
  let* runs =
    get_all cfg
      (repo_path cfg ("/commits/" ^ enc sha ^ "/check-runs"))
      ~items:(fun j ->
        match Api.member "check_runs" j with Some l -> list_of l | None -> [])
  in
  Lwt.return
    (List.map
       (fun r ->
         let state =
           match (str_at [ "status" ] r, str_at [ "conclusion" ] r) with
           | Some "completed", Some c -> c
           | Some s, _ -> s
           | None, Some c -> c
           | None, None -> "unknown"
         in
         `Assoc
           [
             ("name", Api.opt_string (str_at [ "name" ] r));
             ("state", `String state);
             ("detail", Api.opt_string (str_at [ "output"; "title" ] r));
           ])
       runs)

(** Current approvals: each reviewer's latest decisive review, kept when it is APPROVED.
    Reviews come oldest first, over every page. *)
let approvals cfg number =
  let* reviews =
    get_all cfg (repo_path cfg (Printf.sprintf "/pulls/%d/reviews" number)) ~items:list_of
  in
  let latest = Hashtbl.create 8 and order = ref [] in
  List.iter
    (fun r ->
      match (str_at [ "user"; "login" ] r, str_at [ "state" ] r) with
      | Some who, Some (("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED") as st) ->
          if not (Hashtbl.mem latest who) then order := who :: !order;
          Hashtbl.replace latest who (st, str_at [ "submitted_at" ] r)
      | _ -> ())
    reviews;
  Lwt.return
    (List.filter_map
       (fun who ->
         match Hashtbl.find_opt latest who with
         | Some ("APPROVED", at) ->
             Some (`Assoc [ ("by", `String who); ("at", Api.opt_string at) ])
         | _ -> None)
       (List.rev !order))
