(* Outbound notifications and tickets: Slack, PagerDuty (Events API v2) and Jira.

   Every call is best effort: failures are logged (status code or transport error only,
   never the webhook URL, routing key, token or response body) and never fail the caller.
   URLs must be https, or http on a loopback host (Haltsql_cloud.Http.check_endpoint). *)

open Lwt.Syntax
module Http = Haltsql_cloud.Http

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

let section (cfg : Console_config.t) name =
  match Api.member name cfg.integrations with Some (`Assoc _ as j) -> Some j | _ -> None

let str name j =
  match Api.member name j with
  | Some (`String s) when String.trim s <> "" -> Some s
  | _ -> None

(* Expands ${...} placeholders in a value from [integrations] ({!Console_config.resolve},
   cached for at most five minutes). A failure is logged without the value. *)
let resolved (cfg : Console_config.t) ~what v =
  let+ r = Console_config.resolve cfg v in
  match r with
  | Ok v -> Some v
  | Error m ->
      log "warn" "%s: %s" what m;
      None

let post_json ~what ?(headers = []) url (body : Yojson.Safe.t) =
  match Http.check_endpoint ~what url with
  | Error _ ->
      (* The check's message may echo the URL; keep secrets out of the log. *)
      log "warn" "%s: endpoint must be https (or http on a loopback host)" what;
      Lwt.return_none
  | Ok uri ->
      Lwt.catch
        (fun () ->
          let* r =
            Http.request ~timeout:5.
              ~headers:(("content-type", "application/json") :: headers)
              ~body:(Yojson.Safe.to_string body) `POST uri
          in
          match r with
          | Ok resp when resp.status >= 200 && resp.status < 300 -> Lwt.return_some resp
          | Ok resp ->
              log "warn" "%s: HTTP %d" what resp.status;
              Lwt.return_none
          | Error _ ->
              log "warn" "%s: request failed (connection error or timeout)" what;
              Lwt.return_none)
        (fun exn ->
          log "warn" "%s: %s" what (Printexc.exn_slot_name exn);
          Lwt.return_none)

(* ---- signals ---- *)

type alert = {
  id : string;
  severity : string;
  title : string;
  body : string;
  kind : string;
  subject : string;
}

let slack cfg (a : alert) =
  match Option.bind (section cfg "slack") (str "webhook") with
  | None -> Lwt.return_unit
  | Some url -> (
      let* url = resolved cfg ~what:"integrations.slack.webhook" url in
      match url with
      | None -> Lwt.return_unit
      | Some url ->
          let text =
            Printf.sprintf "*HaltSQL %s signal* (%s): %s\n%s\nSignal id: %s" a.severity
              cfg.environment.env_name a.title a.body a.id
          in
          let* _ =
            post_json ~what:"slack notification" url (`Assoc [ ("text", `String text) ])
          in
          Lwt.return_unit)

let pagerduty_default_url = "https://events.pagerduty.com/v2/enqueue"

let pagerduty cfg (a : alert) =
  match section cfg "pagerduty" with
  | None -> Lwt.return_unit
  | Some pd -> (
      match str "routing_key" pd with
      | None -> Lwt.return_unit
      | Some key -> (
          let* key = resolved cfg ~what:"integrations.pagerduty.routing_key" key in
          let* url =
            resolved cfg ~what:"integrations.pagerduty.events_url"
              (Option.value (str "events_url" pd) ~default:pagerduty_default_url)
          in
          match (key, url) with
          | None, _ | _, None -> Lwt.return_unit
          | Some key, Some url ->
              let body =
                `Assoc
                  [
                    ("routing_key", `String key);
                    ("event_action", `String "trigger");
                    ("dedup_key", `String a.id);
                    ( "payload",
                      `Assoc
                        [
                          ("summary", `String a.title);
                          ( "source",
                            `String ("haltsql-console/" ^ cfg.environment.env_name) );
                          ( "severity",
                            `String
                              (if a.severity = "high" then "critical" else "warning") );
                          ("component", `String a.subject);
                          ("class", `String a.kind);
                          ("custom_details", `Assoc [ ("body", `String a.body) ]);
                        ] );
                  ]
              in
              let* _ = post_json ~what:"pagerduty event" url body in
              Lwt.return_unit))

(** Sends a new signal to every configured channel, concurrently. *)
let signal cfg a = Lwt.join [ slack cfg a; pagerduty cfg a ]

(* ---- Jira ---- *)

let base64 s =
  let tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" in
  let n = String.length s in
  let b = Buffer.create (((n + 2) / 3 * 4) + 1) in
  let byte i = if i < n then Char.code s.[i] else 0 in
  let i = ref 0 in
  while !i < n do
    let x = (byte !i lsl 16) lor (byte (!i + 1) lsl 8) lor byte (!i + 2) in
    Buffer.add_char b tbl.[(x lsr 18) land 63];
    Buffer.add_char b tbl.[(x lsr 12) land 63];
    Buffer.add_char b (if !i + 1 < n then tbl.[(x lsr 6) land 63] else '=');
    Buffer.add_char b (if !i + 2 < n then tbl.[x land 63] else '=');
    i := !i + 3
  done;
  Buffer.contents b

let jira_configured cfg = section cfg "jira" <> None

(** Creates a Jira issue; returns its key ([None] when not configured or on failure). *)
let jira_issue cfg ~summary ~description =
  match section cfg "jira" with
  | None -> Lwt.return_none
  | Some j -> (
      match (str "url" j, str "project" j, str "token" j) with
      | Some url, Some project, Some token -> (
          let* url = resolved cfg ~what:"integrations.jira.url" url in
          let* token = resolved cfg ~what:"integrations.jira.token" token in
          let* email =
            match str "email" j with
            | None -> Lwt.return_none
            | Some e -> resolved cfg ~what:"integrations.jira.email" e
          in
          match (url, token) with
          | None, _ | _, None -> Lwt.return_none
          | Some url, Some token -> (
              let url =
                if String.ends_with ~suffix:"/" url then
                  String.sub url 0 (String.length url - 1)
                else url
              in
              let auth =
                match email with
                | Some email -> "Basic " ^ base64 (email ^ ":" ^ token)
                | None -> "Bearer " ^ token
              in
              let body =
                `Assoc
                  [
                    ( "fields",
                      `Assoc
                        [
                          ("project", `Assoc [ ("key", `String project) ]);
                          ("summary", `String summary);
                          ("description", `String description);
                          ( "issuetype",
                            `Assoc
                              [
                                ( "name",
                                  `String
                                    (Option.value (str "issue_type" j) ~default:"Task") );
                              ] );
                        ] );
                  ]
              in
              let* r =
                post_json ~what:"jira issue"
                  ~headers:[ ("authorization", auth) ]
                  (url ^ "/rest/api/2/issue") body
              in
              match r with
              | None -> Lwt.return_none
              | Some resp -> (
                  match Yojson.Safe.from_string resp.body with
                  | `Assoc l -> (
                      match List.assoc_opt "key" l with
                      | Some (`String k) -> Lwt.return_some k
                      | _ -> Lwt.return_none)
                  | _ -> Lwt.return_none
                  | exception _ -> Lwt.return_none)))
      | _ ->
          log "warn" "integrations.jira needs url, project and token";
          Lwt.return_none)

let jira_browse_url cfg key =
  match Option.bind (section cfg "jira") (str "url") with
  | Some url ->
      let url =
        if String.ends_with ~suffix:"/" url then String.sub url 0 (String.length url - 1)
        else url
      in
      Some (url ^ "/browse/" ^ key)
  | None -> None
