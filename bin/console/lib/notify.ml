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

(** Delay before retry [n] (1-based) of a notification; tests shorten it. *)
let retry_delay = ref (fun n -> 0.5 *. float_of_int n)

(* [retries] extra attempts are made after HTTP 429, a 5xx or a transport error (not after
   other 4xx, which would fail again). Jira issue creation passes 0: a retried POST could
   open a duplicate issue. *)
let post_json ~what ?(timeout = 5.) ?(retries = 0) ?(headers = []) url
    (body : Yojson.Safe.t) =
  match Http.check_endpoint ~what url with
  | Error _ ->
      (* The check's message may echo the URL; keep secrets out of the log. *)
      log "warn" "%s: endpoint must be https (or http on a loopback host)" what;
      Lwt.return_none
  | Ok uri ->
      let body = Yojson.Safe.to_string body in
      let rec attempt n =
        let retry msg =
          if n <= retries then (
            log "warn" "%s: %s; retrying" what msg;
            let* () = Lwt_unix.sleep (!retry_delay n) in
            attempt (n + 1))
          else (
            log "warn" "%s: %s" what msg;
            Lwt.return_none)
        in
        let* r =
          Lwt.catch
            (fun () ->
              let+ r =
                Http.request ~timeout
                  ~headers:(("content-type", "application/json") :: headers)
                  ~body `POST uri
              in
              Ok r)
            (fun exn -> Lwt.return (Error exn))
        in
        match r with
        | Ok (Ok resp) when resp.status >= 200 && resp.status < 300 ->
            Lwt.return_some resp
        | Ok (Ok resp) when resp.status = 429 || resp.status >= 500 ->
            retry (Printf.sprintf "HTTP %d" resp.status)
        | Ok (Ok resp) ->
            log "warn" "%s: HTTP %d" what resp.status;
            Lwt.return_none
        | Ok (Error _) -> retry "request failed (connection error or timeout)"
        | Error exn -> retry (Printexc.exn_slot_name exn)
      in
      attempt 1

(** Retries for Slack and PagerDuty deliveries (429, 5xx, transport errors). *)
let notify_retries = 2

(* ---- signals ---- *)

type alert = {
  id : string;
  severity : string;
  title : string;
  body : string;
  kind : string;
  subject : string;
}

(** Escapes Slack mrkdwn control characters ([&], [<], [>]) so caller names, bundle
    sources and other audit-derived text cannot mention [@channel] or disguise a link. *)
let slack_escape s =
  let b = Buffer.create (String.length s) in
  String.iter
    (function
      | '&' -> Buffer.add_string b "&amp;"
      | '<' -> Buffer.add_string b "&lt;"
      | '>' -> Buffer.add_string b "&gt;"
      | c -> Buffer.add_char b c)
    s;
  Buffer.contents b

let slack ?timeout cfg (a : alert) =
  match Option.bind (section cfg "slack") (str "webhook") with
  | None -> Lwt.return_unit
  | Some url -> (
      let* url = resolved cfg ~what:"integrations.slack.webhook" url in
      match url with
      | None -> Lwt.return_unit
      | Some url ->
          let e = slack_escape in
          let text =
            Printf.sprintf "*HaltSQL %s signal* (%s): %s\n%s\nSignal id: %s"
              (e a.severity) (e cfg.environment.env_name) (e a.title) (e a.body) (e a.id)
          in
          let* _ =
            post_json ~what:"slack notification" ?timeout ~retries:notify_retries url
              (`Assoc [ ("text", `String text) ])
          in
          Lwt.return_unit)

let pagerduty_default_url = "https://events.pagerduty.com/v2/enqueue"

let pagerduty ?timeout ?(action = `Trigger) cfg (a : alert) =
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
                match action with
                | `Resolve ->
                    `Assoc
                      [
                        ("routing_key", `String key);
                        ("event_action", `String "resolve");
                        ("dedup_key", `String a.id);
                      ]
                | `Trigger ->
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
                                  (if a.severity = "high" then "critical" else "warning")
                              );
                              ("component", `String a.subject);
                              ("class", `String a.kind);
                              ("custom_details", `Assoc [ ("body", `String a.body) ]);
                            ] );
                      ]
              in
              let* _ =
                post_json ~what:"pagerduty event" ?timeout ~retries:notify_retries url
                  body
              in
              Lwt.return_unit))

(** Sends a new signal to every configured channel, concurrently. *)
let signal ?timeout cfg a = Lwt.join [ slack ?timeout cfg a; pagerduty ?timeout cfg a ]

(** Resolves a signal's PagerDuty incident (same [dedup_key]) once it is resolved. *)
let resolve ?timeout cfg a = pagerduty ?timeout ~action:`Resolve cfg a

(* ---- Jira ---- *)

let base64 = Haltsql_b64.encode
let jira_configured cfg = section cfg "jira" <> None

let strip_slash url =
  if String.ends_with ~suffix:"/" url then String.sub url 0 (String.length url - 1)
  else url

(** Creates a Jira issue; returns its key and browse URL ([None] when not configured or on
    failure). *)
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
              let url = strip_slash url in
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
                      | Some (`String k) -> Lwt.return_some (k, url ^ "/browse/" ^ k)
                      | _ -> Lwt.return_none)
                  | _ -> Lwt.return_none
                  | exception _ -> Lwt.return_none)))
      | _ ->
          log "warn" "integrations.jira needs url, project and token";
          Lwt.return_none)
