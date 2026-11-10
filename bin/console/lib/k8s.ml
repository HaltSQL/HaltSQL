(* Rollout restart of a verifier's Kubernetes workload: the same strategic-merge patch
   [kubectl rollout restart] sends (a new [kubectl.kubernetes.io/restartedAt] pod-template
   annotation), authenticated with the console's service-account token over TLS with the
   cluster CA. Error strings never contain the token or response bodies. *)

open Lwt.Syntax
include K8s_names

let read_token file =
  match In_channel.with_open_bin file In_channel.input_all with
  | exception Sys_error _ -> Error "cannot read the service-account token file"
  | s -> (
      match String.trim s with
      | "" -> Error "the service-account token file is empty"
      | t -> Ok t)

let patch_body ~restarted_at =
  `Assoc
    [
      ( "spec",
        `Assoc
          [
            ( "template",
              `Assoc
                [
                  ( "metadata",
                    `Assoc
                      [
                        ( "annotations",
                          `Assoc
                            [
                              ("kubectl.kubernetes.io/restartedAt", `String restarted_at);
                            ] );
                      ] );
                ] );
          ] );
    ]

(* The [reason] of a Kubernetes Status body (e.g. Forbidden, NotFound); never the
   message, which can echo request details. *)
let status_reason body =
  match Yojson.Safe.from_string body with
  | `Assoc l -> (
      match List.assoc_opt "reason" l with
      | Some (`String r) when r <> "" && String.length r <= 64 -> Some r
      | _ -> None)
  | _ | (exception _) -> None

type error =
  | Config of string  (** the console's own setup is wrong (token file, CA, URL) *)
  | Upstream of string  (** the Kubernetes API failed or refused *)

type outcome =
  | Rolled_out
  | No_rollout of string
      (** the patch was accepted but will not restart pods (paused Deployment, StatefulSet
          with [updateStrategy: OnDelete]); the string says why *)

(* What the PATCH response (the updated object) says about the rollout. *)
let outcome_of_body (w : workload) body =
  match Yojson.Safe.from_string body with
  | exception _ -> Rolled_out
  | j -> (
      let field path =
        List.fold_left
          (fun j k ->
            match j with
            | `Assoc l -> Option.value (List.assoc_opt k l) ~default:`Null
            | _ -> `Null)
          j path
      in
      match w.kind with
      | Deployment when field [ "spec"; "paused" ] = `Bool true ->
          No_rollout "the Deployment is paused (spec.paused); no pods were restarted"
      | Statefulset when field [ "spec"; "updateStrategy"; "type" ] = `String "OnDelete"
        ->
          No_rollout
            "the StatefulSet uses updateStrategy OnDelete; pods restart only when deleted"
      | _ -> Rolled_out)

let api_is_allowed uri =
  match (Option.map String.lowercase_ascii (Uri.scheme uri), Uri.host uri) with
  | Some "https", Some h -> h <> ""
  | Some "http", Some h -> Console_config.is_loopback_host h
  | _ -> false

(** Patches the workload. [Ok outcome] on a 2xx answer. Config errors are also rejected
    when the config loads; they are re-checked here because the token file and CA are read
    on every restart. *)
let restart (k : Console_config.kubernetes) (w : workload) ~restarted_at :
    (outcome, error) result Lwt.t =
  if not (valid_dns_name k.k_namespace) then
    Lwt.return (Error (Config "fleet.kubernetes.namespace is not a valid namespace name"))
  else
    match read_token k.k_token_file with
    | Error e -> Lwt.return (Error (Config e))
    | Ok token -> (
        let api =
          if String.ends_with ~suffix:"/" k.k_api then
            String.sub k.k_api 0 (String.length k.k_api - 1)
          else k.k_api
        in
        let uri =
          Uri.of_string
            (Printf.sprintf "%s/apis/apps/v1/namespaces/%s/%s/%s" api k.k_namespace
               (resource w.kind) w.name)
        in
        let* tls =
          if not (api_is_allowed uri) then
            Lwt.return
              (Error
                 "fleet.kubernetes.api must be https:// (or http:// on a loopback host)")
          else
            match Uri.scheme uri with
            | Some "https" -> (
                let+ r = Haltsql_cloud.Http.ctx_of_ca_file k.k_ca_file in
                match r with
                | Ok c -> Ok c
                | Error e -> Error ("fleet.kubernetes.ca_file: " ^ e))
            | _ -> Lwt.return (Ok Haltsql_cloud.Http.default_ctx)
        in
        match tls with
        | Error e -> Lwt.return (Error (Config e))
        | Ok ctx -> (
            let* r =
              Lwt.catch
                (fun () ->
                  Haltsql_cloud.Http.request ~ctx ~timeout:10. ~max_body:(1024 * 1024)
                    ~headers:
                      [
                        ("authorization", "Bearer " ^ token);
                        ("content-type", "application/strategic-merge-patch+json");
                        ("accept", "application/json");
                      ]
                    ~body:(Yojson.Safe.to_string (patch_body ~restarted_at))
                    `PATCH uri)
                (fun exn -> Lwt.return (Error (Printexc.to_string exn)))
            in
            match r with
            | Error e ->
                Lwt.return (Error (Upstream ("Kubernetes API unreachable: " ^ e)))
            | Ok resp when resp.status >= 200 && resp.status < 300 ->
                Lwt.return (Ok (outcome_of_body w resp.body))
            | Ok resp ->
                Lwt.return
                  (Error
                     (Upstream
                        (Printf.sprintf "Kubernetes API answered HTTP %d%s" resp.status
                           (match status_reason resp.body with
                           | Some r -> " (" ^ r ^ ")"
                           | None -> ""))))))
