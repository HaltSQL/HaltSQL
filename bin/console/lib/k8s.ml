(* Rollout restart of a verifier's Kubernetes workload: the same strategic-merge patch
   [kubectl rollout restart] sends (a new [kubectl.kubernetes.io/restartedAt] pod-template
   annotation), authenticated with the console's service-account token over TLS with the
   cluster CA. Error strings never contain the token or response bodies. *)

open Lwt.Syntax

type kind = Deployment | Statefulset
type workload = { kind : kind; name : string }

let resource = function Deployment -> "deployments" | Statefulset -> "statefulsets"

let workload_to_string w =
  (match w.kind with Deployment -> "deployment/" | Statefulset -> "statefulset/")
  ^ w.name

(* DNS-1123 subdomain: lowercase alphanumerics, '-' and '.', alphanumeric at both ends. *)
let valid_dns_name s =
  let n = String.length s in
  let alnum c = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') in
  n > 0 && n <= 253
  && String.for_all (fun c -> alnum c || c = '-' || c = '.') s
  && alnum s.[0]
  && alnum s.[n - 1]

(** [deployment/x], [deploy/x], [statefulset/x] or [sts/x]. *)
let parse_workload s =
  match String.index_opt s '/' with
  | None -> None
  | Some i -> (
      let k = String.lowercase_ascii (String.sub s 0 i)
      and name = String.sub s (i + 1) (String.length s - i - 1) in
      if not (valid_dns_name name) then None
      else
        match k with
        | "deployment" | "deployments" | "deploy" -> Some { kind = Deployment; name }
        | "statefulset" | "statefulsets" | "sts" -> Some { kind = Statefulset; name }
        | _ -> None)

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

(** Patches the workload. [Ok ()] on a 2xx answer. *)
let restart (k : Console_config.kubernetes) (w : workload) ~restarted_at :
    (unit, string) result Lwt.t =
  if not (valid_dns_name k.k_namespace) then
    Lwt.return (Error "fleet.kubernetes.namespace is not a valid namespace name")
  else
    match read_token k.k_token_file with
    | Error e -> Lwt.return (Error e)
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
          match Uri.scheme uri with
          | Some "https" -> Haltsql_cloud.Http.ctx_of_ca_file k.k_ca_file
          | Some "http" -> Lwt.return (Ok Haltsql_cloud.Http.default_ctx)
          | _ -> Lwt.return (Error "fleet.kubernetes.api must be an http(s) URL")
        in
        match tls with
        | Error e -> Lwt.return (Error e)
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
            | Error e -> Lwt.return (Error ("Kubernetes API unreachable: " ^ e))
            | Ok resp when resp.status >= 200 && resp.status < 300 -> Lwt.return (Ok ())
            | Ok resp ->
                Lwt.return
                  (Error
                     (Printf.sprintf "Kubernetes API answered HTTP %d%s" resp.status
                        (match status_reason resp.body with
                        | Some r -> " (" ^ r ^ ")"
                        | None -> "")))))
