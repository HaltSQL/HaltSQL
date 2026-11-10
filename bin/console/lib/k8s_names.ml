(* Kubernetes name and workload parsing, with no dependency on the console config, so
   that [Console_config] can validate [fleet.kubernetes] and [verifiers[].workload] at
   load and [K8s] can reuse the same rules at restart time. *)

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
