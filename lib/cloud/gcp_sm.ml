open Lwt.Infix
module Config = Haltsql_load.Config

type t = {
  cfg : Config.gcp_secrets;
  env : string -> string option;
  now : unit -> float;
  timeout : float;
  mutable auth : Gcp_auth.t option;
}

let create ?(env = Sys.getenv_opt) ?(now = Unix.gettimeofday) ?(timeout = 10.) ?auth cfg =
  { cfg; env; now; timeout; auth }

let valid_id s =
  s <> ""
  && String.length s <= 255
  && String.for_all
       (fun c ->
         (c >= 'a' && c <= 'z')
         || (c >= 'A' && c <= 'Z')
         || (c >= '0' && c <= '9')
         || c = '-' || c = '_')
       s

let resource_name ~project name =
  let bad () = Error (Printf.sprintf "invalid Secret Manager name %S" name) in
  let with_project s v =
    match project with
    | Some p when valid_id p ->
        Ok (Printf.sprintf "projects/%s/secrets/%s/versions/%s" p s v)
    | Some _ -> Error "invalid secrets.gcp.project"
    | None ->
        Error
          (Printf.sprintf "gcp-sm %S is a short name but secrets.gcp.project is not set"
             name)
  in
  match String.split_on_char '/' name with
  | [ "projects"; p; "secrets"; s; "versions"; v ]
    when valid_id p && valid_id s && valid_id v ->
      Ok name
  | [ "projects"; p; "secrets"; s ] when valid_id p && valid_id s ->
      Ok (name ^ "/versions/latest")
  | [ s ] when valid_id s -> with_project s "latest"
  | [ s; "versions"; v ] when valid_id s && valid_id v -> with_project s v
  | _ -> bad ()

let auth t =
  match t.auth with
  | Some a -> Ok a
  | None -> (
      match Gcp_auth.default ~env:t.env ~now:t.now () with
      | Ok a ->
          t.auth <- Some a;
          Ok a
      | Error e -> Error e)

let get t reference =
  let name, key =
    match String.index_opt reference '#' with
    | None -> (reference, None)
    | Some i ->
        ( String.sub reference 0 i,
          Some (String.sub reference (i + 1) (String.length reference - i - 1)) )
  in
  match (resource_name ~project:t.cfg.gcp_project name, auth t) with
  | Error e, _ | _, Error e -> Lwt.return (Error ("gcp-sm: " ^ e))
  | Ok res, Ok auth ->
      let base =
        Option.value ~default:"https://secretmanager.googleapis.com" t.cfg.gcp_endpoint
      in
      let base =
        if String.length base > 0 && base.[String.length base - 1] = '/' then
          String.sub base 0 (String.length base - 1)
        else base
      in
      let uri = Uri.of_string (Printf.sprintf "%s/v1/%s:access" base res) in
      let rec attempt ~retried =
        Gcp_auth.token auth >>= function
        | Error e -> Lwt.return (Error ("gcp-sm: " ^ e))
        | Ok tok -> (
            Http.request ~timeout:t.timeout
              ~headers:[ ("authorization", "Bearer " ^ tok) ]
              `GET uri
            >>= function
            | Error e -> Lwt.return (Error ("gcp-sm: " ^ e))
            | Ok r when r.status = 401 && not retried ->
                Gcp_auth.invalidate auth;
                attempt ~retried:true
            | Ok r when r.status <> 200 ->
                let st =
                  match Yojson.Safe.from_string r.body with
                  | `Assoc kv -> (
                      match List.assoc_opt "error" kv with
                      | Some e ->
                          Option.value ~default:""
                            (Cloud_util.json_string_field e "status")
                      | None -> "")
                  | _ -> ""
                  | exception _ -> ""
                in
                Lwt.return
                  (Error
                     (Printf.sprintf "gcp-sm: access %s failed: HTTP %d %s" res r.status
                        st))
            | Ok r ->
                Lwt.return
                  (match Yojson.Safe.from_string r.body with
                  | exception _ -> Error "gcp-sm: malformed response"
                  | `Assoc kv -> (
                      match List.assoc_opt "payload" kv with
                      | Some (`Assoc p as pj) -> (
                          match Cloud_util.json_string_field pj "data" with
                          | None -> Error "gcp-sm: response has no payload.data"
                          | Some d -> (
                              match Cloud_util.base64_decode d with
                              | Error _ ->
                                  Error "gcp-sm: payload.data is not valid base64"
                              | Ok v -> (
                                  let crc_ok =
                                    match List.assoc_opt "dataCrc32c" p with
                                    | Some (`String c) -> (
                                        match Int64.of_string_opt c with
                                        | Some n ->
                                            Int64.equal n
                                              (Int64.logand
                                                 (Int64.of_int32 (Cloud_util.crc32c v))
                                                 0xFFFFFFFFL)
                                        | None -> false)
                                    | Some (`Int n) ->
                                        Int64.equal (Int64.of_int n)
                                          (Int64.logand
                                             (Int64.of_int32 (Cloud_util.crc32c v))
                                             0xFFFFFFFFL)
                                    | None -> true
                                    | Some _ -> false
                                  in
                                  if not crc_ok then
                                    Error
                                      (Printf.sprintf "gcp-sm: CRC32C mismatch for %s" res)
                                  else
                                    match key with
                                    | None -> Ok v
                                    | Some k ->
                                        Cloud_util.json_key
                                          ~what:(Printf.sprintf "gcp-sm secret %s" res)
                                          ~key:k v)))
                      | _ -> Error "gcp-sm: response has no payload")
                  | _ -> Error "gcp-sm: malformed response"))
      in
      attempt ~retried:false
