open Lwt.Infix
module Http = Haltsql_cloud.Http

let rng = lazy (Mirage_crypto_rng_unix.use_default ())
let ensure_rng () = Lazy.force rng

let loopback_host h =
  let h = String.lowercase_ascii h in
  h = "localhost" || h = "::1" || h = "[::1]"
  || (String.length h > 4 && String.sub h 0 4 = "127.")

let check_url ~what u =
  match (Uri.scheme u, Uri.host u) with
  | _, (None | Some "") -> Error (what ^ ": not an absolute URL")
  | Some "https", Some _ | Some "http", Some _ -> (
      if Uri.userinfo u <> None then Error (what ^ ": URL must not contain credentials")
      else if Uri.fragment u <> None then Error (what ^ ": URL must not have a fragment")
      else
        match (Uri.scheme u, Uri.host u) with
        | Some "http", Some h when not (loopback_host h) ->
            Error (what ^ ": http is only allowed for loopback hosts; use https")
        | _ -> Ok ())
  | _ -> Error (what ^ ": unsupported URL scheme")

let basic ~username ~password =
  "Basic " ^ Haltsql_cloud.Cloud_util.base64 (username ^ ":" ^ password)

let origin u =
  ( Option.map String.lowercase_ascii (Uri.scheme u),
    Option.map String.lowercase_ascii (Uri.host u),
    Uri.port u )

let classify_transport msg =
  (* Haltsql_cloud.Http reports an oversized body as "... exceeds N bytes". *)
  let contains s sub =
    let n = String.length s and m = String.length sub in
    let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
    go 0
  in
  if contains msg " exceeds " then Fetch_error.Integrity msg
  else Fetch_error.Unavailable msg

let request ?ctx ?timeout ?max_body ?(headers = []) ?authorization ?body ?(follow = 3)
    meth uri =
  ensure_rng ();
  let first = origin uri in
  let can_follow = match meth with `GET | `HEAD -> true | _ -> false in
  let rec go uri left =
    let headers =
      match authorization with
      | Some a when origin uri = first -> ("authorization", a) :: headers
      | _ -> headers
    in
    Http.request ?ctx ?timeout ?max_body ~headers ?body meth uri >>= function
    | Error m -> Lwt.return (Error (classify_transport m))
    | Ok r when can_follow && List.mem r.status [ 301; 302; 303; 307; 308 ] -> (
        if left <= 0 then
          Lwt.return
            (Error
               (Fetch_error.Protocol
                  (Printf.sprintf "too many redirects from %s" (Http.host_header uri))))
        else
          match Http.header r "location" with
          | None ->
              Lwt.return
                (Error
                   (Fetch_error.Protocol
                      (Printf.sprintf "HTTP %d without a Location" r.status)))
          | Some loc -> (
              let target = Uri.resolve "" uri (Uri.of_string loc) in
              match check_url ~what:"redirect target" target with
              | Error e -> Lwt.return (Error (Fetch_error.Protocol e))
              | Ok () -> go target (left - 1)))
    | Ok r -> Lwt.return (Ok r)
  in
  go uri follow
