(** Bounded HTTP client (deadline, size cap, explicit connection lifetime); see http.mli.
*)

open Lwt.Infix

type response = { status : int; headers : (string * string) list; body : string }
type ctx = Cohttp_lwt_unix.Net.ctx option

let default_ctx = None

let ctx_of_ca_file path =
  match In_channel.with_open_bin path In_channel.input_all with
  | exception Sys_error m -> Lwt.return (Error ("cannot read CA file: " ^ m))
  | pem -> (
      match X509.Certificate.decode_pem_multiple pem with
      | Error (`Msg m) -> Lwt.return (Error ("invalid CA file " ^ path ^ ": " ^ m))
      | Ok [] -> Lwt.return (Error ("CA file " ^ path ^ " contains no certificate"))
      | Ok certs ->
          let tls_authenticator =
            X509.Authenticator.chain_of_trust
              ~time:(fun () -> Some (Ptime_clock.now ()))
              certs
          in
          Lwt.catch
            (fun () ->
              Conduit_lwt_unix.init ~tls_authenticator () >|= fun ctx ->
              Ok (Some (Cohttp_lwt_unix.Net.init ~ctx ())))
            (fun e -> Lwt.return (Error ("TLS setup failed: " ^ Printexc.to_string e))))

let header r name =
  let name = String.lowercase_ascii name in
  List.find_map
    (fun (k, v) -> if String.lowercase_ascii k = name then Some v else None)
    r.headers

let is_unreserved c =
  (c >= 'A' && c <= 'Z')
  || (c >= 'a' && c <= 'z')
  || (c >= '0' && c <= '9')
  || c = '-' || c = '_' || c = '.' || c = '~'

let pct_encode ?(keep_slash = false) s =
  let b = Buffer.create (String.length s * 3 / 2) in
  String.iter
    (fun c ->
      if is_unreserved c || (keep_slash && c = '/') then Buffer.add_char b c
      else Buffer.add_string b (Printf.sprintf "%%%02X" (Char.code c)))
    s;
  Buffer.contents b

let form_encode kvs =
  String.concat "&" (List.map (fun (k, v) -> pct_encode k ^ "=" ^ pct_encode v) kvs)

let host_header u =
  let h = Option.value ~default:"" (Uri.host u) in
  let h = if String.contains h ':' then "[" ^ h ^ "]" else h in
  match (Uri.port u, Uri.scheme u) with
  | Some 80, Some "http" | Some 443, Some "https" | None, _ -> h
  | Some p, _ -> Printf.sprintf "%s:%d" h p

let loopback_host h =
  h = "localhost" || h = "::1" || h = "[::1]"
  || (String.length h > 4 && String.sub h 0 4 = "127.")

let is_loopback_http s =
  let u = Uri.of_string s in
  Uri.scheme u = Some "http"
  && match Uri.host u with Some h -> loopback_host h | None -> false

let check_endpoint ~what s =
  let u = Uri.of_string s in
  match (Uri.scheme u, Uri.host u) with
  | _, (None | Some "") -> Error (Printf.sprintf "%s: %S is not an absolute URL" what s)
  | (Some "https", _ | Some "http", _)
    when Uri.scheme u = Some "https" || is_loopback_http s ->
      if Uri.userinfo u <> None then Error (what ^ ": URL must not contain credentials")
      else if Uri.query u <> [] || Uri.fragment u <> None then
        Error (what ^ ": URL must not have a query or fragment")
      else Ok u
  | Some "http", _ -> Error (what ^ ": http is only allowed for loopback hosts; use https")
  | _ -> Error (Printf.sprintf "%s: unsupported URL scheme in %S" what s)

exception Body_too_large

(* Reads [body] into a string, failing with [Body_too_large] as soon as more than
   [max_body] bytes have arrived, whatever the response claims in Content-Length (a
   chunked or lying server cannot make us buffer more than the cap). *)
let read_capped ~max_body body =
  let buf = Buffer.create 4096 in
  Lwt_stream.iter
    (fun chunk ->
      if Buffer.length buf + String.length chunk > max_body then raise Body_too_large;
      Buffer.add_string buf chunk)
    (Cohttp_lwt.Body.to_stream body)
  >|= fun () -> Buffer.contents buf

let request ?(ctx = default_ctx) ?(timeout = 10.) ?(max_body = 8 * 1024 * 1024)
    ?(headers = []) ?body meth uri =
  let headers = Cohttp.Header.of_list headers in
  let body = Option.map Cohttp_lwt.Body.of_string body in
  let net_ctx =
    match ctx with Some c -> c | None -> Lazy.force Cohttp_lwt_unix.Net.default_ctx
  in
  (* One explicit connection per request, closed on every exit path (success, oversized
     body, timeout cancellation, exception). With [Cohttp_lwt_unix.Client] a response
     whose body is abandoned half-read keeps its socket open. *)
  let call () =
    Cohttp_lwt_unix.Net.resolve ~ctx:net_ctx uri >>= fun endp ->
    Cohttp_lwt_unix.Connection.connect ~ctx:net_ctx ~persistent:true endp >>= fun conn ->
    Lwt.finalize
      (fun () ->
        Cohttp_lwt_unix.Connection.call conn ~headers ?body meth uri
        >>= fun (resp, rbody) ->
        let status = Cohttp.Code.code_of_status (Cohttp.Response.status resp) in
        let rh = Cohttp.Header.to_list (Cohttp.Response.headers resp) in
        let declared_too_big =
          match
            List.assoc_opt "content-length"
              (List.map (fun (k, v) -> (String.lowercase_ascii k, v)) rh)
          with
          | Some l -> (
              match int_of_string_opt (String.trim l) with
              | Some n -> n > max_body
              | None -> false)
          | None -> false
        in
        if declared_too_big then Lwt.return `Too_big
        else
          Lwt.catch
            (fun () ->
              read_capped ~max_body rbody >|= fun b ->
              `Ok { status; headers = rh; body = b })
            (function Body_too_large -> Lwt.return `Too_big | e -> Lwt.reraise e))
      (fun () ->
        Cohttp_lwt_unix.Connection.close conn;
        Lwt.return_unit)
  in
  Lwt.catch
    (fun () -> Lwt.pick [ call (); (Lwt_unix.sleep timeout >|= fun () -> `Timeout) ])
    (fun e -> Lwt.return (`Exn e))
  >|= function
  | `Ok r -> Ok r
  | `Too_big ->
      Error
        (Printf.sprintf "response from %s exceeds %d bytes" (host_header uri) max_body)
  | `Timeout ->
      Error (Printf.sprintf "request to %s timed out after %gs" (host_header uri) timeout)
  | `Exn e ->
      let m =
        match e with
        | Unix.Unix_error (e, _, _) -> Unix.error_message e
        | Failure m | Invalid_argument m -> m
        | e -> Printexc.to_string e
      in
      Error (Printf.sprintf "request to %s failed: %s" (host_header uri) m)
