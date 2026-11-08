(* In-process HTTP server on 127.0.0.1:<ephemeral> for tests. The handler gets
   the request and its full body. *)
open Lwt.Infix

type t = {
  port : int;
  stop : unit -> unit;
  mutable requests : (Cohttp.Request.t * string) list;
}

let start
    (handler :
      Cohttp.Request.t -> string -> (Cohttp.Response.t * Cohttp_lwt.Body.t) Lwt.t) =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  Unix.bind (Lwt_unix.unix_file_descr fd) (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  Lwt_unix.listen fd 128;
  let port =
    match Unix.getsockname (Lwt_unix.unix_file_descr fd) with
    | Unix.ADDR_INET (_, p) -> p
    | _ -> assert false
  in
  let stop_p, stopper = Lwt.wait () in
  let t =
    {
      port;
      stop = (fun () -> if Lwt.is_sleeping stop_p then Lwt.wakeup_later stopper ());
      requests = [];
    }
  in
  let callback _conn req body =
    Cohttp_lwt.Body.to_string body >>= fun b ->
    t.requests <- t.requests @ [ (req, b) ];
    handler req b
  in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~stop:stop_p ~on_exn:ignore
        ~mode:(`TCP (`Socket fd))
        (Cohttp_lwt_unix.Server.make ~callback ()));
  t

let respond ?(headers = []) ?(status = 200) body =
  Cohttp_lwt_unix.Server.respond_string
    ~headers:(Cohttp.Header.of_list headers)
    ~status:(Cohttp.Code.status_of_code status)
    ~body ()

let url t path = Printf.sprintf "http://127.0.0.1:%d%s" t.port path

let header (req : Cohttp.Request.t) name =
  Cohttp.Header.get (Cohttp.Request.headers req) name

let path (req : Cohttp.Request.t) = Uri.path (Cohttp.Request.uri req)
