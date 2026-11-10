(** Buffered transport; see io.mli. *)

open Lwt.Syntax

exception Closed
exception Too_large of int

type kind = Plain | Tls of Tls_lwt.Unix.t

type t = {
  fd : Lwt_unix.file_descr;
  kind : kind;
  buf : Bytes.t;
  mutable pos : int;
  mutable len : int;
  wlock : Lwt_mutex.t;
  mutable closed : bool;
}

let make fd kind =
  {
    fd;
    kind;
    buf = Bytes.create 16384;
    pos = 0;
    len = 0;
    wlock = Lwt_mutex.create ();
    closed = false;
  }

let of_fd fd = make fd Plain
let of_tls fd t = make fd (Tls t)
let fd t = t.fd
let tls t = match t.kind with Tls s -> Some s | Plain -> None
let buffered t = t.len - t.pos

let refill t =
  let* n =
    match t.kind with
    | Plain -> Lwt_unix.read t.fd t.buf 0 (Bytes.length t.buf)
    | Tls s ->
        (* Never cancelled: tls-lwt records any exception of a read, including the
           [Lwt.Canceled] of a read abandoned by [Lwt.pick] or a timeout, as the failure
           of the whole connection and refuses every later write. The FATAL error that
           ends a session is written after exactly such a cancellation. The read ends
           when the connection is closed. *)
        Lwt.no_cancel
          (Lwt.catch
             (fun () -> Tls_lwt.Unix.read s t.buf)
             (function End_of_file -> Lwt.return 0 | e -> Lwt.fail e))
  in
  if n <= 0 then Lwt.fail Closed
  else begin
    t.pos <- 0;
    t.len <- n;
    Lwt.return_unit
  end

let read_exact t n =
  let out = Bytes.create n in
  let rec go off =
    if off >= n then Lwt.return (Bytes.unsafe_to_string out)
    else if t.pos < t.len then begin
      let k = min (n - off) (t.len - t.pos) in
      Bytes.blit t.buf t.pos out off k;
      t.pos <- t.pos + k;
      go (off + k)
    end
    else
      let* () = refill t in
      go off
  in
  go 0

let read_byte t =
  let* s = read_exact t 1 in
  Lwt.return s.[0]

let read_len t =
  let* s = read_exact t 4 in
  Lwt.return (Int32.to_int (String.get_int32_be s 0))

let read_startup t ~max =
  let* len = read_len t in
  if len < 8 then Lwt.fail (Wire.Malformed "invalid startup packet length")
  else if len > max then Lwt.fail (Too_large len)
  else read_exact t (len - 4)

let read_message t ~max =
  let* tag = read_byte t in
  let* len = read_len t in
  if len < 4 then Lwt.fail (Wire.Malformed "invalid message length")
  else if len - 4 > max then Lwt.fail (Too_large len)
  else
    let* payload = read_exact t (len - 4) in
    Lwt.return (tag, payload)

let write t s =
  Lwt_mutex.with_lock t.wlock (fun () ->
      if t.closed then Lwt.fail Closed
      else
        match t.kind with
        | Tls sess -> Tls_lwt.Unix.write sess s
        | Plain ->
            let b = Bytes.unsafe_of_string s in
            let n = Bytes.length b in
            let rec go off =
              if off >= n then Lwt.return_unit
              else
                let* k = Lwt_unix.write t.fd b off (n - off) in
                if k <= 0 then Lwt.fail Closed else go (off + k)
            in
            go 0)

let close t =
  if t.closed then Lwt.return_unit
  else begin
    t.closed <- true;
    Lwt.catch
      (fun () ->
        match t.kind with Tls s -> Tls_lwt.Unix.close s | Plain -> Lwt_unix.close t.fd)
      (fun _ -> Lwt.return_unit)
  end
