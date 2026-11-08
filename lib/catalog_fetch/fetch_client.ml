(* Stub: implemented in the foundation commit. *)
type auth = No_auth | Bearer of string
type t = { base : Uri.t }

let create ?ctx:_ ?timeout:_ ?max_pages:_ ?max_body:_ ~base_url _auth =
  Ok { base = Uri.of_string base_url }

let base_url t = t.base
let get_json _ ?query:_ _ = Lwt.return (Error "not implemented")
let post_json _ ?query:_ _ _ = Lwt.return (Error "not implemented")
let paginate _ ~what:_ _ = Lwt.return (Error "not implemented")
let request_count _ = 0
