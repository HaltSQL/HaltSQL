(* PostgreSQL connection strings (see pg_dsn.mli). *)

type sslmode = Disable | Prefer | Require | Verify_ca | Verify_full

let sslmode_to_string = function
  | Disable -> "disable"
  | Prefer -> "prefer"
  | Require -> "require"
  | Verify_ca -> "verify-ca"
  | Verify_full -> "verify-full"

let sslmode_of_string = function
  | "disable" -> Some Disable
  | "allow" | "prefer" -> Some Prefer
  | "require" -> Some Require
  | "verify-ca" -> Some Verify_ca
  | "verify-full" -> Some Verify_full
  | _ -> None

type t = {
  host : string;
  port : int;
  user : string;
  password : string option;
  dbname : string;
  sslmode : sslmode;
  sslrootcert : string option;
  connect_timeout : float option;
  application_name : string option;
}

let ( let* ) = Result.bind

let is_loopback h =
  (String.length h > 0 && h.[0] = '/') (* Unix-domain socket directory *)
  || Haltsql_core.Loopback.is_host h

let hex_val c =
  match c with
  | '0' .. '9' -> Some (Char.code c - 48)
  | 'a' .. 'f' -> Some (Char.code c - 87)
  | 'A' .. 'F' -> Some (Char.code c - 55)
  | _ -> None

(* Percent-decoding. [what] names the component for error messages (never its value,
   which could be the password). *)
let pct_decode ~what s =
  let n = String.length s in
  let b = Buffer.create n in
  let rec go i =
    if i >= n then Ok (Buffer.contents b)
    else if s.[i] = '%' then
      if i + 2 >= n then Error (Printf.sprintf "invalid percent-encoding in %s" what)
      else
        match (hex_val s.[i + 1], hex_val s.[i + 2]) with
        | Some h, Some l ->
            Buffer.add_char b (Char.chr ((h * 16) + l));
            go (i + 3)
        | _ -> Error (Printf.sprintf "invalid percent-encoding in %s" what)
    else begin
      Buffer.add_char b s.[i];
      go (i + 1)
    end
  in
  go 0

let index_from_opt s i c = try Some (String.index_from s i c) with Not_found -> None
let rindex_opt s c = try Some (String.rindex s c) with Not_found -> None

let known_params =
  [
    "host";
    "hostaddr";
    "port";
    "user";
    "password";
    "dbname";
    "sslmode";
    "sslrootcert";
    "connect_timeout";
    "application_name";
  ]

(* Raw settings collected from either syntax, before defaults. *)
type raw = (string * string) list

let parse_url s : (raw, string) result =
  let prefix =
    if String.starts_with ~prefix:"postgresql://" s then 13
    else if String.starts_with ~prefix:"postgres://" s then 11
    else 0
  in
  let rest = String.sub s prefix (String.length s - prefix) in
  let rest, query =
    match String.index_opt rest '?' with
    | Some i ->
        (String.sub rest 0 i, Some (String.sub rest (i + 1) (String.length rest - i - 1)))
    | None -> (rest, None)
  in
  let authority, path =
    match String.index_opt rest '/' with
    | Some i ->
        (String.sub rest 0 i, Some (String.sub rest (i + 1) (String.length rest - i - 1)))
    | None -> (rest, None)
  in
  let userinfo, hostport =
    match rindex_opt authority '@' with
    | Some i ->
        ( Some (String.sub authority 0 i),
          String.sub authority (i + 1) (String.length authority - i - 1) )
    | None -> (None, authority)
  in
  let* user_kv =
    match userinfo with
    | None -> Ok []
    | Some ui -> (
        match String.index_opt ui ':' with
        | Some i ->
            let* u = pct_decode ~what:"user" (String.sub ui 0 i) in
            let* p =
              pct_decode ~what:"password"
                (String.sub ui (i + 1) (String.length ui - i - 1))
            in
            Ok ((if u = "" then [] else [ ("user", u) ]) @ [ ("password", p) ])
        | None ->
            let* u = pct_decode ~what:"user" ui in
            Ok (if u = "" then [] else [ ("user", u) ]))
  in
  let* host_kv =
    if hostport = "" then Ok []
    else if hostport.[0] = '[' then
      match String.index_opt hostport ']' with
      | None -> Error "unterminated IPv6 address in DSN host"
      | Some j ->
          let h = String.sub hostport 1 (j - 1) in
          let after = String.sub hostport (j + 1) (String.length hostport - j - 1) in
          if after = "" then Ok [ ("host", h) ]
          else if after.[0] = ':' then
            Ok [ ("host", h); ("port", String.sub after 1 (String.length after - 1)) ]
          else Error "unexpected characters after IPv6 address in DSN host"
    else
      match String.index_opt hostport ',' with
      | Some _ -> Error "multiple hosts in a DSN are not supported"
      | None -> (
          match rindex_opt hostport ':' with
          | Some i ->
              let* h = pct_decode ~what:"host" (String.sub hostport 0 i) in
              Ok
                ((if h = "" then [] else [ ("host", h) ])
                @ [
                    ("port", String.sub hostport (i + 1) (String.length hostport - i - 1));
                  ])
          | None ->
              let* h = pct_decode ~what:"host" hostport in
              Ok [ ("host", h) ])
  in
  let* db_kv =
    match path with
    | None | Some "" -> Ok []
    | Some p ->
        let* d = pct_decode ~what:"dbname" p in
        Ok [ ("dbname", d) ]
  in
  let* q_kv =
    match query with
    | None | Some "" -> Ok []
    | Some q ->
        let parts = String.split_on_char '&' q |> List.filter (fun x -> x <> "") in
        List.fold_left
          (fun acc part ->
            let* acc = acc in
            match String.index_opt part '=' with
            | None -> Error (Printf.sprintf "DSN parameter %S has no value" part)
            | Some i ->
                let* k = pct_decode ~what:"parameter name" (String.sub part 0 i) in
                let* v =
                  pct_decode ~what:("parameter " ^ k)
                    (String.sub part (i + 1) (String.length part - i - 1))
                in
                Ok (acc @ [ (k, v) ]))
          (Ok []) parts
  in
  Ok (user_kv @ host_kv @ db_kv @ q_kv)

let parse_keywords s : (raw, string) result =
  let n = String.length s in
  let is_space c = c = ' ' || c = '\t' || c = '\n' || c = '\r' in
  let rec skip i = if i < n && is_space s.[i] then skip (i + 1) else i in
  let rec go i acc =
    let i = skip i in
    if i >= n then Ok (List.rev acc)
    else
      match index_from_opt s i '=' with
      | None -> Error "malformed DSN: expected key=value"
      | Some eq ->
          let key = String.trim (String.sub s i (eq - i)) in
          if key = "" || String.exists is_space key then
            Error "malformed DSN: expected key=value"
          else
            let j = skip (eq + 1) in
            if j < n && s.[j] = '\'' then begin
              let b = Buffer.create 16 in
              let rec q k =
                if k >= n then
                  Error (Printf.sprintf "unterminated quoted value for %s" key)
                else if s.[k] = '\\' && k + 1 < n then begin
                  Buffer.add_char b s.[k + 1];
                  q (k + 2)
                end
                else if s.[k] = '\'' then Ok (k + 1)
                else begin
                  Buffer.add_char b s.[k];
                  q (k + 1)
                end
              in
              let* k = q (j + 1) in
              go k ((key, Buffer.contents b) :: acc)
            end
            else begin
              let k = ref j in
              while !k < n && not (is_space s.[!k]) do
                incr k
              done;
              go !k ((key, String.sub s j (!k - j)) :: acc)
            end
  in
  go 0 []

let parse ?(env = Sys.getenv_opt) s =
  let s = String.trim s in
  let* raw =
    if
      String.starts_with ~prefix:"postgres://" s
      || String.starts_with ~prefix:"postgresql://" s
    then parse_url s
    else if s = "" then Ok []
    else parse_keywords s
  in
  let* () =
    List.fold_left
      (fun acc (k, _) ->
        let* () = acc in
        if List.mem k known_params then Ok ()
        else Error (Printf.sprintf "unknown DSN parameter %S" k))
      (Ok ()) raw
  in
  let get k = match List.assoc_opt k (List.rev raw) with Some "" -> None | x -> x in
  let env_nonempty k = match env k with Some "" -> None | x -> x in
  let host =
    match (get "host", get "hostaddr") with
    | Some h, _ | None, Some h -> h
    | None, None -> Option.value (env_nonempty "PGHOST") ~default:"localhost"
  in
  let* port =
    let p = match get "port" with Some p -> Some p | None -> env_nonempty "PGPORT" in
    match p with
    | None -> Ok 5432
    | Some p -> (
        match int_of_string_opt p with
        | Some n
          when n > 0 && n < 65536 && String.for_all (fun c -> c >= '0' && c <= '9') p ->
            Ok n
        | _ -> Error (Printf.sprintf "invalid port %S" p))
  in
  let user =
    match get "user" with
    | Some u -> u
    | None -> (
        match env_nonempty "PGUSER" with
        | Some u -> u
        | None -> Option.value (env_nonempty "USER") ~default:"postgres")
  in
  let password =
    match List.assoc_opt "password" (List.rev raw) with
    | Some p -> Some p
    | None -> env "PGPASSWORD"
  in
  let dbname =
    match get "dbname" with
    | Some d -> d
    | None -> Option.value (env_nonempty "PGDATABASE") ~default:user
  in
  let* sslmode =
    match
      match get "sslmode" with Some m -> Some m | None -> env_nonempty "PGSSLMODE"
    with
    | None -> Ok (if is_loopback host then Prefer else Require)
    | Some m -> (
        match sslmode_of_string m with
        | Some m -> Ok m
        | None ->
            Error
              (Printf.sprintf
                 "invalid sslmode %S (expected disable, prefer, require, verify-ca or \
                  verify-full)"
                 m))
  in
  let sslrootcert =
    match get "sslrootcert" with Some c -> Some c | None -> env_nonempty "PGSSLROOTCERT"
  in
  let* connect_timeout =
    match get "connect_timeout" with
    | None -> Ok None
    | Some t -> (
        match float_of_string_opt t with
        | Some f when f > 0. && f <= 3600. -> Ok (Some f)
        | _ -> Error (Printf.sprintf "invalid connect_timeout %S" t))
  in
  let* () =
    if String.exists (fun c -> c = '\000') (user ^ dbname ^ host) then
      Error "NUL byte in DSN"
    else Ok ()
  in
  Ok
    {
      host;
      port;
      user;
      password;
      dbname;
      sslmode;
      sslrootcert;
      connect_timeout;
      application_name = get "application_name";
    }

let pct_encode s =
  let b = Buffer.create (String.length s) in
  String.iter
    (fun c ->
      match c with
      | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '_' | '.' | '~' ->
          Buffer.add_char b c
      | c -> Buffer.add_string b (Printf.sprintf "%%%02X" (Char.code c)))
    s;
  Buffer.contents b

let redacted t =
  let host =
    if String.contains t.host ':' then "[" ^ t.host ^ "]" else pct_encode t.host
  in
  Printf.sprintf "postgres://%s@%s:%d/%s?sslmode=%s" (pct_encode t.user) host t.port
    (pct_encode t.dbname) (sslmode_to_string t.sslmode)
