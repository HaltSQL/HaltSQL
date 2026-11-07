(* PostgreSQL protocol v3 codecs; see wire.mli. *)

exception Malformed of string

let malformed fmt = Printf.ksprintf (fun s -> raise (Malformed s)) fmt

let add_int32 b n =
  Buffer.add_char b (Char.unsafe_chr ((n lsr 24) land 0xff));
  Buffer.add_char b (Char.unsafe_chr ((n lsr 16) land 0xff));
  Buffer.add_char b (Char.unsafe_chr ((n lsr 8) land 0xff));
  Buffer.add_char b (Char.unsafe_chr (n land 0xff))

let add_int16 b n =
  Buffer.add_char b (Char.unsafe_chr ((n lsr 8) land 0xff));
  Buffer.add_char b (Char.unsafe_chr (n land 0xff))

let add_cstring b s =
  if String.contains s '\000' then malformed "string contains a NUL byte";
  Buffer.add_string b s;
  Buffer.add_char b '\000'

let frame tag payload =
  let b = Buffer.create (String.length payload + 5) in
  Buffer.add_char b tag;
  add_int32 b (String.length payload + 4);
  Buffer.add_string b payload;
  Buffer.contents b

let frame_untagged body =
  let b = Buffer.create (String.length body + 4) in
  add_int32 b (String.length body + 4);
  Buffer.add_string b body;
  Buffer.contents b

let build f =
  let b = Buffer.create 64 in
  f b;
  Buffer.contents b

(* ------------------------------------------------------------------ *)

type cursor = { s : string; mutable pos : int }

let cursor s = { s; pos = 0 }
let remaining c = String.length c.s - c.pos

let need c n =
  if n < 0 || remaining c < n then malformed "truncated message (need %d bytes)" n

let get_int32 c =
  need c 4;
  let v = String.get_int32_be c.s c.pos in
  c.pos <- c.pos + 4;
  Int32.to_int v

let get_int16 c =
  need c 2;
  let v = String.get_int16_be c.s c.pos in
  c.pos <- c.pos + 2;
  v

let get_cstring c =
  match String.index_from_opt c.s c.pos '\000' with
  | None -> malformed "missing NUL terminator"
  | Some i ->
      let v = String.sub c.s c.pos (i - c.pos) in
      c.pos <- i + 1;
      v

let get_bytes c n =
  need c n;
  let v = String.sub c.s c.pos n in
  c.pos <- c.pos + n;
  v

let get_rest c = get_bytes c (remaining c)
let at_end c = remaining c = 0
let expect_end c = if not (at_end c) then malformed "%d trailing bytes" (remaining c)

(* ------------------------------------------------------------------ *)

let ssl_request_code = 80877103
let gssenc_request_code = 80877104
let cancel_request_code = 80877102
let protocol_3_0 = 196608

type startup =
  | Ssl_request
  | Gssenc_request
  | Cancel_request of { pid : int; key : int }
  | Startup of { major : int; minor : int; params : (string * string) list }

let decode_startup body =
  let c = cursor body in
  let code = get_int32 c land 0xffffffff in
  if code = ssl_request_code then (
    expect_end c;
    Ssl_request)
  else if code = gssenc_request_code then (
    expect_end c;
    Gssenc_request)
  else if code = cancel_request_code then (
    let pid = get_int32 c in
    let key = get_int32 c in
    expect_end c;
    Cancel_request { pid; key })
  else
    let major = code lsr 16 and minor = code land 0xffff in
    if major <> 3 then malformed "unsupported frontend protocol %d.%d" major minor;
    let rec params acc =
      let k = get_cstring c in
      if k = "" then List.rev acc
      else
        let v = get_cstring c in
        if List.mem_assoc k acc then malformed "duplicate startup parameter %S" k;
        params ((k, v) :: acc)
    in
    let ps = params [] in
    expect_end c;
    Startup { major; minor; params = ps }

let encode_startup params =
  frame_untagged
    (build (fun b ->
         add_int32 b protocol_3_0;
         List.iter
           (fun (k, v) ->
             add_cstring b k;
             add_cstring b v)
           params;
         Buffer.add_char b '\000'))

let encode_cancel ~pid ~key =
  frame_untagged
    (build (fun b ->
         add_int32 b cancel_request_code;
         add_int32 b pid;
         add_int32 b key))

let encode_ssl_request = frame_untagged (build (fun b -> add_int32 b ssl_request_code))

(* ------------------------------------------------------------------ *)

type parse = { stmt : string; query : string; param_types : int list }

type bind = {
  portal : string;
  bstmt : string;
  param_formats : int list;
  params : string option list;
  result_formats : int list;
}

let decode_query p =
  let c = cursor p in
  let q = get_cstring c in
  expect_end c;
  q

let count c what =
  let n = get_int16 c in
  if n < 0 then malformed "negative %s count" what;
  n

let decode_parse p =
  let c = cursor p in
  let stmt = get_cstring c in
  let query = get_cstring c in
  let n = count c "parameter type" in
  let param_types = List.init n (fun _ -> get_int32 c) in
  expect_end c;
  { stmt; query; param_types }

let encode_parse { stmt; query; param_types } =
  frame 'P'
    (build (fun b ->
         add_cstring b stmt;
         add_cstring b query;
         add_int16 b (List.length param_types);
         List.iter (add_int32 b) param_types))

let decode_bind p =
  let c = cursor p in
  let portal = get_cstring c in
  let bstmt = get_cstring c in
  let nf = count c "format code" in
  let param_formats =
    List.init nf (fun _ ->
        let f = get_int16 c in
        if f <> 0 && f <> 1 then malformed "invalid format code %d" f;
        f)
  in
  let np = count c "parameter" in
  let params =
    List.init np (fun _ ->
        let len = get_int32 c in
        if len = -1 then None
        else if len < 0 then malformed "invalid parameter length %d" len
        else Some (get_bytes c len))
  in
  let nr = count c "result format" in
  let result_formats =
    List.init nr (fun _ ->
        let f = get_int16 c in
        if f <> 0 && f <> 1 then malformed "invalid format code %d" f;
        f)
  in
  expect_end c;
  if nf > 1 && nf <> np then malformed "bind has %d format codes for %d parameters" nf np;
  { portal; bstmt; param_formats; params; result_formats }

let encode_bind b =
  frame 'B'
    (build (fun buf ->
         add_cstring buf b.portal;
         add_cstring buf b.bstmt;
         add_int16 buf (List.length b.param_formats);
         List.iter (add_int16 buf) b.param_formats;
         add_int16 buf (List.length b.params);
         List.iter
           (function
             | None -> add_int32 buf (-1)
             | Some v ->
                 add_int32 buf (String.length v);
                 Buffer.add_string buf v)
           b.params;
         add_int16 buf (List.length b.result_formats);
         List.iter (add_int16 buf) b.result_formats))

let param_format b i =
  match b.param_formats with
  | [] -> 0
  | [ f ] -> f
  | fs when List.length fs = List.length b.params -> List.nth fs i
  | _ -> malformed "format code count does not match parameter count"

let decode_describe_or_close p =
  let c = cursor p in
  let kind = get_bytes c 1 in
  let name = get_cstring c in
  expect_end c;
  match kind.[0] with
  | ('S' | 'P') as k -> (k, name)
  | k -> malformed "invalid describe/close target %C" k

let decode_execute p =
  let c = cursor p in
  let portal = get_cstring c in
  let rows = get_int32 c in
  expect_end c;
  (portal, rows)

let decode_sasl_initial p =
  let c = cursor p in
  let mech = get_cstring c in
  let len = get_int32 c in
  let data =
    if len = -1 then None
    else if len < 0 then malformed "invalid SASL response length"
    else Some (get_bytes c len)
  in
  expect_end c;
  (mech, data)

(* ------------------------------------------------------------------ *)

let auth_ok = frame 'R' (build (fun b -> add_int32 b 0))

let auth_sasl mechs =
  frame 'R'
    (build (fun b ->
         add_int32 b 10;
         List.iter (add_cstring b) mechs;
         Buffer.add_char b '\000'))

let auth_sasl_continue data =
  frame 'R'
    (build (fun b ->
         add_int32 b 11;
         Buffer.add_string b data))

let auth_sasl_final data =
  frame 'R'
    (build (fun b ->
         add_int32 b 12;
         Buffer.add_string b data))

let backend_key_data ~pid ~key =
  frame 'K'
    (build (fun b ->
         add_int32 b pid;
         add_int32 b key))

let ready_for_query st = frame 'Z' (String.make 1 st)

let parameter_status k v =
  frame 'S'
    (build (fun b ->
         add_cstring b k;
         add_cstring b v))

let negotiate_protocol_version ~minor opts =
  frame 'v'
    (build (fun b ->
         add_int32 b ((3 lsl 16) lor minor);
         add_int32 b (List.length opts);
         List.iter (add_cstring b) opts))

(* Field values must not contain NUL; replace any with '?' rather than fail. *)
let sanitize s = String.map (fun ch -> if ch = '\000' then '?' else ch) s

let error_response fields =
  frame 'E'
    (build (fun b ->
         List.iter
           (fun (k, v) ->
             Buffer.add_char b k;
             add_cstring b (sanitize v))
           fields;
         Buffer.add_char b '\000'))

let decode_fields p =
  let c = cursor p in
  let rec go acc =
    let t = get_bytes c 1 in
    if t.[0] = '\000' then List.rev acc
    else
      let v = get_cstring c in
      go ((t.[0], v) :: acc)
  in
  let fs = go [] in
  expect_end c;
  fs

type auth_request =
  | Auth_ok
  | Auth_cleartext
  | Auth_md5 of string
  | Auth_sasl of string list
  | Auth_sasl_continue of string
  | Auth_sasl_final of string
  | Auth_other of int

let decode_auth p =
  let c = cursor p in
  match get_int32 c with
  | 0 ->
      expect_end c;
      Auth_ok
  | 3 ->
      expect_end c;
      Auth_cleartext
  | 5 ->
      let salt = get_bytes c 4 in
      expect_end c;
      Auth_md5 salt
  | 10 ->
      let rec go acc =
        let m = get_cstring c in
        if m = "" then List.rev acc else go (m :: acc)
      in
      let ms = go [] in
      expect_end c;
      Auth_sasl ms
  | 11 -> Auth_sasl_continue (get_rest c)
  | 12 -> Auth_sasl_final (get_rest c)
  | n -> Auth_other n

let sasl_initial_response ~mechanism data =
  frame 'p'
    (build (fun b ->
         add_cstring b mechanism;
         add_int32 b (String.length data);
         Buffer.add_string b data))

let sasl_response data = frame 'p' data
let password_message pw = frame 'p' (build (fun b -> add_cstring b pw))
