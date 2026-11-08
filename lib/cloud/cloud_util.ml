(** Helpers shared by the cloud integrations; see cloud_util.mli. *)

let unescape_xml s =
  let reps =
    [ ("&lt;", "<"); ("&gt;", ">"); ("&quot;", "\""); ("&apos;", "'"); ("&amp;", "&") ]
  in
  let b = Buffer.create (String.length s) in
  let n = String.length s in
  let rec go i =
    if i >= n then ()
    else if s.[i] = '&' then (
      match
        List.find_opt
          (fun (e, _) -> i + String.length e <= n && String.sub s i (String.length e) = e)
          reps
      with
      | Some (e, r) ->
          Buffer.add_string b r;
          go (i + String.length e)
      | None ->
          Buffer.add_char b '&';
          go (i + 1))
    else begin
      Buffer.add_char b s.[i];
      go (i + 1)
    end
  in
  go 0;
  Buffer.contents b

let find_sub s sub from =
  let n = String.length s and m = String.length sub in
  let rec go i =
    if i + m > n then None else if String.sub s i m = sub then Some i else go (i + 1)
  in
  go from

let xml_tag body name =
  let o = "<" ^ name ^ ">" and c = "</" ^ name ^ ">" in
  match find_sub body o 0 with
  | None -> None
  | Some i -> (
      let start = i + String.length o in
      match find_sub body c start with
      | None -> None
      | Some j -> Some (unescape_xml (String.trim (String.sub body start (j - start)))))

let parse_rfc3339 s =
  match Ptime.of_rfc3339 (String.trim s) with
  | Ok (t, _, _) -> Some (Ptime.to_float_s t)
  | Error _ -> None

let rfc3339 t =
  let tm = Unix.gmtime t in
  Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ" (tm.tm_year + 1900) (tm.tm_mon + 1)
    tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec

let json_string_field j k =
  match j with
  | `Assoc kv -> (
      match List.assoc_opt k kv with Some (`String s) -> Some s | _ -> None)
  | _ -> None

let scalar_to_string : Yojson.Safe.t -> string option = function
  | `String s -> Some s
  | `Int i -> Some (string_of_int i)
  | `Intlit s -> Some s
  | `Float f -> Some (Yojson.Safe.to_string (`Float f))
  | `Bool b -> Some (string_of_bool b)
  | _ -> None

let json_key ~what ~key v =
  match Yojson.Safe.from_string v with
  | exception _ ->
      Error (Printf.sprintf "%s is not a JSON object, cannot select key %S" what key)
  | `Assoc kv -> (
      match List.assoc_opt key kv with
      | None -> Error (Printf.sprintf "key %S not found in %s" key what)
      | Some x -> (
          match scalar_to_string x with
          | Some s -> Ok s
          | None -> Error (Printf.sprintf "key %S in %s is not a scalar" key what)))
  | _ -> Error (Printf.sprintf "%s is not a JSON object, cannot select key %S" what key)

let read_file ?(limit = 1024 * 1024) path =
  match
    In_channel.with_open_bin path (fun ic ->
        if Int64.compare (In_channel.length ic) (Int64.of_int limit) > 0 then None
        else Some (In_channel.input_all ic))
  with
  | exception Sys_error m -> Error m
  | None -> Error (Printf.sprintf "%s is larger than %d bytes" path limit)
  | Some s -> Ok s

let crc32c_table =
  lazy
    (Array.init 256 (fun n ->
         let c = ref (Int32.of_int n) in
         for _ = 0 to 7 do
           if Int32.logand !c 1l <> 0l then
             c := Int32.logxor 0x82F63B78l (Int32.shift_right_logical !c 1)
           else c := Int32.shift_right_logical !c 1
         done;
         !c))

let crc32c s =
  let t = Lazy.force crc32c_table in
  let c = ref 0xFFFFFFFFl in
  String.iter
    (fun ch ->
      let idx =
        Int32.to_int (Int32.logand (Int32.logxor !c (Int32.of_int (Char.code ch))) 0xFFl)
      in
      c := Int32.logxor t.(idx) (Int32.shift_right_logical !c 8))
    s;
  Int32.logxor !c 0xFFFFFFFFl

let base64 s = Base64.encode_string s

let base64url_nopad s =
  Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet s

let base64_decode s =
  match Base64.decode (String.trim s) with
  | Ok v -> Ok v
  | Error (`Msg m) -> Error ("invalid base64: " ^ m)
