type credentials = {
  access_key_id : string;
  secret_access_key : string;
  session_token : string option;
}

let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))
let hmac_sha256 ~key s = Digestif.SHA256.(to_raw_string (hmac_string ~key s))

let to_hex s =
  let b = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string b (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents b

let amz_date t =
  let tm = Unix.gmtime t in
  Printf.sprintf "%04d%02d%02dT%02d%02d%02dZ" (tm.tm_year + 1900) (tm.tm_mon + 1)
    tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec

(* S3: the decoded path, percent-encoded once (every byte outside
   [A-Za-z0-9-_.~/]). This must not depend on how the path happens to be
   spelled on the wire: ocaml-uri turns "%3D" back into "=" (and likewise for
   the other sub-delims), while S3 and S3-compatible servers canonicalise the
   decoded key, so signing the wire spelling fails for keys containing
   = : + @ , ; etc. *)
let canonical_uri ~s3 path =
  let path = if path = "" then "/" else path in
  if s3 then Http.pct_encode ~keep_slash:true (Uri.pct_decode path)
  else Http.pct_encode ~keep_slash:true path

let canonical_query q =
  List.map (fun (k, v) -> (Http.pct_encode k, Http.pct_encode v)) q
  |> List.sort compare
  |> List.map (fun (k, v) -> k ^ "=" ^ v)
  |> String.concat "&"

let collapse v =
  let v = String.trim v in
  let b = Buffer.create (String.length v) in
  let prev_space = ref false in
  String.iter
    (fun c ->
      if c = ' ' || c = '\t' then begin
        if not !prev_space then Buffer.add_char b ' ';
        prev_space := true
      end
      else begin
        Buffer.add_char b c;
        prev_space := false
      end)
    v;
  Buffer.contents b

let canonical_headers headers =
  let hs =
    List.map (fun (k, v) -> (String.lowercase_ascii (String.trim k), collapse v)) headers
  in
  let names = List.sort_uniq compare (List.map fst hs) in
  let block =
    List.map
      (fun n ->
        let vs = List.filter_map (fun (k, v) -> if k = n then Some v else None) hs in
        n ^ ":" ^ String.concat "," vs ^ "\n")
      names
  in
  (String.concat "" block, String.concat ";" names)

let canonical_request ~meth ~canonical_uri ~query ~headers ~payload_hash =
  let block, signed = canonical_headers headers in
  ( String.concat "\n"
      [ meth; canonical_uri; canonical_query query; block; signed; payload_hash ],
    signed )

let credential_scope ~date ~region ~service =
  String.concat "/" [ date; region; service; "aws4_request" ]

let string_to_sign ~amz_date ~scope ~canonical_request =
  String.concat "\n" [ "AWS4-HMAC-SHA256"; amz_date; scope; sha256_hex canonical_request ]

let signing_key ~secret ~date ~region ~service =
  let k = hmac_sha256 ~key:("AWS4" ^ secret) date in
  let k = hmac_sha256 ~key:k region in
  let k = hmac_sha256 ~key:k service in
  hmac_sha256 ~key:k "aws4_request"

let signature ~signing_key sts = to_hex (hmac_sha256 ~key:signing_key sts)

let sign ?(s3 = false) creds ~service ~region ~time ~meth ~uri ~headers ~payload =
  let d = amz_date time in
  let date = String.sub d 0 8 in
  let payload_hash = sha256_hex payload in
  let drop names =
    List.filter (fun (k, _) -> not (List.mem (String.lowercase_ascii k) names))
  in
  let headers =
    drop
      [
        "host";
        "x-amz-date";
        "authorization";
        "x-amz-security-token";
        "x-amz-content-sha256";
      ]
      headers
    @ [ ("host", Http.host_header uri); ("x-amz-date", d) ]
    @ (if s3 then [ ("x-amz-content-sha256", payload_hash) ] else [])
    @
    match creds.session_token with
    | Some t -> [ ("x-amz-security-token", t) ]
    | None -> []
  in
  let query =
    List.concat_map
      (fun (k, vs) ->
        match vs with [] -> [ (k, "") ] | vs -> List.map (fun v -> (k, v)) vs)
      (Uri.query uri)
  in
  let creq, signed =
    canonical_request ~meth
      ~canonical_uri:(canonical_uri ~s3 (Uri.path uri))
      ~query ~headers ~payload_hash
  in
  let scope = credential_scope ~date ~region ~service in
  let sts = string_to_sign ~amz_date:d ~scope ~canonical_request:creq in
  let key = signing_key ~secret:creds.secret_access_key ~date ~region ~service in
  let auth =
    Printf.sprintf "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
      creds.access_key_id scope signed
      (signature ~signing_key:key sts)
  in
  headers @ [ ("authorization", auth) ]

type authorization = {
  credential : string;
  signed_headers : string list;
  signature_hex : string;
}

let parse_authorization s =
  let pre = "AWS4-HMAC-SHA256 " in
  let n = String.length pre in
  if String.length s <= n || String.sub s 0 n <> pre then None
  else
    let parts =
      String.sub s n (String.length s - n)
      |> String.split_on_char ',' |> List.map String.trim
      |> List.filter_map (fun p ->
          match String.index_opt p '=' with
          | Some i ->
              Some (String.sub p 0 i, String.sub p (i + 1) (String.length p - i - 1))
          | None -> None)
    in
    match
      ( List.assoc_opt "Credential" parts,
        List.assoc_opt "SignedHeaders" parts,
        List.assoc_opt "Signature" parts )
    with
    | Some c, Some sh, Some sg ->
        Some
          {
            credential = c;
            signed_headers = String.split_on_char ';' sh;
            signature_hex = sg;
          }
    | _ -> None
