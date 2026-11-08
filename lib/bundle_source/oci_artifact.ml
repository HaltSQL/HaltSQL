open Lwt.Infix
module B = Haltsql_bundle

let artifact_type = "application/vnd.haltsql.bundle.v1"
let bundle_media_type = "application/vnd.haltsql.bundle.v1+json"
let signature_media_type = "application/vnd.haltsql.bundle.signature.v1+json"
let manifest_media_type = "application/vnd.oci.image.manifest.v1+json"
let index_media_type = "application/vnd.oci.image.index.v1+json"
let empty_config_media_type = "application/vnd.oci.empty.v1+json"
let empty_config = "{}"
let title_annotation = "org.opencontainers.image.title"

type descriptor = {
  media_type : string;
  digest : string;
  size : int;
  title : string option;
}

type layout = { bundle_layer : descriptor; signature_layer : descriptor }

let ( let* ) = Result.bind

let descriptor_of_json what (j : Yojson.Safe.t) =
  match j with
  | `Assoc kvs -> (
      let media_type =
        match List.assoc_opt "mediaType" kvs with Some (`String s) -> Some s | _ -> None
      in
      let digest =
        match List.assoc_opt "digest" kvs with Some (`String s) -> Some s | _ -> None
      in
      let size =
        match List.assoc_opt "size" kvs with
        | Some (`Int n) -> Some n
        | Some (`Intlit _) -> Some max_int
        | _ -> None
      in
      let title =
        match List.assoc_opt "annotations" kvs with
        | Some (`Assoc a) -> (
            match List.assoc_opt title_annotation a with
            | Some (`String s) -> Some s
            | _ -> None)
        | _ -> None
      in
      match (media_type, digest, size) with
      | Some media_type, Some digest, Some size ->
          if not (Oci_ref.valid_digest digest) then
            Error (Printf.sprintf "%s: malformed digest" what)
          else if size < 0 then Error (Printf.sprintf "%s: negative size" what)
          else Ok { media_type; digest; size; title }
      | _ ->
          Error (Printf.sprintf "%s: a descriptor needs mediaType, digest and size" what))
  | _ -> Error (Printf.sprintf "%s: a descriptor must be an object" what)

let strip_params ct =
  match String.index_opt ct ';' with
  | Some i -> String.trim (String.sub ct 0 i)
  | None -> String.trim ct

let parse_manifest ?(max_bundle_bytes = B.default_max_bytes) ~content_type body =
  let err m = Error ("not a valid HaltSQL bundle artifact: " ^ m) in
  match Yojson.Safe.from_string body with
  | exception Yojson.Json_error _ -> err "the manifest is not JSON"
  | `Assoc kvs -> (
      let str k =
        match List.assoc_opt k kvs with Some (`String s) -> Some s | _ -> None
      in
      let media_type =
        match str "mediaType" with
        | Some m -> Some m
        | None -> Option.map strip_params content_type
      in
      match (List.assoc_opt "schemaVersion" kvs, media_type) with
      | Some (`Int 2), Some m when m = index_media_type ->
          err "the reference points to an image index, not to a bundle manifest"
      | Some (`Int 2), Some m when m = manifest_media_type -> (
          let* config =
            match List.assoc_opt "config" kvs with
            | Some j -> descriptor_of_json "config" j
            | None -> err "no config descriptor"
          in
          let typed =
            match str "artifactType" with
            | Some a -> a = artifact_type
            | None -> config.media_type = artifact_type
          in
          if not typed then
            err
              (Printf.sprintf "artifactType is %s, expected %s"
                 (match str "artifactType" with
                 | Some a -> a
                 | None -> "(none: config " ^ config.media_type ^ ")")
                 artifact_type)
          else
            let* layers =
              match List.assoc_opt "layers" kvs with
              | Some (`List l) ->
                  List.fold_left
                    (fun acc (i, j) ->
                      let* acc = acc in
                      let* d = descriptor_of_json (Printf.sprintf "layers[%d]" i) j in
                      Ok (d :: acc))
                    (Ok [])
                    (List.mapi (fun i j -> (i, j)) l)
                  |> Result.map List.rev
              | _ -> err "no layers"
            in
            let of_type t = List.filter (fun d -> d.media_type = t) layers in
            match
              ( of_type bundle_media_type,
                of_type signature_media_type,
                List.filter
                  (fun d ->
                    d.media_type <> bundle_media_type
                    && d.media_type <> signature_media_type)
                  layers )
            with
            | [ b ], [ s ], [] ->
                if b.size > max_bundle_bytes then
                  err
                    (Printf.sprintf "the bundle layer is %d bytes (limit %d)" b.size
                       max_bundle_bytes)
                else if s.size > B.max_signature_bytes then
                  err
                    (Printf.sprintf "the signature layer is %d bytes (limit %d)" s.size
                       B.max_signature_bytes)
                else Ok { bundle_layer = b; signature_layer = s }
            | [], _, _ -> err ("no layer of type " ^ bundle_media_type)
            | _, [], _ -> err ("no layer of type " ^ signature_media_type)
            | _ :: _ :: _, _, _ | _, _ :: _ :: _, _ ->
                err "more than one bundle or signature layer"
            | _, _, d :: _ -> err ("unexpected layer of type " ^ d.media_type))
      | Some (`Int 2), Some m -> err ("unsupported manifest media type " ^ m)
      | Some (`Int 2), None -> err "the manifest has no media type"
      | _ -> err "schemaVersion must be 2")
  | _ -> err "the manifest is not a JSON object"

let valid_title s =
  s <> ""
  && String.length s <= 128
  && s <> "." && s <> ".."
  && String.for_all
       (fun c ->
         (c >= 'a' && c <= 'z')
         || (c >= 'A' && c <= 'Z')
         || (c >= '0' && c <= '9')
         || c = '.' || c = '_' || c = '-')
       s

let descriptor_json ?title media_type content : Yojson.Safe.t =
  `Assoc
    ([
       ("mediaType", `String media_type);
       ("digest", `String (Content_digest.sha256 content));
       ("size", `Int (String.length content));
     ]
    @
    match title with
    | Some t -> [ ("annotations", `Assoc [ (title_annotation, `String t) ]) ]
    | None -> [])

let build_manifest ?(title = "bundle.haltsqlbundle") ?(annotations = []) ~bundle
    ~signature () =
  let title = if valid_title title then title else "bundle.haltsqlbundle" in
  let annotations =
    List.sort_uniq (fun (a, _) (b, _) -> String.compare a b) annotations
  in
  Yojson.Safe.to_string
    (`Assoc
       ([
          ("schemaVersion", `Int 2);
          ("mediaType", `String manifest_media_type);
          ("artifactType", `String artifact_type);
          ( "config",
            `Assoc
              [
                ("mediaType", `String empty_config_media_type);
                ("digest", `String (Content_digest.sha256 empty_config));
                ("size", `Int (String.length empty_config));
                ("data", `String (Haltsql_cloud.Cloud_util.base64 empty_config));
              ] );
          ( "layers",
            `List
              [
                descriptor_json ~title bundle_media_type bundle;
                descriptor_json ~title:(title ^ ".sig") signature_media_type signature;
              ] );
        ]
       @
       if annotations = [] then []
       else
         [ ("annotations", `Assoc (List.map (fun (k, v) -> (k, `String v)) annotations)) ]
       ))

let annotations_of_bundle (t : B.t) =
  [
    ("dev.haltsql.bundle.name", t.metadata.name);
    ("dev.haltsql.bundle.version", t.metadata.version);
    ("dev.haltsql.bundle.digest", t.digest);
  ]

type pulled = {
  manifest_digest : string;
  bundle : string;
  signature : string;
  bundle_title : string option;
}

let pull ?max_bundle_bytes ?reference reg =
  let reference =
    match reference with
    | Some r -> r
    | None -> Oci_ref.reference (Registry.reference reg)
  in
  Registry.get_manifest reg reference >>= function
  | Error e -> Lwt.return (Error e)
  | Ok m -> (
      match parse_manifest ?max_bundle_bytes ~content_type:m.media_type m.body with
      | Error e -> Lwt.return (Error (Fetch_error.Integrity e))
      | Ok l -> (
          Registry.get_blob reg ~digest:l.bundle_layer.digest ~size:l.bundle_layer.size
          >>= function
          | Error e -> Lwt.return (Error e)
          | Ok bundle -> (
              Registry.get_blob reg ~digest:l.signature_layer.digest
                ~size:l.signature_layer.size
              >|= function
              | Error e -> Error e
              | Ok signature ->
                  Ok
                    {
                      manifest_digest = m.digest;
                      bundle;
                      signature;
                      bundle_title = l.bundle_layer.title;
                    })))

let push ?title ?annotations reg ~bundle ~signature =
  let r = Registry.reference reg in
  let manifest = build_manifest ?title ?annotations ~bundle ~signature () in
  let digest = Content_digest.sha256 manifest in
  match r.digest with
  | Some d when d <> digest ->
      Lwt.return
        (Error
           (Fetch_error.Integrity
              (Printf.sprintf
                 "the reference pins %s but the artifact's manifest digest is %s" d digest)))
  | _ -> (
      let rec blobs = function
        | [] -> Lwt.return (Ok ())
        | b :: rest -> (
            Registry.push_blob reg b >>= function
            | Error e -> Lwt.return (Error e)
            | Ok _ -> blobs rest)
      in
      blobs [ empty_config; bundle; signature ] >>= function
      | Error e -> Lwt.return (Error e)
      | Ok () ->
          let reference = match r.tag with Some t -> t | None -> digest in
          Registry.put_manifest reg ~reference ~media_type:manifest_media_type manifest)
