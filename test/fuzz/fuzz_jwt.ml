(* Mutation fuzzer for haltsql-server's caller authentication: Jwt.decode, the JWK / JWK
   Set parser and full token verification (Oidc.verify). Same shape as fuzz.ml: a
   deterministic home-made mutator run for a fixed number of iterations.

   Seeds (test/auth/vectors, so that a run needs no random keys and a finding can be
   replayed): the pyca/cryptography interop JWKS with one valid token for each of the
   seven accepted algorithms, plus the RFC 7515 / 7520 / 8037 example tokens and keys.

   Token inputs: 1-6 mutations of a valid token. Byte-level (bit flips, inserts,
   deletes, duplication, splicing, dictionary insertion, truncation) and structural
   (mutate inside a base64url-decoded segment and re-encode, swap a segment with
   another token's, re-encode a segment non-canonically, replace the signature).
   Properties:

   - Jwt.decode, Jwt.looks_like_jwt, Jwt.unverified_issuer and Oidc.verify never raise.
   - A decoded token is canonical: its signing input and re-encoded signature spell
     the input exactly.
   - Oidc.verify accepts an input only if it is one of the seven seed tokens, byte for
     byte. The oracle compares header, payload and signature bytes with its own lenient
     base64url decoder, so an accepted second spelling of a seed token is reported
     separately from an accepted different token. (For ECDSA the signature (r, n - s)
     is also valid, by design; no mutation here computes it.)
   - Every call returns within one second.

   JWKS inputs: 1-6 byte-level mutations of a JWK Set or a single key. Properties:

   - Jwk.set_of_string never raises; every key it returns survives
     Jwk.to_json / Jwk.of_json and, if RSA, has an odd exponent and 2048..8192 bits.
   - Under the mutated key set, none of the "never valid" tokens verifies: seed tokens
     with a changed payload, an all-zero ECDSA signature, the Ed25519 signature
     (identity, 0) that verifies under a small-order key, and an RS256 "signature"
     that is its own padded digest (valid under e = 1).
   - A seed token verifies only when the set still holds its original key under its
     kid.

   Any violation is minimized (greedy chunk removal) and written to
   test/fuzz/crashes/jwt-<kind>-<sha>.txt.

   Environment: HALTSQL_FUZZ_ITERS (default 20000), HALTSQL_FUZZ_SEED (default 1),
   HALTSQL_FUZZ_CRASH_DIR. Exit code 1 if anything was found, 2 if the seeds are
   unusable. *)

open Haltsql_auth
module Config = Haltsql.Config

let ( // ) = Filename.concat

let read_file f =
  let ic = open_in_bin f in
  let s = really_input_string ic (in_channel_length ic) in
  close_in ic;
  s

let iters =
  match Option.bind (Sys.getenv_opt "HALTSQL_FUZZ_ITERS") int_of_string_opt with
  | Some n when n > 0 -> n
  | _ -> 20000

let seed =
  match Option.bind (Sys.getenv_opt "HALTSQL_FUZZ_SEED") int_of_string_opt with
  | Some n -> n
  | None -> 1

let crash_dir () =
  match Sys.getenv_opt "HALTSQL_FUZZ_CRASH_DIR" with
  | Some d -> d
  | None -> (
      match Sys.getenv_opt "DUNE_SOURCEROOT" with
      | Some r -> r // "test/fuzz/crashes"
      | None -> "crashes")

let die fmt =
  Printf.ksprintf
    (fun m ->
      prerr_endline ("fuzz_jwt: " ^ m);
      exit 2)
    fmt

(* ---- an independent base64url codec for the oracle ---- *)

let b64 s = Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet s

(* Lenient on purpose: padding, the standard alphabet and stray trailing bits all decode,
   so that two spellings of the same bytes compare equal. *)
let unb64 s =
  let s = String.concat "" (String.split_on_char '=' s) in
  let s = String.map (function '+' -> '-' | '/' -> '_' | c -> c) s in
  match Base64.decode ~pad:false ~alphabet:Base64.uri_safe_alphabet s with
  | Ok v -> Some v
  | Error _ -> None

let segments tok = String.split_on_char '.' tok

let same_bytes a b =
  match (segments a, segments b) with
  | [ a1; a2; a3 ], [ b1; b2; b3 ] ->
      List.for_all2
        (fun x y -> match (unb64 x, unb64 y) with Some x, Some y -> x = y | _ -> false)
        [ a1; a2; a3 ] [ b1; b2; b3 ]
  | _ -> false

(* ---- mutations ---- *)

let dict =
  [|
    "none";
    "None";
    "HS256";
    "RS256";
    "RS384";
    "RS512";
    "PS256";
    "PS384";
    "ES256";
    "ES384";
    "ES512";
    "EdDSA";
    "\"alg\":\"none\",";
    "\"alg\":\"HS256\",";
    "\"alg\":";
    "\"kid\":";
    "\"crit\":[\"exp\"],";
    "\"b64\":false,";
    "\"typ\":1,";
    "\"jwk\":{";
    "\"jku\":\"https://x\",";
    "\"exp\":1e400,";
    "\"exp\":\"9\",";
    "\"exp\":-1,";
    "\"aud\":[],";
    "\"iss\":";
    "\"kty\":\"oct\",";
    "\"kty\":\"RSA\",";
    "\"kty\":\"EC\",";
    "\"kty\":\"OKP\",";
    "\"crv\":\"P-256\",";
    "\"crv\":\"P-384\",";
    "\"crv\":\"Ed25519\",";
    "\"k\":\"AAAA\",";
    "\"d\":\"AQAB\",";
    "\"e\":\"AQ\",";
    "\"e\":\"AA\",";
    "\"e\":\"Ag\",";
    "\"e\":\"Aw\",";
    "\"use\":\"enc\",";
    "\"use\":\"sig\",";
    "\"key_ops\":[\"sign\"],";
    "\"keys\":[";
    (* Ed25519 points of small order: the identity, and a point of order 8 *)
    "\"x\":\"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",";
    "\"x\":\"JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_AU\",";
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    "AQ";
    "AA";
    "AQAB";
    "{";
    "}";
    "[";
    "]";
    ",";
    ":";
    "\"";
    "\\u0000";
    "\\";
    ".";
    "..";
    "=";
    "==";
    "+";
    "/";
    "-";
    "_";
    " ";
    "\n";
    "\x00";
    "\xff";
    "\xc3\x28";
    "NaN";
    "Infinity";
    "null";
    "true";
    "-1";
    "0";
    "1e999";
    "99999999999999999999999999";
    "/**/";
    "eyJhbGciOiJub25lIn0";
    "e30";
  |]

let mutate_bytes rng (seeds : string array) s =
  let n = String.length s in
  let pos () = if n = 0 then 0 else Random.State.int rng (n + 1) in
  match Random.State.int rng 10 with
  | 0 when n > 0 ->
      let b = Bytes.of_string s in
      let i = Random.State.int rng n in
      Bytes.set b i
        (Char.chr (Char.code (Bytes.get b i) lxor (1 lsl Random.State.int rng 8)));
      Bytes.to_string b
  | 1 ->
      let i = pos () in
      String.sub s 0 i
      ^ String.make 1 (Char.chr (Random.State.int rng 256))
      ^ String.sub s i (n - i)
  | 2 when n > 0 ->
      let i = Random.State.int rng n in
      let l = 1 + Random.State.int rng (min 16 (n - i)) in
      String.sub s 0 i ^ String.sub s (i + l) (n - i - l)
  | 3 when n > 0 ->
      let i = Random.State.int rng n in
      let l = 1 + Random.State.int rng (min 64 (n - i)) in
      let chunk = String.sub s i l in
      String.sub s 0 i ^ chunk ^ chunk ^ String.sub s i (n - i)
  | 4 ->
      let o = seeds.(Random.State.int rng (Array.length seeds)) in
      let i = pos ()
      and j = if o = "" then 0 else Random.State.int rng (String.length o + 1) in
      String.sub s 0 i ^ String.sub o j (String.length o - j)
  | 5 | 6 ->
      let i = pos () in
      String.sub s 0 i
      ^ dict.(Random.State.int rng (Array.length dict))
      ^ String.sub s i (n - i)
  | 7 -> String.sub s 0 (pos ())
  | 8 when n > 0 ->
      (* overwrite a byte with a boundary value *)
      let b = Bytes.of_string s in
      let i = Random.State.int rng n in
      Bytes.set b i [| '\x00'; '\xff'; '\x7f'; '\x80'; '\x01' |].(Random.State.int rng 5);
      Bytes.to_string b
  | _ ->
      (* amplify nesting *)
      let i = pos () in
      let k = 1 + Random.State.int rng 300 in
      String.sub s 0 i ^ String.make k '[' ^ String.sub s i (n - i)

let replace_nth l i v = List.mapi (fun j x -> if j = i then v else x) l

let mutate_token rng (seeds : string array) tok =
  let segs = segments tok in
  let nseg = List.length segs in
  let pick () = Random.State.int rng nseg in
  let join = String.concat "." in
  match Random.State.int rng 10 with
  | 0 | 1 | 2 -> mutate_bytes rng seeds tok
  | 3 | 4 | 5 -> (
      (* mutate the decoded bytes of one segment, then re-encode canonically *)
      let i = pick () in
      match unb64 (List.nth segs i) with
      | Some raw -> join (replace_nth segs i (b64 (mutate_bytes rng seeds raw)))
      | None -> mutate_bytes rng seeds tok)
  | 6 -> (
      (* a segment of another seed token *)
      let i = pick () in
      match segments seeds.(Random.State.int rng (Array.length seeds)) with
      | o when List.length o > i -> join (replace_nth segs i (List.nth o i))
      | _ -> tok)
  | 7 -> (
      (* another spelling of the same bytes *)
      let i = pick () in
      let s = List.nth segs i in
      let n = String.length s in
      match Random.State.int rng 4 with
      | 0 -> join (replace_nth segs i (s ^ "="))
      | 1 -> join (replace_nth segs i (s ^ "=="))
      | 2 ->
          join
            (replace_nth segs i
               (String.map (function '-' -> '+' | '_' -> '/' | c -> c) s))
      | _ when n > 0 && n mod 4 <> 0 -> (
          (* set an unused trailing bit of the last character *)
          let alphabet = Base64.(alphabet uri_safe_alphabet) in
          match String.index_opt alphabet s.[n - 1] with
          | Some v ->
              join
                (replace_nth segs i
                   (String.sub s 0 (n - 1) ^ String.make 1 alphabet.[v lor 1]))
          | None -> tok)
      | _ -> tok)
  | 8 when nseg = 3 -> (
      (* signature surgery *)
      match unb64 (List.nth segs 2) with
      | Some sg when sg <> "" ->
          let n = String.length sg in
          let sg' =
            match Random.State.int rng 7 with
            | 0 -> ""
            | 1 -> String.make n '\x00'
            | 2 -> String.make n '\xff'
            | 3 -> String.sub sg 0 (n - 1)
            | 4 -> sg ^ "\x00"
            | 5 -> "\x00" ^ sg
            | _ -> String.sub sg (n / 2) (n - (n / 2)) ^ String.sub sg 0 (n / 2)
          in
          join (replace_nth segs 2 (b64 sg'))
      | _ -> tok)
  | _ ->
      (* a different number of segments *)
      if Random.State.bool rng then tok ^ "." ^ List.nth segs (pick ())
      else
        let d = pick () in
        join (List.filteri (fun j _ -> j <> d) segs)

(* ---- seeds ---- *)

let member k = function
  | `Assoc kv -> ( match List.assoc_opt k kv with Some v -> v | None -> `Null)
  | _ -> `Null

let str k j = match member k j with `String s -> s | _ -> die "vector has no %S" k

type world = {
  provider : Config.oidc_provider;
  keys : Jwk.t list;
  now : float;
  tokens : (string * string) array;  (** kid, token: the seven valid seed tokens *)
  never : (string * string) list;  (** name, token: must not verify under any key set *)
}

let provider issuer : Config.oidc_provider =
  {
    oidc_name = "fuzz";
    issuer;
    audiences = [ "haltsql" ];
    jwks_uri = Some "https://idp.example.test/jwks";
    algorithms = Config.[ RS256; RS384; RS512; PS256; ES256; ES384; EdDSA ];
    leeway_seconds = 60;
    jwks_cache_seconds = 300;
    oidc_policy = Config.Oidc_pinned "p";
    context_claims = [];
    required_claims = [];
    oidc_request_context_fields = [];
    allow_insecure_http = false;
  }

let digest_info_sha256 =
  "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

(* Tokens that no key set derived from the seed JWKS may ever accept. *)
let never_tokens (tokens : (string * string) array) =
  let split tok =
    match segments tok with [ h; p; s ] -> (h, p, s) | _ -> die "seed token shape"
  in
  let with_kid suffix =
    List.find_opt (fun (kid, _) -> String.ends_with ~suffix kid) (Array.to_list tokens)
  in
  let tampered =
    Array.to_list tokens
    |> List.map (fun (kid, tok) ->
        let h, p, s = split tok in
        let p' =
          match unb64 p with
          | Some j -> b64 (String.concat "admin" (String.split_on_char '-' j))
          | None -> die "seed payload"
        in
        if p' = p then die "tampering changed nothing";
        ("tampered payload, " ^ kid, h ^ "." ^ p' ^ "." ^ s))
  in
  let forged suffix name signature =
    match with_kid suffix with
    | Some (kid, tok) ->
        let h, p, _ = split tok in
        [ (name ^ ", " ^ kid, h ^ "." ^ p ^ "." ^ b64 (signature (h ^ "." ^ p))) ]
    | None -> die "no seed token for %s" suffix
  in
  tampered
  @ forged "eddsa" "Ed25519 signature (identity, 0)" (fun _ ->
      "\x01" ^ String.make 31 '\x00' ^ String.make 32 '\x00')
  @ forged "es256" "ECDSA r = s = 0" (fun _ -> String.make 64 '\x00')
  @ forged "es384" "ECDSA r = s = 0" (fun _ -> String.make 96 '\x00')
  @ forged "rs256" "RSA signature = its own padded digest (e = 1)" (fun i ->
      let t = digest_info_sha256 ^ Digestif.SHA256.(to_raw_string (digest_string i)) in
      "\x00\x01" ^ String.make (256 - 3 - String.length t) '\xff' ^ "\x00" ^ t)
  @ forged "rs256" "RSA signature = 1" (fun _ -> String.make 255 '\x00' ^ "\x01")
  @ forged "ps256" "RSA-PSS signature = 0" (fun _ -> String.make 256 '\x00')

let load dir =
  let interop = Yojson.Safe.from_string (read_file (dir // "interop_vectors.json")) in
  let rfc = Yojson.Safe.from_string (read_file (dir // "rfc_vectors.json")) in
  let keys =
    match Jwk.set_of_json (member "jwks" interop) with
    | Ok (ks, []) -> ks
    | _ -> die "the interop JWKS does not load"
  in
  let tokens =
    match member "tokens" interop with
    | `List l -> Array.of_list (List.map (fun t -> (str "kid" t, str "token" t)) l)
    | _ -> die "no interop tokens"
  in
  let rfc_entries = match rfc with `Assoc kv -> List.map snd kv | _ -> [] in
  let token_seeds =
    Array.to_list (Array.map snd tokens)
    @ List.map (str "token") rfc_entries
    @ match member "negative" interop with `List l -> List.map (str "token") l | _ -> []
  in
  let jwk_texts =
    (match member "keys" (member "jwks" interop) with `List l -> l | _ -> [])
    @ List.filter_map
        (fun e -> match member "jwk" e with `Null -> None | j -> Some j)
        rfc_entries
  in
  (* Hostile neighbours of the seed keys, one member away from a usable key: the parser
     refuses each of them, and mutations start right at that boundary. *)
  let hostile =
    let set k v = function
      | `Assoc kv ->
          `Assoc
            (List.map (fun (k', v') -> if k' = k then (k, `String v) else (k', v')) kv)
      | j -> j
    in
    let add k v = function `Assoc kv -> `Assoc (kv @ [ (k, v) ]) | j -> j in
    List.concat_map
      (fun j ->
        match member "kty" j with
        | `String "RSA" ->
            [ set "e" "AQ" j; set "e" "AA" j; set "e" "Ag" j; add "d" (`String "AQAB") j ]
            @ [ set "kty" "oct" (add "k" (member "n" j) j) ]
        | `String "OKP" ->
            [
              set "x" "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" j;
              set "x" "JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_AU" j;
              set "x" "7P________________________________________8" j;
            ]
        | `String "EC" ->
            [ set "y" (str "x" j) j; add "key_ops" (`List [ `String "sign" ]) j ]
        | _ -> [])
      (match member "keys" (member "jwks" interop) with `List l -> l | _ -> [])
  in
  let jwk_texts = jwk_texts @ hostile in
  let jwks_seeds =
    Yojson.Safe.to_string (member "jwks" interop)
    :: List.concat_map
         (fun j ->
           let s = Yojson.Safe.to_string j in
           [ "{\"keys\":[" ^ s ^ "]}"; "{\"keys\":[" ^ s ^ "," ^ s ^ "]}" ])
         jwk_texts
  in
  ( {
      provider = provider (str "issuer" interop);
      keys;
      now = 1767225700.;
      tokens;
      never = never_tokens tokens;
    },
    Array.of_list token_seeds,
    Array.of_list jwks_seeds )

(* ---- oracles: [Some kind] when the input is a finding ---- *)

let max_seconds = 1.0

let timed kind f =
  let t0 = Unix.gettimeofday () in
  match f () with
  | exception e -> Error (kind ^ "-exception: " ^ Printexc.to_string e)
  | v ->
      let dt = Unix.gettimeofday () -. t0 in
      if dt > max_seconds then Error (Printf.sprintf "%s-slow: %.2fs" kind dt) else Ok v

let ( let* ) = Result.bind
let finding = function Ok () -> None | Error k -> Some k

let check_token w tok =
  finding
    (let* d = timed "decode" (fun () -> Jwt.decode tok) in
     let* () =
       match d with
       | Ok t ->
           if String.equal (t.signing_input ^ "." ^ b64 t.signature) tok then Ok ()
           else Error "decode-not-canonical"
       | Error _ -> Ok ()
     in
     let* _ = timed "looks-like-jwt" (fun () -> Jwt.looks_like_jwt tok) in
     let* _ = timed "unverified-issuer" (fun () -> Jwt.unverified_issuer tok) in
     let* v =
       timed "verify" (fun () -> Oidc.verify w.provider ~keys:w.keys ~now:w.now tok)
     in
     match v with
     | Error _ -> Ok ()
     | Ok _ ->
         if Result.is_error d then Error "verify-accepted-undecodable"
         else if Array.exists (fun (_, s) -> String.equal s tok) w.tokens then Ok ()
         else if Array.exists (fun (_, s) -> same_bytes s tok) w.tokens then
           Error "verify-accepted-second-spelling"
         else Error "verify-accepted-mutated-token")

let material (k : Jwk.t) = Jwk.to_json { k with kid = None; alg = None; use = None }

let check_jwks w text =
  finding
    (let* r = timed "jwks" (fun () -> Jwk.set_of_string text) in
     match r with
     | Error _ -> Ok ()
     | Ok (ks, _) ->
         let* sound =
           timed "jwks-invariant" (fun () ->
               List.for_all
                 (fun (k : Jwk.t) ->
                   (match k.key with
                     | Jwk.Rsa pub ->
                         let bits = Mirage_crypto_pk.Rsa.pub_bits pub in
                         bits >= Jwk.min_rsa_bits && bits <= Jwk.max_rsa_bits
                         && Z.is_odd pub.e
                     | _ -> true)
                   &&
                   match Jwk.of_json (Jwk.to_json k) with
                   | Ok k' -> material k' = material k
                   | Error _ -> false)
                 ks)
         in
         let* () = if sound then Ok () else Error "jwks-invariant" in
         let verify tok = Oidc.verify w.provider ~keys:ks ~now:w.now tok in
         let* () =
           List.fold_left
             (fun acc (name, tok) ->
               let* () = acc in
               let* v = timed "jwks-verify" (fun () -> verify tok) in
               if Result.is_ok v then Error ("jwks-forgery: " ^ name) else Ok ())
             (Ok ()) w.never
         in
         Array.fold_left
           (fun acc (kid, tok) ->
             let* () = acc in
             let* v = timed "jwks-verify" (fun () -> verify tok) in
             match v with
             | Error _ -> Ok ()
             | Ok _ ->
                 let original =
                   List.find (fun (k : Jwk.t) -> k.kid = Some kid) w.keys |> material
                 in
                 if
                   List.exists
                     (fun (k : Jwk.t) -> k.kid = Some kid && material k = original)
                     ks
                 then Ok ()
                 else Error "jwks-accepted-under-another-key")
           (Ok ()) w.tokens)

(* Greedy delta minimization: drop chunks (halving sizes) while [still_fails]. *)
let minimize still_fails s =
  let s = ref s in
  let chunk = ref (max 1 (String.length !s / 2)) in
  let budget = ref 2000 in
  while !chunk >= 1 && !budget > 0 do
    let i = ref 0 in
    let progressed = ref false in
    while !i < String.length !s && !budget > 0 do
      decr budget;
      let n = String.length !s in
      let l = min !chunk (n - !i) in
      let cand = String.sub !s 0 !i ^ String.sub !s (!i + l) (n - !i - l) in
      if still_fails cand then (
        s := cand;
        progressed := true)
      else i := !i + l
    done;
    if not !progressed then chunk := !chunk / 2
  done;
  !s

let kind_prefix k =
  match String.index_opt k ':' with Some i -> String.sub k 0 i | None -> k

let () =
  let dir = ref "../auth/vectors" in
  let rec args = function
    | "--vectors" :: d :: tl ->
        dir := d;
        args tl
    | _ :: tl -> args tl
    | [] -> ()
  in
  args (List.tl (Array.to_list Sys.argv));
  let w, token_seeds, jwks_seeds = load !dir in
  (* The oracles must hold on the unmutated seeds, and the seeds must be live: every
     valid token verifies, every "never" token is rejected with the real keys. *)
  Array.iter
    (fun (kid, tok) ->
      (match Oidc.verify w.provider ~keys:w.keys ~now:w.now tok with
      | Ok _ -> ()
      | Error e -> die "seed token %s does not verify: %s" kid (Jwt.error_to_string e));
      match check_token w tok with Some k -> die "seed token %s: %s" kid k | None -> ())
    w.tokens;
  List.iter
    (fun (name, tok) ->
      match Oidc.verify w.provider ~keys:w.keys ~now:w.now tok with
      | Ok _ -> die "\"never\" token verifies with the seed keys: %s" name
      | Error _ -> ())
    w.never;
  Array.iter
    (fun s -> match check_jwks w s with Some k -> die "seed JWKS: %s" k | None -> ())
    jwks_seeds;
  Printf.printf
    "haltsql jwt fuzz: seed=%d iters=%d token_seeds=%d (7 valid) jwks_seeds=%d never=%d\n\
     %!"
    seed iters (Array.length token_seeds) (Array.length jwks_seeds) (List.length w.never);
  let rng = Random.State.make [| seed |] in
  let found = Hashtbl.create 16 in
  let record kind input still_fails =
    let key = kind_prefix kind in
    if not (Hashtbl.mem found key) then begin
      let small = minimize still_fails input in
      Hashtbl.add found key ();
      let dir = crash_dir () in
      (try if not (Sys.file_exists dir) then Sys.mkdir dir 0o755 with _ -> ());
      let file =
        dir
        // Printf.sprintf "jwt-%s-%s.txt" key (String.sub (Haltsql.sha256_hex small) 0 12)
      in
      (try
         let oc = open_out_bin file in
         output_string oc small;
         close_out oc
       with Sys_error e -> Printf.printf "  (could not write %s: %s)\n" file e);
      Printf.printf "FOUND %s\n  minimized (%d bytes): %S\n  written to %s\n%!" kind
        (String.length small) small file
    end
  in
  let run check input =
    match check input with
    | None -> ()
    | Some kind ->
        let pre = kind_prefix kind in
        record kind input (fun c ->
            match check c with Some k -> kind_prefix k = pre | None -> false)
  in
  let valid = Array.map snd w.tokens in
  let t0 = Unix.gettimeofday () in
  let token_runs = ref 0 and jwks_runs = ref 0 and reached_crypto = ref 0 in
  for i = 1 to iters do
    let k = 1 + Random.State.int rng 6 in
    if i mod 4 <> 0 then begin
      incr token_runs;
      (* two in three start from a valid token, so that most inputs get past decoding *)
      let pool = if i mod 3 <> 0 then valid else token_seeds in
      let s = ref pool.(Random.State.int rng (Array.length pool)) in
      for _ = 1 to k do
        s := mutate_token rng token_seeds !s
      done;
      (match Oidc.verify w.provider ~keys:w.keys ~now:w.now !s with
      | Error Jwt.Bad_signature | Ok _ -> incr reached_crypto
      | Error _ | (exception _) -> ());
      run (check_token w) !s
    end
    else begin
      incr jwks_runs;
      let s = ref jwks_seeds.(Random.State.int rng (Array.length jwks_seeds)) in
      for _ = 1 to k do
        s := mutate_bytes rng jwks_seeds !s
      done;
      run (check_jwks w) !s
    end
  done;
  let dt = Unix.gettimeofday () -. t0 in
  Printf.printf
    "haltsql jwt fuzz: %d token inputs (%d reached signature verification) + %d JWKS \
     inputs in %.1fs (%.0f/s); findings: %d\n"
    !token_runs !reached_crypto !jwks_runs dt
    (float_of_int iters /. dt)
    (Hashtbl.length found);
  if Hashtbl.length found > 0 then exit 1
