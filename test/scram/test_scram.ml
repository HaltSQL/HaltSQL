(* haltsql.scram. RFC 5802's own example is SCRAM-SHA-1, which is not implemented; the
   vector here is RFC 7677 section 3 (SCRAM-SHA-256), asserted for both roles. *)

module S = Haltsql_scram

let check_str = Alcotest.(check string)
let check_bool = Alcotest.(check bool)

let error =
  Alcotest.testable (fun ppf e -> Format.pp_print_string ppf (S.error_to_string e)) ( = )

let check_err name expected got =
  Alcotest.(check (result unit error)) name (Error expected) got

let hex s =
  String.concat ""
    (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

(* RFC 7677 section 3: user "user", password "pencil". *)
let cnonce = "rOprNGfwEbeRWgbNEkqO"
let snonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
let salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ=="
let client_first_msg = "n,,n=user,r=" ^ cnonce
let server_first_msg = "r=" ^ cnonce ^ snonce ^ ",s=" ^ salt_b64 ^ ",i=4096"

let client_final_msg =
  "c=biws,r=" ^ cnonce ^ snonce ^ ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

let server_final_msg = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
let rfc_first () = S.client_first ~user:"user" ~nonce:cnonce ()

let rfc_final () =
  match
    S.client_final S.SHA256 (rfc_first ()) ~password:"pencil"
      ~server_first:server_first_msg
  with
  | Ok f -> f
  | Error e -> Alcotest.fail (S.error_to_string e)

let rfc_verifier () =
  S.make_verifier ~iterations:4096 ~salt:(Base64.decode_exn salt_b64) "pencil"

(* ------------------------------------------------------------------ client *)

let test_client_rfc7677 () =
  let first = rfc_first () in
  check_str "client-first" client_first_msg first.message;
  check_str "bare" ("n=user,r=" ^ cnonce) first.bare;
  let f = rfc_final () in
  check_str "client-final" client_final_msg f.final_message;
  check_str "server signature" "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    (Base64.encode_string f.server_signature);
  Alcotest.(check (result unit error))
    "server-final accepted" (Ok ())
    (S.verify_server_final f server_final_msg);
  Alcotest.(check (result unit error))
    "extension after v" (Ok ())
    (S.verify_server_final f (server_final_msg ^ ",x=ext"))

let test_client_server_final_rejects () =
  let f = rfc_final () in
  let v = S.verify_server_final f in
  check_err "wrong signature" S.Server_signature_mismatch
    (v "v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
  check_err "all-zero signature" S.Server_signature_mismatch
    (v ("v=" ^ Base64.encode_string (String.make 32 '\000')));
  check_err "truncated signature" S.Server_signature_mismatch
    (v ("v=" ^ Base64.encode_string (String.sub f.server_signature 0 31)));
  check_err "empty signature" S.Server_signature_mismatch (v "v=");
  (* same bytes, non-zero trailing bits: only the canonical encoding is accepted *)
  check_err "non-canonical base64" S.Server_signature_mismatch
    (v "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G5=");
  check_err "unpadded base64" S.Server_signature_mismatch
    (v "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4");
  check_err "server error" (S.Server_error "invalid-proof") (v "e=invalid-proof");
  check_err "server error is made printable" (S.Server_error "a?b?c") (v "e=a\nb\027c");
  check_err "error after a valid signature" S.Malformed_server_final
    (v (server_final_msg ^ ",e=other-error"));
  check_err "signature not first" S.Malformed_server_final (v ("x=1," ^ server_final_msg));
  List.iter
    (fun m -> check_err (Printf.sprintf "malformed %S" m) S.Malformed_server_final (v m))
    [
      "";
      "x";
      "v";
      "=";
      "=v";
      ",";
      "garbage";
      "V" ^ server_final_msg;
      server_final_msg ^ ",";
    ];
  check_err "too long" S.Message_too_long (v ("v=" ^ String.make 4096 'A'))

let test_client_server_first_rejects () =
  let first = S.client_first ~nonce:"abc" () in
  let go ?(password = "p") sf =
    Result.map ignore (S.client_final S.SHA256 first ~password ~server_first:sf)
  in
  let s = "c2FsdA==" in
  Alcotest.(check (result unit error))
    "accepted" (Ok ())
    (go ("r=abcd,s=" ^ s ^ ",i=4096"));
  Alcotest.(check (result unit error))
    "extension after i" (Ok ())
    (go ("r=abcd,s=" ^ s ^ ",i=4096,x=y"));
  check_err "nonce does not extend ours" S.Nonce_not_extended
    (go ("r=xyz123,s=" ^ s ^ ",i=4096"));
  check_err "nonce is ours, not extended" S.Nonce_not_extended
    (go ("r=abc,s=" ^ s ^ ",i=4096"));
  check_err "nonce shorter than ours" S.Nonce_not_extended
    (go ("r=ab,s=" ^ s ^ ",i=4096"));
  check_err "ours as a suffix" S.Nonce_not_extended (go ("r=Xabc,s=" ^ s ^ ",i=4096"));
  check_err "unprintable nonce" S.Invalid_nonce (go ("r=abc\001,s=" ^ s ^ ",i=4096"));
  check_err "space in nonce" S.Invalid_nonce (go ("r=abc d,s=" ^ s ^ ",i=4096"));
  let range count = S.Iteration_count_out_of_range { count; min = 4096; max = 600_000 } in
  check_err "below the minimum" (range 4095) (go ("r=abcd,s=" ^ s ^ ",i=4095"));
  check_err "one iteration" (range 1) (go ("r=abcd,s=" ^ s ^ ",i=1"));
  check_err "zero iterations" (range 0) (go ("r=abcd,s=" ^ s ^ ",i=0"));
  check_err "above the maximum" (range 600_001) (go ("r=abcd,s=" ^ s ^ ",i=600001"));
  check_err "far above the maximum" (range 99_999_999)
    (go ("r=abcd,s=" ^ s ^ ",i=99999999"));
  List.iter
    (fun i ->
      check_err
        (Printf.sprintf "iteration count %S" i)
        S.Invalid_iteration_count
        (go ("r=abcd,s=" ^ s ^ ",i=" ^ i)))
    [
      "";
      "-4096";
      "+4096";
      "0x1000";
      "4_096";
      " 4096";
      "4096 ";
      "4096.0";
      "1e4";
      "9999999999";
    ];
  check_err "salt is not base64" S.Invalid_salt (go "r=abcd,s=!!!,i=4096");
  check_err "empty salt" S.Invalid_salt (go "r=abcd,s=,i=4096");
  check_err "non-canonical salt" S.Invalid_salt (go "r=abcd,s=c2FsdB==,i=4096");
  check_err "unpadded salt" S.Invalid_salt (go "r=abcd,s=c2FsdA,i=4096");
  check_err "mandatory extension" S.Unsupported_extension
    (go ("m=ext,r=abcd,s=" ^ s ^ ",i=4096"));
  List.iter
    (fun m -> check_err (Printf.sprintf "malformed %S" m) S.Malformed_server_first (go m))
    [
      "";
      "garbage";
      "r=abcd";
      "r=abcd,i=4096";
      "r=abcd,s=" ^ s;
      "s=" ^ s ^ ",r=abcd,i=4096";
      "r=abcd,s=" ^ s ^ ",i=4096,";
      "r=abcd,s=" ^ s ^ ",i=4096,junk";
      "junk,r=abcd,s=" ^ s ^ ",i=4096";
      "x=1,r=abcd,s=" ^ s ^ ",i=4096";
      "e=other-error";
      ",,,";
    ];
  check_err "too long" S.Message_too_long
    (go ("r=abcd" ^ String.make 4096 'x' ^ ",s=" ^ s ^ ",i=4096"));
  (* an unusable nonce of ours is reported, not sent on *)
  let bad = S.client_first ~nonce:"a b" () in
  check_err "invalid client nonce" S.Invalid_nonce
    (Result.map ignore
       (S.client_final S.SHA256 bad ~password:"p"
          ~server_first:("r=a bc,s=" ^ s ^ ",i=4096")))

let test_client_bounds_override () =
  let first = S.client_first ~nonce:"abc" () in
  let sf = "r=abcd,s=c2FsdA==,i=1000" in
  check_bool "default refuses 1000" true
    (Result.is_error (S.client_final S.SHA256 first ~password:"p" ~server_first:sf));
  check_bool "explicit minimum" true
    (Result.is_ok
       (S.client_final ~min_iterations:1000 S.SHA256 first ~password:"p" ~server_first:sf));
  check_bool "explicit maximum" true
    (Result.is_error
       (S.client_final ~min_iterations:1 ~max_iterations:999 S.SHA256 first ~password:"p"
          ~server_first:sf))

let test_escaping_and_nonce () =
  check_str "saslname" "n,,n=a=3Db=2Cc,r=n"
    (S.client_first ~user:"a=b,c" ~nonce:"n" ()).message;
  check_str "default user" "n,,n=,r=n" (S.client_first ~nonce:"n" ()).message;
  let n = S.nonce_of_entropy (String.make S.nonce_entropy_bytes '\xff') in
  check_str "nonce" (String.make 32 '/') n;
  check_str "mechanisms" "SCRAM-SHA-256,SCRAM-SHA-512"
    (S.mechanism S.SHA256 ^ "," ^ S.mechanism S.SHA512)

(* SCRAM-SHA-512 has no RFC vector: check the client against an independent server-side
   computation (RFC 5802 section 3) written here with Digestif. *)
let test_sha512 () =
  let module H = Digestif.SHA512 in
  let hmac key m = H.(to_raw_string (hmac_string ~key m)) in
  let password = "s3cr3t-p@ss" and salt = "0123456789abcdef" and iterations = 4096 in
  let first = S.client_first ~user:"haltsql" ~nonce:"clientnonce" () in
  let server_first =
    Printf.sprintf "r=clientnonceSERVER,s=%s,i=%d" (Base64.encode_string salt) iterations
  in
  match S.client_final S.SHA512 first ~password ~server_first with
  | Error e -> Alcotest.fail (S.error_to_string e)
  | Ok f ->
      let salted = S.hi S.SHA512 ~password ~salt ~iterations in
      Alcotest.(check int) "64-byte Hi" 64 (String.length salted);
      let stored = H.(to_raw_string (digest_string (hmac salted "Client Key"))) in
      let without_proof = "c=biws,r=clientnonceSERVER" in
      let auth = first.bare ^ "," ^ server_first ^ "," ^ without_proof in
      let prefix = without_proof ^ ",p=" in
      check_bool "client-final prefix" true (String.starts_with ~prefix f.final_message);
      let proof =
        Base64.decode_exn
          (String.sub f.final_message (String.length prefix)
             (String.length f.final_message - String.length prefix))
      in
      let client_sig = hmac stored auth in
      let client_key =
        String.init (String.length proof) (fun i ->
            Char.chr (Char.code proof.[i] lxor Char.code client_sig.[i]))
      in
      check_str "proof verifies" (hex stored)
        (hex H.(to_raw_string (digest_string client_key)));
      let server_sig = hmac (hmac salted "Server Key") auth in
      check_str "server signature" (hex server_sig) (hex f.server_signature);
      Alcotest.(check (result unit error))
        "server-final" (Ok ())
        (S.verify_server_final f ("v=" ^ Base64.encode_string server_sig));
      (* a SHA-256 signature over the same exchange is not accepted *)
      let f256 = Result.get_ok (S.client_final S.SHA256 first ~password ~server_first) in
      check_err "other hash" S.Server_signature_mismatch
        (S.verify_server_final f ("v=" ^ Base64.encode_string f256.server_signature))

let test_hi () =
  (* RFC 7914 section 11 (PBKDF2-HMAC-SHA-256, first block) *)
  check_str "c=1" "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    (hex (S.hi S.SHA256 ~password:"passwd" ~salt:"salt" ~iterations:1));
  check_str "c=80000" "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
    (hex (S.hi S.SHA256 ~password:"Password" ~salt:"NaCl" ~iterations:80000));
  check_bool "equal" true (S.equal_ct "abc" "abc");
  check_bool "differ" false (S.equal_ct "abc" "abd");
  check_bool "length" false (S.equal_ct "abc" "abcd");
  check_bool "empty" true (S.equal_ct "" "")

(* ------------------------------------------------------------------ server *)

let start ?(verifier = Some (rfc_verifier ())) ?(user = "user") ?(server_nonce = snonce)
    first =
  S.server_start ~verifier ~mock_secret:"m" ~user ~server_nonce first

let rfc_server () =
  match start client_first_msg with
  | Ok r -> r
  | Error e -> Alcotest.fail (S.error_to_string e)

let test_server_rfc7677 () =
  let st, server_first = rfc_server () in
  check_str "server-first" server_first_msg server_first;
  Alcotest.(check (result string error))
    "server-final" (Ok server_final_msg)
    (S.server_finish st client_final_msg)

let test_server_finish_rejects () =
  let st, _ = rfc_server () in
  let fin m = Result.map ignore (S.server_finish st m) in
  let r = "r=" ^ cnonce ^ snonce in
  let p = ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=" in
  check_err "wrong proof" S.Authentication_failed
    (fin ("c=biws," ^ r ^ ",p=eHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="));
  check_err "non-canonical proof" S.Invalid_proof
    (fin ("c=biws," ^ r ^ ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVR="));
  check_err "short proof" S.Invalid_proof (fin ("c=biws," ^ r ^ ",p=AAAA"));
  check_err "empty proof" S.Invalid_proof (fin ("c=biws," ^ r ^ ",p="));
  check_err "wrong nonce" S.Nonce_mismatch (fin ("c=biws,r=" ^ cnonce ^ "X" ^ p));
  check_err "client nonce only" S.Nonce_mismatch (fin ("c=biws,r=" ^ cnonce ^ p));
  check_err "channel binding echo" S.Channel_binding_mismatch (fin ("c=eSws," ^ r ^ p));
  List.iter
    (fun m ->
      check_err (Printf.sprintf "malformed %S" m) S.Malformed_client_final (fin m))
    [
      "";
      "p=";
      ",p=";
      "garbage";
      r ^ ",c=biws" ^ p;
      "c=biws" ^ p;
      "c=biws," ^ r;
      "junk,c=biws," ^ r ^ p;
    ];
  check_err "too long" S.Message_too_long
    (fin ("c=biws," ^ r ^ ",p=" ^ String.make 4096 'A'));
  (* the password of another user does not pass *)
  let other = S.make_verifier ~salt:(Base64.decode_exn salt_b64) "pen" in
  let st', _ = Result.get_ok (start ~verifier:(Some other) client_first_msg) in
  check_err "wrong password" S.Authentication_failed
    (Result.map ignore (S.server_finish st' client_final_msg))

let test_server_start_rejects () =
  let go m = Result.map ignore (start ~server_nonce:"abc" m) in
  check_err "channel binding requested" S.Channel_binding_unsupported
    (go "p=tls-server-end-point,,n=,r=x");
  check_err "channel binding, no name" S.Channel_binding_unsupported (go "p=,,n=,r=x");
  check_err "authzid" S.Authzid_unsupported (go "n,a=admin,n=,r=x");
  check_err "mandatory extension" S.Unsupported_extension (go "n,,m=ext,n=,r=x");
  check_err "empty nonce" S.Invalid_nonce (go "n,,n=,r=");
  check_err "unprintable nonce" S.Invalid_nonce (go "n,,n=,r=a\000b");
  List.iter
    (fun m -> check_err (Printf.sprintf "malformed %S" m) S.Malformed_client_first (go m))
    [
      "";
      "n";
      "n,";
      "n,,";
      "hello";
      "n,,n=";
      "n,,r=x";
      "n,,r=x,n=";
      "x,,n=,r=x";
      "p,,n=,r=x";
      "n,,n=,junk";
      ",,n=,r=x";
    ];
  check_err "too long" S.Message_too_long (go ("n,,n=" ^ String.make 4096 'u' ^ ",r=x"));
  Alcotest.(check (result unit error)) "y flag" (Ok ()) (go "y,,n=,r=abc");
  Alcotest.(check (result unit error)) "extension" (Ok ()) (go "n,,n=,r=abc,x=y")

let test_server_unknown_user () =
  let first = "n,,n=,r=" ^ cnonce in
  let go () = Result.get_ok (start ~verifier:None ~user:"ghost" first) in
  let st, sf = go () in
  check_str "the mock salt is stable" sf (snd (go ()));
  check_bool "another user, another salt" true
    (sf <> snd (Result.get_ok (start ~verifier:None ~user:"ghost2" first)));
  check_bool "looks like a real server-first" true
    (String.starts_with ~prefix:("r=" ^ cnonce ^ snonce ^ ",s=") sf
    && String.ends_with ~suffix:",i=4096" sf);
  (* a client that answers the mock challenge correctly for some password still fails *)
  let cf = S.client_first ~nonce:cnonce () in
  let f =
    Result.get_ok (S.client_final S.SHA256 cf ~password:"pencil" ~server_first:sf)
  in
  check_err "never succeeds" S.Authentication_failed
    (Result.map ignore (S.server_finish st f.final_message))

let test_roundtrip () =
  let v = S.make_verifier ~salt:"0123456789abcdef" "s3cret!" in
  let cf = S.client_first ~nonce:"clientnonce" () in
  let st, sf =
    Result.get_ok
      (S.server_start ~verifier:(Some v) ~mock_secret:"m" ~user:"agent"
         ~server_nonce:"servernonce" cf.message)
  in
  let f =
    Result.get_ok (S.client_final S.SHA256 cf ~password:"s3cret!" ~server_first:sf)
  in
  let server_final = Result.get_ok (S.server_finish st f.final_message) in
  Alcotest.(check (result unit error))
    "mutual authentication" (Ok ())
    (S.verify_server_final f server_final);
  let wrong =
    Result.get_ok (S.client_final S.SHA256 cf ~password:"wrong" ~server_first:sf)
  in
  check_err "wrong password" S.Authentication_failed
    (Result.map ignore (S.server_finish st wrong.final_message));
  (* a server that does not know the password cannot produce the signature *)
  check_err "impostor server" S.Server_signature_mismatch
    (S.verify_server_final wrong server_final)

let test_verifier () =
  let v = S.make_verifier ~salt:"0123456789abcdef" "pw" in
  let s = S.verifier_to_string v in
  check_bool "format" true
    (String.starts_with ~prefix:"SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$" s);
  check_bool "parse (to_string v) = v" true (S.parse_verifier s = Ok v);
  let k = String.make 43 'A' ^ "=" in
  List.iter
    (fun s ->
      check_bool
        (Printf.sprintf "rejects %S" s)
        true
        (Result.is_error (S.parse_verifier s)))
    [
      "";
      "md5abcdef";
      "SCRAM-SHA-256$4096:c2FsdA==$AAAA:BBBB";
      "SCRAM-SHA-256$0:c2FsdA==$" ^ k ^ ":" ^ k;
      "SCRAM-SHA-256$x:c2FsdA==$" ^ k ^ ":" ^ k;
      "SCRAM-SHA-256$0x1000:c2FsdA==$" ^ k ^ ":" ^ k;
      "SCRAM-SHA-256$-1:c2FsdA==$" ^ k ^ ":" ^ k;
      "SCRAM-SHA-256$4096:$" ^ k ^ ":" ^ k;
      "SCRAM-SHA-256$4096:c2FsdB==$" ^ k ^ ":" ^ k;
      "SCRAM-SHA-256$4096:c2FsdA==$" ^ k;
      "SCRAM-SHA-256$4096:c2FsdA==$" ^ k ^ ":" ^ k ^ ":" ^ k;
      "SCRAM-SHA-256$4096:c2FsdA==$" ^ k ^ ":" ^ k ^ "$";
      "SCRAM-SHA-1$4096:c2FsdA==$" ^ k ^ ":" ^ k;
      "SCRAM-SHA-512$4096:c2FsdA==$" ^ k ^ ":" ^ k;
    ];
  check_bool "accepts" true
    (Result.is_ok (S.parse_verifier ("SCRAM-SHA-256$4096:c2FsdA==$" ^ k ^ ":" ^ k)))

(* No input makes any entry point raise: every prefix of every valid message, and every
   single-byte substitution with a few awkward bytes. *)
let test_no_exceptions () =
  let variants m =
    let n = String.length m in
    List.init (n + 1) (String.sub m 0)
    @ List.concat_map
        (fun c ->
          List.init n (fun i -> String.mapi (fun j x -> if i = j then c else x) m))
        [ ','; '='; '\000'; '\xff'; 'p'; 'm' ]
  in
  let first = rfc_first () and f = rfc_final () in
  let total = ref 0 in
  let run name msg call =
    List.iter
      (fun m ->
        incr total;
        try ignore (call m)
        with e -> Alcotest.failf "%s raised %s on %S" name (Printexc.to_string e) m)
      (variants msg)
  in
  run "client_final" server_first_msg (fun m ->
      Result.map ignore (S.client_final S.SHA256 first ~password:"pencil" ~server_first:m));
  run "verify_server_final" server_final_msg (S.verify_server_final f);
  run "server_start" client_first_msg (fun m -> Result.map ignore (start m));
  let st, _ = rfc_server () in
  run "server_finish" client_final_msg (fun m -> Result.map ignore (S.server_finish st m));
  run "parse_verifier"
    (S.verifier_to_string (rfc_verifier ()))
    (fun m ->
      Result.map ignore
        (Result.map_error (fun _ -> S.Message_too_long) (S.parse_verifier m)));
  check_bool "ran" true (!total > 1000)

let () =
  let t n f = Alcotest.test_case n `Quick f in
  Alcotest.run "scram"
    [
      ( "client",
        [
          t "RFC 7677 vector" test_client_rfc7677;
          t "server-final: what is refused" test_client_server_final_rejects;
          t "server-first: what is refused" test_client_server_first_rejects;
          t "iteration bounds can be set" test_client_bounds_override;
          t "user escaping, nonce, mechanism names" test_escaping_and_nonce;
          t "SCRAM-SHA-512 against an independent computation" test_sha512;
          t "Hi (PBKDF2 RFC 7914) and constant-time equality" test_hi;
        ] );
      ( "server",
        [
          t "RFC 7677 vector" test_server_rfc7677;
          t "client-final: what is refused" test_server_finish_rejects;
          t "client-first: what is refused" test_server_start_rejects;
          t "unknown user" test_server_unknown_user;
          t "verifier format" test_verifier;
        ] );
      ( "both",
        [
          t "client and server agree" test_roundtrip; t "no exceptions" test_no_exceptions;
        ] );
    ]
