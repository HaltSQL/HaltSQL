(** Test helper: writes a throwaway PKI into DIR ([argv.(1)]):
    {v
    ca.pem            test CA
    server.pem/.key   server cert for localhost / 127.0.0.1, signed by ca
    client.pem/.key   client cert CN=agent-cert, SAN URI spiffe://haltsql.test/agent
    rogue.pem/.key    client cert CN=agent-cert signed by an unrelated CA
    v}
    Keys are ECDSA P-256. Never use outside tests. *)

let ok = function Ok x -> x | Error (`Msg m) -> failwith m

let write path s =
  (* keys must be 0600 or libpq refuses them *)
  let oc = open_out_gen [ Open_wronly; Open_creat; Open_trunc; Open_binary ] 0o600 path in
  output_string oc s;
  close_out oc

let dn cn = [ X509.Distinguished_name.Relative_distinguished_name.singleton (CN cn) ]
let now () = Ptime_clock.now ()

let span days =
  match Ptime.Span.of_int_s (days * 86400) |> fun d -> Ptime.add_span (now ()) d with
  | Some t -> t
  | None -> failwith "time"

let valid_from () =
  match Ptime.sub_span (now ()) (Ptime.Span.of_int_s 3600) with
  | Some t -> t
  | None -> now ()

let make_ca name =
  let key = X509.Private_key.generate `P256 in
  let csr = ok (X509.Signing_request.create (dn name) key) in
  let ext =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (true, None))
      |> add Key_usage (true, [ `Key_cert_sign; `CRL_sign; `Digital_signature ]))
  in
  let cert =
    match
      X509.Signing_request.sign csr ~valid_from:(valid_from ()) ~valid_until:(span 30)
        ~extensions:ext key (dn name)
    with
    | Ok c -> c
    | Error _ -> failwith "sign ca"
  in
  (key, cert)

let make_leaf ~ca_key ~ca_cert ~cn ~usage ~san =
  let key = X509.Private_key.generate `P256 in
  let csr = ok (X509.Signing_request.create (dn cn) key) in
  let ext =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (false, None))
      |> add Key_usage (true, [ `Digital_signature; `Key_agreement ])
      |> add Ext_key_usage (false, [ usage ])
      |> add Subject_alt_name (false, san))
  in
  let cert =
    match
      X509.Signing_request.sign csr ~valid_from:(valid_from ()) ~valid_until:(span 30)
        ~extensions:ext ca_key
        (X509.Certificate.subject ca_cert)
    with
    | Ok c -> c
    | Error _ -> failwith "sign leaf"
  in
  (key, cert)

let () =
  Mirage_crypto_rng_unix.use_default ();
  let dir = Sys.argv.(1) in
  let p f = Filename.concat dir f in
  let ca_key, ca_cert = make_ca "haltsql test CA" in
  write (p "ca.pem") (X509.Certificate.encode_pem ca_cert);
  let skey, scert =
    make_leaf ~ca_key ~ca_cert ~cn:"localhost" ~usage:`Server_auth
      ~san:
        X509.General_name.(singleton DNS [ "localhost" ] |> add IP [ "\127\000\000\001" ])
  in
  write (p "server.pem") (X509.Certificate.encode_pem scert);
  write (p "server.key") (X509.Private_key.encode_pem skey);
  let ckey, ccert =
    make_leaf ~ca_key ~ca_cert ~cn:"agent-cert" ~usage:`Client_auth
      ~san:X509.General_name.(singleton URI [ "spiffe://haltsql.test/agent" ])
  in
  write (p "client.pem") (X509.Certificate.encode_pem ccert);
  write (p "client.key") (X509.Private_key.encode_pem ckey);
  let rca_key, rca_cert = make_ca "rogue CA" in
  let rkey, rcert =
    make_leaf ~ca_key:rca_key ~ca_cert:rca_cert ~cn:"agent-cert" ~usage:`Client_auth
      ~san:X509.General_name.(singleton URI [ "spiffe://haltsql.test/agent" ])
  in
  write (p "rogue.pem") (X509.Certificate.encode_pem rcert);
  write (p "rogue.key") (X509.Private_key.encode_pem rkey)
