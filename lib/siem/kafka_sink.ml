open Lwt.Infix
module Config = Haltsql_load.Config
module W = Kafka_wire

exception Conn_error of string

let conn_fail fmt = Printf.ksprintf (fun s -> Lwt.fail (Conn_error s)) fmt
let max_response = 16 * 1024 * 1024

type conn = {
  addr : string * int;
  ic : Lwt_io.input_channel;
  oc : Lwt_io.output_channel;
  close : unit -> unit Lwt.t;
  mutable corr : int32;
  produce_v : int;
  metadata_v : int;
}

type tls = { authenticator : X509.Authenticator.t; own : Tls.Config.own_cert option }

type t = {
  cfg : Config.kafka_sink;
  key : string;
  brokers : (string * int) list;
  tls : tls option;
  request_timeout : float;
  connect_timeout : float;
  on_event : string -> unit;
  mutable conn : conn option;
  mutable partition : int option;
  mutable next_bootstrap : int;
}

let name (cfg : Config.kafka_sink) =
  Printf.sprintf "kafka://%s/%s"
    (match cfg.kafka_brokers with b :: _ -> b | [] -> "?")
    cfg.kafka_topic

let partition t = t.partition

let parse_broker s =
  match String.rindex_opt s ':' with
  | None -> Error (Printf.sprintf "kafka broker %S: expected host:port" s)
  | Some i -> (
      let host = String.sub s 0 i
      and port = String.sub s (i + 1) (String.length s - i - 1) in
      let host =
        if
          String.length host >= 2 && host.[0] = '[' && host.[String.length host - 1] = ']'
        then String.sub host 1 (String.length host - 2)
        else host
      in
      match int_of_string_opt port with
      | Some p when p > 0 && p < 65536 && host <> "" -> Ok (host, p)
      | _ -> Error (Printf.sprintf "kafka broker %S: expected host:port" s))

let create ?(request_timeout = 30.) ?(connect_timeout = 10.) ?(on_event = ignore) ~key
    (cfg : Config.kafka_sink) =
  let ( let* ) = Result.bind in
  let* brokers =
    List.fold_right
      (fun b acc ->
        Result.bind acc (fun l -> Result.map (fun x -> x :: l) (parse_broker b)))
      cfg.kafka_brokers (Ok [])
  in
  if brokers = [] then Error "kafka sink: no brokers"
  else if request_timeout < 6. then Error "kafka sink: request_timeout must be >= 6 s"
  else
    let* tls =
      match cfg.kafka_tls with
      | None -> Ok None
      | Some tc ->
          let* authenticator =
            match tc.kafka_ca with
            | Some pem ->
                let* cas = Siem_pem.certificates ~what:"kafka tls.ca_file" pem in
                Ok
                  (X509.Authenticator.chain_of_trust
                     ~time:(fun () -> Some (Ptime_clock.now ()))
                     cas)
            | None -> (
                match Ca_certs.authenticator () with
                | Ok a -> Ok a
                | Error (`Msg m) -> Error ("kafka sink: system trust store: " ^ m))
          in
          let* own =
            match (tc.kafka_cert, tc.kafka_key) with
            | Some c, Some k ->
                let* chain = Siem_pem.certificates ~what:"kafka tls.cert_file" c in
                let* key = Siem_pem.private_key ~what:"kafka tls.key_file" k in
                Ok (Some (`Single (chain, key)))
            | None, None -> Ok None
            | _ -> Error "kafka sink: tls.cert_file and tls.key_file go together"
          in
          Ok (Some { authenticator; own })
    in
    Ok
      {
        cfg;
        key;
        brokers;
        tls;
        request_timeout;
        connect_timeout;
        on_event;
        conn = None;
        partition = None;
        next_bootstrap = 0;
      }

(* ---- connections ---- *)

let tcp_connect t (host, port) =
  Lwt.catch
    (fun () ->
      Lwt_unix.getaddrinfo host (string_of_int port) [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ])
    (fun _ -> Lwt.return [])
  >>= fun addrs ->
  let rec attempt last = function
    | [] ->
        conn_fail "cannot connect to %s:%d: %s" host port
          (Option.value ~default:"cannot resolve host" last)
    | ai :: rest -> (
        let fd = Lwt_unix.socket ai.Unix.ai_family Unix.SOCK_STREAM 0 in
        Lwt.catch
          (fun () ->
            Lwt_unix.with_timeout t.connect_timeout (fun () ->
                Lwt_unix.connect fd ai.Unix.ai_addr)
            >|= fun () ->
            (try Lwt_unix.setsockopt fd Unix.TCP_NODELAY true with _ -> ());
            Ok fd)
          (fun e ->
            Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
            >|= fun () ->
            Error
              (match e with
              | Lwt_unix.Timeout -> "timed out"
              | Unix.Unix_error (err, _, _) -> Unix.error_message err
              | e -> Printexc.to_string e))
        >>= function
        | Ok fd -> Lwt.return fd
        | Error m -> attempt (Some m) rest)
  in
  attempt None addrs

let tls_failure = function
  | Tls_lwt.Tls_failure f -> Tls.Engine.string_of_failure f
  | Tls_lwt.Tls_alert a -> Tls.Packet.alert_type_to_string a
  | e -> Printexc.to_string e

let transport t (host, port) fd =
  match t.tls with
  | None ->
      let ic = Lwt_io.of_fd ~mode:Lwt_io.input fd
      and oc = Lwt_io.of_fd ~mode:Lwt_io.output fd in
      Lwt.return
        ( ic,
          oc,
          fun () -> Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) )
  | Some tls -> (
      let ip, peer_name =
        match Ipaddr.of_string host with
        | Ok ip -> (Some ip, None)
        | Error _ -> (
            match Result.bind (Domain_name.of_string host) Domain_name.host with
            | Ok h -> (None, Some h)
            | Error _ -> (None, None))
      in
      match
        Tls.Config.client ~authenticator:tls.authenticator ?peer_name ?ip
          ?certificates:tls.own ()
      with
      | Error (`Msg m) ->
          Lwt_unix.close fd >>= fun () -> conn_fail "kafka TLS configuration: %s" m
      | Ok cfg ->
          Lwt.catch
            (fun () ->
              Lwt_unix.with_timeout t.connect_timeout (fun () ->
                  Tls_lwt.Unix.client_of_fd cfg ?host:peer_name fd)
              >|= fun s ->
              let ic, oc = Tls_lwt.of_t s in
              ( ic,
                oc,
                fun () ->
                  Lwt.catch (fun () -> Tls_lwt.Unix.close s) (fun _ -> Lwt.return_unit) ))
            (fun e ->
              Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
              >>= fun () ->
              conn_fail "TLS handshake with %s:%d failed: %s" host port
                (match e with Lwt_unix.Timeout -> "timed out" | e -> tls_failure e)))

(* One request, one response; any failure leaves the connection unusable. *)
let raw_call t c ~api_key ~version body =
  let corr = c.corr in
  c.corr <- Int32.succ corr;
  let host, port = c.addr in
  let frame =
    W.frame ~api_key ~api_version:version ~correlation_id:corr
      ~client_id:t.cfg.kafka_client_id body
  in
  Lwt.catch
    (fun () ->
      Lwt_unix.with_timeout t.request_timeout (fun () ->
          Lwt_io.write c.oc frame >>= fun () ->
          Lwt_io.flush c.oc >>= fun () ->
          let hdr = Bytes.create 4 in
          Lwt_io.read_into_exactly c.ic hdr 0 4 >>= fun () ->
          let n = Int32.to_int (Bytes.get_int32_be hdr 0) in
          if n < 4 || n > max_response then
            conn_fail "invalid response size %d from %s:%d" n host port
          else
            let buf = Bytes.create n in
            Lwt_io.read_into_exactly c.ic buf 0 n >>= fun () ->
            let s = Bytes.unsafe_to_string buf in
            let id, off = W.response_correlation s in
            if id <> corr then conn_fail "correlation id mismatch from %s:%d" host port
            else Lwt.return (String.sub s off (String.length s - off))))
    (function
      | Conn_error _ as e -> Lwt.fail e
      | Lwt_unix.Timeout -> conn_fail "request to %s:%d timed out" host port
      | End_of_file -> conn_fail "connection to %s:%d closed by the broker" host port
      | Unix.Unix_error (e, _, _) ->
          conn_fail "connection to %s:%d failed: %s" host port (Unix.error_message e)
      | e -> conn_fail "connection to %s:%d failed: %s" host port (tls_failure e))

let decode what f =
  match f () with
  | v -> Lwt.return v
  | exception W.Malformed m -> conn_fail "malformed %s response: %s" what m

let pick_version apis ~key ~lo ~hi what =
  match List.find_opt (fun (k, _, _) -> k = key) apis with
  | Some (_, blo, bhi) when max lo blo <= min hi bhi -> Lwt.return (min hi bhi)
  | _ -> conn_fail "broker does not support %s v%d-v%d" what lo hi

let printable s =
  String.map (fun c -> if c < ' ' || c > '~' then '?' else c) s |> fun s ->
  if String.length s > 200 then String.sub s 0 200 else s

let sasl_authenticate t c ~auth_v (sasl : Config.kafka_sasl) =
  let mech =
    match sasl.sasl_mechanism with
    | Config.Sasl_plain -> "PLAIN"
    | Config.Sasl_scram_sha_256 -> "SCRAM-SHA-256"
    | Config.Sasl_scram_sha_512 -> "SCRAM-SHA-512"
  in
  raw_call t c ~api_key:W.sasl_handshake ~version:1 (W.sasl_handshake_request mech)
  >>= fun r ->
  decode "SaslHandshake" (fun () -> W.decode_sasl_handshake r) >>= fun (err, mechs) ->
  if err <> 0 then
    conn_fail "SASL mechanism %s not enabled on the broker (it offers: %s)" mech
      (printable (String.concat ", " mechs))
  else
    let step bytes =
      raw_call t c ~api_key:W.sasl_authenticate ~version:auth_v
        (W.sasl_authenticate_request bytes)
      >>= fun r ->
      decode "SaslAuthenticate" (fun () -> W.decode_sasl_authenticate ~version:auth_v r)
      >>= fun (err, msg, auth) ->
      if err <> 0 then
        conn_fail "SASL %s authentication failed: %s%s" mech (W.error_name err)
          (match msg with Some m -> " (" ^ printable m ^ ")" | None -> "")
      else Lwt.return auth
    in
    match sasl.sasl_mechanism with
    | Config.Sasl_plain ->
        step ("\000" ^ sasl.sasl_username ^ "\000" ^ sasl.sasl_password) >|= ignore
    | Config.Sasl_scram_sha_256 | Config.Sasl_scram_sha_512 -> (
        let h =
          if sasl.sasl_mechanism = Config.Sasl_scram_sha_256 then Scram.Sha256
          else Scram.Sha512
        in
        let first = Scram.client_first ~username:sasl.sasl_username () in
        step first.message >>= fun server_first ->
        match Scram.client_final h ~password:sasl.sasl_password first ~server_first with
        | Error m -> conn_fail "%s" m
        | Ok (final, expected) -> (
            step final >>= fun server_final ->
            match Scram.verify_server_final ~expected server_final with
            | Ok () -> Lwt.return_unit
            | Error m -> conn_fail "%s" m))

let connect t addr =
  tcp_connect t addr >>= fun fd ->
  transport t addr fd >>= fun (ic, oc, close) ->
  let c0 = { addr; ic; oc; close; corr = 1l; produce_v = 3; metadata_v = 1 } in
  Lwt.catch
    (fun () ->
      raw_call t c0 ~api_key:W.api_versions ~version:0 "" >>= fun r ->
      decode "ApiVersions" (fun () -> W.decode_api_versions r) >>= fun (err, apis) ->
      if err <> 0 then conn_fail "ApiVersions failed: %s" (W.error_name err)
      else
        pick_version apis ~key:W.produce ~lo:3 ~hi:8 "Produce" >>= fun produce_v ->
        pick_version apis ~key:W.metadata ~lo:1 ~hi:8 "Metadata" >>= fun metadata_v ->
        let c = { c0 with produce_v; metadata_v } in
        (match t.cfg.kafka_sasl with
          | None -> Lwt.return_unit
          | Some sasl ->
              pick_version apis ~key:W.sasl_handshake ~lo:1 ~hi:1 "SaslHandshake"
              >>= fun _ ->
              pick_version apis ~key:W.sasl_authenticate ~lo:0 ~hi:1 "SaslAuthenticate"
              >>= fun auth_v -> sasl_authenticate t c ~auth_v sasl)
        >|= fun () -> c)
    (fun e -> close () >>= fun () -> Lwt.fail e)

let drop_conn t =
  match t.conn with
  | None -> Lwt.return_unit
  | Some c ->
      t.conn <- None;
      c.close ()

(* ---- leader discovery ---- *)

let metadata_from t addr =
  connect t addr >>= fun c ->
  Lwt.catch
    (fun () ->
      raw_call t c ~api_key:W.metadata ~version:c.metadata_v
        (W.metadata_request ~version:c.metadata_v ~topic:t.cfg.kafka_topic)
      >>= fun r ->
      decode "Metadata" (fun () ->
          W.decode_metadata ~version:c.metadata_v ~topic:t.cfg.kafka_topic r)
      >|= fun md -> (c, md))
    (fun e -> c.close () >>= fun () -> Lwt.fail e)

let discover t =
  let n = List.length t.brokers in
  let rec try_broker i last =
    if i >= n then
      conn_fail "no bootstrap broker reachable: %s" (Option.value ~default:"?" last)
    else
      let idx = (t.next_bootstrap + i) mod n in
      Lwt.catch
        (fun () -> metadata_from t (List.nth t.brokers idx) >|= fun r -> Ok r)
        (function Conn_error m -> Lwt.return (Error m) | e -> Lwt.fail e)
      >>= function
      | Ok r ->
          t.next_bootstrap <- idx;
          Lwt.return r
      | Error m ->
          t.next_bootstrap <- (idx + 1) mod n;
          try_broker (i + 1) (Some m)
  in
  try_broker 0 None >>= fun (bc, (brokers, tm)) ->
  let give_up fmt =
    Printf.ksprintf (fun s -> bc.close () >>= fun () -> conn_fail "%s" s) fmt
  in
  if tm.W.topic_error <> 0 then
    give_up "topic %s: %s" t.cfg.kafka_topic (W.error_name tm.topic_error)
  else if tm.partitions = [] then give_up "topic %s has no partitions" t.cfg.kafka_topic
  else
    let p =
      match t.partition with
      | Some p -> p
      | None ->
          let p = W.partition_for_key t.key ~partitions:(List.length tm.partitions) in
          t.partition <- Some p;
          t.on_event
            (Printf.sprintf "audit sink %s: shipping to partition %d" (name t.cfg) p);
          p
    in
    match
      List.find_opt (fun (pm : W.partition_meta) -> pm.partition = p) tm.partitions
    with
    | None -> give_up "topic %s: partition %d no longer exists" t.cfg.kafka_topic p
    | Some pm when pm.partition_error <> 0 && pm.leader < 0 ->
        give_up "topic %s partition %d: %s" t.cfg.kafka_topic p
          (W.error_name pm.partition_error)
    | Some pm when pm.leader < 0 ->
        give_up "topic %s partition %d has no leader" t.cfg.kafka_topic p
    | Some pm -> (
        match List.find_opt (fun (b : W.broker) -> b.node_id = pm.leader) brokers with
        | None -> give_up "leader %d of partition %d is not in the metadata" pm.leader p
        | Some b ->
            if (b.host, b.port) = bc.addr then Lwt.return bc
            else bc.close () >>= fun () -> connect t (b.host, b.port))

let ensure t =
  match t.conn with
  | Some c -> Lwt.return c
  | None ->
      discover t >|= fun c ->
      t.conn <- Some c;
      c

(* ---- produce ---- *)

type outcome = Ok_all | Too_large | Failed of string

let produce_once t (entries : Stream_sink.entry array) =
  Lwt.catch
    (fun () ->
      ensure t >>= fun c ->
      let p = Option.get t.partition in
      let records =
        Array.to_list
          (Array.map
             (fun (e : Stream_sink.entry) -> { W.key = Some t.key; value = e.line })
             entries)
      in
      let batch =
        W.record_batch
          ~timestamp_ms:(Int64.of_float (Unix.gettimeofday () *. 1000.))
          records
      in
      let acks =
        match t.cfg.kafka_acks with Config.Acks_all -> -1 | Config.Acks_leader -> 1
      in
      let timeout_ms = int_of_float ((t.request_timeout -. 5.) *. 1000.) in
      raw_call t c ~api_key:W.produce ~version:c.produce_v
        (W.produce_request ~version:c.produce_v ~acks ~timeout_ms ~topic:t.cfg.kafka_topic
           ~partition:p batch)
      >>= fun r ->
      decode "Produce" (fun () ->
          W.decode_produce ~version:c.produce_v ~topic:t.cfg.kafka_topic ~partition:p r)
      >>= fun (err, _offset, msg) ->
      if err = 0 then Lwt.return Ok_all
      else if err = 10 || err = 18 then Lwt.return Too_large
      else
        let m =
          Printf.sprintf "produce to %s/%d: %s%s" t.cfg.kafka_topic p (W.error_name err)
            (match msg with Some m -> " (" ^ printable m ^ ")" | None -> "")
        in
        (if W.refresh_metadata err then drop_conn t else Lwt.return_unit) >|= fun () ->
        Failed m)
    (function
      | Conn_error m -> drop_conn t >|= fun () -> Failed m
      | e -> drop_conn t >|= fun () -> Failed (Printexc.to_string e))

let deliver t entries =
  let n = Array.length entries in
  let results = Array.make n (Stream_sink.Retry "not sent") in
  (* Ships entries.(lo .. hi-1) in order; returns false at the first failure. *)
  let rec ship lo hi =
    if lo >= hi then Lwt.return (Ok ())
    else
      produce_once t (Array.sub entries lo (hi - lo)) >>= function
      | Ok_all ->
          Array.fill results lo (hi - lo) Stream_sink.Delivered;
          Lwt.return (Ok ())
      | Too_large when hi - lo = 1 ->
          results.(lo) <-
            Stream_sink.Rejected
              {
                reason = "too_large";
                detail = "record exceeds the broker's message size limit";
              };
          Lwt.return (Ok ())
      | Too_large -> (
          let mid = lo + ((hi - lo) / 2) in
          ship lo mid >>= function Ok () -> ship mid hi | Error _ as e -> Lwt.return e)
      | Failed m -> Lwt.return (Error m)
  in
  ship 0 n >|= function
  | Ok () -> Ok results
  | Error m ->
      if Array.for_all (function Stream_sink.Retry _ -> true | _ -> false) results then
        Error m
      else
        Ok
          (Array.map
             (function Stream_sink.Retry _ -> Stream_sink.Retry m | r -> r)
             results)

let close t = drop_conn t
