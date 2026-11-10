(* haltsql-proxy added latency versus connecting to PostgreSQL directly.

   Both paths use the same client (Haltsql_pgwire.Upstream, SCRAM-SHA-256 auth) and
   the simple query protocol, so the only difference is the proxy hop: verifying the
   statement, relaying the messages and writing one audit record. Direct and proxied
   runs are interleaved in rounds so drift on the machine affects both equally.

   A scratch database (release_bench_<pid>) with app.orders (20k rows over two
   tenants) is created on the target Postgres and dropped afterwards. The proxy runs
   a literal-tenancy policy (bench/fixtures/proxy-policy.yaml), so tenant-scoped
   queries are allowed over the simple protocol. *)

open Lwt.Syntax
open Haltsql_pgwire

let ( >|= ) = Lwt.( >|= )
let ( // ) = Filename.concat

type target = { host : string; port : int; user : string; password : string }

let upstream (t : target) db : Proxy_config.upstream =
  {
    host = t.host;
    port = t.port;
    database = db;
    user = t.user;
    password = Some t.password;
    tls_mode = Tls_disable;
    tls_ca = [];
    connect_timeout = 10.0;
    (* a local benchmark client: keep accepting whatever the server asks for *)
    allow_insecure_auth = true;
  }

exception Pg_error of string

(* Reads until ReadyForQuery; returns the rows seen, raises Pg_error on ErrorResponse
   (after draining to ReadyForQuery). *)
let rec drain io ~rows ~err =
  let* tag, payload = Io.read_message io ~max:(64 * 1024 * 1024) in
  match tag with
  | 'Z' -> ( match err with Some e -> Lwt.fail (Pg_error e) | None -> Lwt.return rows)
  | 'D' -> drain io ~rows:(rows + 1) ~err
  | 'E' ->
      let fields = Wire.decode_fields payload in
      let get c = Option.value ~default:"" (List.assoc_opt c fields) in
      drain io ~rows ~err:(Some (get 'C' ^ " " ^ get 'M'))
  | _ -> drain io ~rows ~err

let connect t db =
  let* io = Upstream.connect (upstream t db) ~application_name:(Some "haltsql-bench") in
  let* _ = drain io ~rows:0 ~err:None in
  Lwt.return io

let query io sql =
  let* () = Io.write io (Wire.frame 'Q' (sql ^ "\000")) in
  drain io ~rows:0 ~err:None

let exec_all t db sqls =
  let* io = connect t db in
  let* () = Lwt_list.iter_s (fun s -> query io s >|= ignore) sqls in
  Io.close io

let schema =
  [
    "CREATE SCHEMA app";
    "CREATE TABLE app.orders (id bigint PRIMARY KEY, tenant_id text NOT NULL, \
     customer_id bigint NOT NULL, status text NOT NULL, total_cents bigint NOT NULL, \
     currency text NOT NULL, created_at timestamptz NOT NULL)";
    "INSERT INTO app.orders SELECT g, CASE WHEN g % 2 = 0 THEN 'acme' ELSE 'globex' END, \
     g % 500, (ARRAY['new','paid','shipped','refunded'])[1 + g % 4], (g * 7919) % \
     100000, 'USD', timestamptz '2026-01-01' + (g || ' minutes')::interval FROM \
     generate_series(1, 20000) g";
    "CREATE INDEX ON app.orders (tenant_id, created_at)";
    "ANALYZE app.orders";
  ]

let queries =
  [
    ( "point_select",
      "SELECT id, status, total_cents FROM app.orders WHERE tenant_id = 'acme' AND id = \
       4242 LIMIT 1",
      1 );
    ( "aggregate",
      "SELECT status, count(*) AS n, sum(total_cents) AS total FROM app.orders WHERE \
       tenant_id = 'acme' GROUP BY status ORDER BY status LIMIT 10",
      2 (* acme holds the even ids: statuses 'new' and 'shipped' *) );
    ( "range_100_rows",
      "SELECT id, customer_id, status, total_cents, created_at FROM app.orders WHERE \
       tenant_id = 'acme' AND created_at >= timestamptz '2026-01-02' ORDER BY created_at \
       LIMIT 100",
      100 );
  ]

let denied_sql = "SELECT id FROM app.orders WHERE tenant_id = 'globex' LIMIT 1"

let proxy_config ~dir ~listen_port ~pg ~db ~verifier ~policy =
  `Assoc
    [
      ("apiVersion", `String "haltsql.dev/v1");
      ("kind", `String "ProxyConfig");
      ("listen", `String (Printf.sprintf "127.0.0.1:%d" listen_port));
      ( "upstream",
        `Assoc
          [
            ("host", `String pg.host);
            ("port", `Int pg.port);
            ("database", `String db);
            ("user", `String pg.user);
            ("password", `String "${env:HALTSQL_BENCH_UPSTREAM_PASSWORD}");
          ] );
      ("policies", `List [ `Assoc [ ("path", `String policy) ] ]);
      ( "auth",
        `Assoc
          [
            ("method", `String "scram");
            ( "users",
              `List
                [
                  `Assoc
                    [
                      ("name", `String "bench");
                      ("scram_verifier", `String verifier);
                      ("policy", `String "proxy-bench");
                      ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                    ];
                ] );
          ] );
      ("limits", `Assoc [ ("max_connections", `Int 512) ]);
      ( "audit",
        `Assoc [ ("type", `String "file"); ("path", `String (dir // "audit.jsonl")) ] );
      ("logging", `Assoc [ ("level", `String "info") ]);
    ]

(* Sequential latency of [sql] on one connection: [rounds] rounds of [per_round]
   queries, alternating direct and proxied connections. *)
let sequential ~direct_io ~proxy_io ~sql ~expect_rows ~rounds ~per_round =
  let d = Array.make (rounds * per_round) 0.0
  and p = Array.make (rounds * per_round) 0.0 in
  let errors = ref 0 in
  let time_into io arr base =
    let rec go i =
      if i = per_round then Lwt.return_unit
      else
        let t0 = Stats.now () in
        let* rows = query io sql in
        arr.(base + i) <- (Stats.now () -. t0) *. 1e6;
        if rows <> expect_rows then (
          if !errors = 0 then
            Printf.eprintf "proxy bench: %d rows, expected %d for %s\n%!" rows expect_rows
              sql;
          incr errors);
        go (i + 1)
    in
    go 0
  in
  let* () = time_into direct_io (Array.make per_round 0.0) 0 in
  let* () = time_into proxy_io (Array.make per_round 0.0) 0 in
  let rec rounds_loop r =
    if r = rounds then Lwt.return_unit
    else
      let* () = time_into direct_io d (r * per_round) in
      let* () = time_into proxy_io p (r * per_round) in
      rounds_loop (r + 1)
  in
  let* () = rounds_loop 0 in
  Lwt.return (d, p, !errors)

(* Closed-loop throughput with [conns] connections for [duration] seconds. *)
let concurrent t db ~conns ~duration ~sql =
  let* ios = Lwt_list.map_p (fun _ -> connect t db) (List.init conns Fun.id) in
  let lat = ref [] and errors = ref 0 in
  let t_end = Stats.now () +. duration in
  let worker io =
    let rec go () =
      let t0 = Stats.now () in
      if t0 >= t_end then Lwt.return_unit
      else
        let* () =
          Lwt.catch
            (fun () -> query io sql >|= ignore)
            (fun _ ->
              incr errors;
              Lwt.return_unit)
        in
        lat := ((Stats.now () -. t0) *. 1e6) :: !lat;
        go ()
    in
    go ()
  in
  let* () = Lwt_list.iter_p worker ios in
  let* () = Lwt_list.iter_p Io.close ios in
  Lwt.return (Array.of_list !lat, !errors)

let available pg =
  Lwt_main.run
    (Lwt.catch
       (fun () ->
         let* io = connect pg "postgres" in
         let* () = Io.close io in
         Lwt.return_ok ())
       (fun e -> Lwt.return_error (Printexc.to_string e)))

let run ~root ~proxy ~pg ~small =
  match available pg with
  | Error e ->
      Printf.printf "proxy suite SKIPPED: Postgres at %s:%d unavailable (%s)\n%!" pg.host
        pg.port e;
      []
  | Ok () ->
      let db = Printf.sprintf "release_bench_%d" (Unix.getpid ()) in
      let dir = Procs.temp_dir "haltsql-bench-proxy" in
      let admin sqls = Lwt_main.run (exec_all pg "postgres" sqls) in
      admin [ "DROP DATABASE IF EXISTS " ^ db; "CREATE DATABASE " ^ db ];
      Fun.protect
        ~finally:(fun () ->
          (try admin [ "DROP DATABASE IF EXISTS " ^ db ^ " WITH (FORCE)" ]
           with e ->
             Printf.eprintf "could not drop %s: %s\n%!" db (Printexc.to_string e));
          Procs.rm_rf dir)
        (fun () ->
          Lwt_main.run (exec_all pg db schema);
          let bench_pw = "bench-" ^ string_of_int (Random.bits ()) in
          let verifier = Scram.verifier_to_string (Scram.make_verifier bench_pw) in
          let listen_port = Procs.free_port () in
          let cfg = dir // "proxy.json" in
          Procs.write_file cfg
            (Yojson.Safe.to_string
               (proxy_config ~dir ~listen_port ~pg ~db ~verifier
                  ~policy:(root // "bench/fixtures/proxy-policy.yaml")));
          let env =
            Array.append
              [| "HALTSQL_BENCH_UPSTREAM_PASSWORD=" ^ pg.password |]
              (Unix.environment ())
          in
          let log = dir // "proxy.log" in
          let pid = Procs.spawn ~env ~log proxy [ "run"; "--config"; cfg ] in
          Fun.protect
            ~finally:(fun () -> Procs.stop pid)
            (fun () ->
              if not (Procs.wait_port ~timeout:15.0 listen_port) then
                failwith ("haltsql-proxy did not start:\n" ^ Procs.read_file log);
              let via =
                {
                  host = "127.0.0.1";
                  port = listen_port;
                  user = "bench";
                  password = bench_pw;
                }
              in
              Lwt_main.run
                (let* direct_io = connect pg db in
                 let* proxy_io = connect via db in
                 (* the proxy must actually enforce: a cross-tenant query is denied *)
                 let* () =
                   Lwt.catch
                     (fun () ->
                       let* _ = query proxy_io denied_sql in
                       Lwt.fail_with "proxy allowed a cross-tenant query")
                     (function
                       | Pg_error e
                         when String.length e >= 5 && String.sub e 0 5 = "42501" ->
                           Lwt.return_unit
                       | e -> Lwt.fail e)
                 in
                 let rounds = if small then 4 else 10
                 and per_round = if small then 250 else 500 in
                 let* seq =
                   Lwt_list.map_s
                     (fun (name, sql, expect_rows) ->
                       let* d, p, errors =
                         sequential ~direct_io ~proxy_io ~sql ~expect_rows ~rounds
                           ~per_round
                       in
                       let wall a = Array.fold_left ( +. ) 0.0 a /. 1e6 in
                       let rd =
                         Stats.summarize ~suite:"proxy" ~name:(name ^ "_direct")
                           ~unit_:"us" ~wall:(wall d) d
                       and rp =
                         Stats.summarize ~errors ~suite:"proxy"
                           ~name:(name ^ "_via_proxy") ~unit_:"us" ~wall:(wall p) p
                       in
                       (* differences of percentiles, not percentiles of differences:
                          only p50 and p99 are reported *)
                       let added =
                         {
                           (Stats.summarize ~suite:"proxy" ~name:(name ^ "_added")
                              ~unit_:"us" ~wall:0.0 [||])
                           with
                           p50 = rp.p50 -. rd.p50;
                           p99 = rp.p99 -. rd.p99;
                         }
                       in
                       Lwt.return [ rd; rp; added ])
                     queries
                 in
                 let* () = Io.close direct_io in
                 let* () = Io.close proxy_io in
                 let conns = if small then 8 else 32
                 and duration = if small then 3.0 else 8.0 in
                 let _, sql, _ = List.hd queries in
                 let* dl, de = concurrent pg db ~conns ~duration ~sql in
                 let* pl, pe = concurrent via db ~conns ~duration ~sql in
                 let conc name l e =
                   Stats.summarize ~errors:e ~suite:"proxy"
                     ~name:(Printf.sprintf "point_select_c%d_%s" conns name)
                     ~unit_:"us" ~wall:duration
                     ~extra:[ ("concurrency", `Int conns) ]
                     l
                 in
                 Lwt.return
                   (List.concat seq @ [ conc "direct" dl de; conc "via_proxy" pl pe ]))))
