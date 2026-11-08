(* Real servers in Docker for the bundle source integration tests.

   Every container is named haltsql-bundles-*, publishes only on 127.0.0.1
   ports 15000-15009 and is removed at exit. Files the containers need live in
   a fresh directory below the test's working directory. *)

let prefix = "haltsql-bundles-"

(* host ports (assigned range 15000-15009) *)
let port_anon = 15000
let port_basic = 15001
let port_token_registry = 15002
let port_token_auth = 15003
let port_minio = 15004
let port_minio_console = 15005
let port_https = 15006
let log fmt = Printf.ksprintf (fun s -> prerr_endline ("[docker-env] " ^ s)) fmt

let read_all path =
  match In_channel.with_open_bin path In_channel.input_all with
  | s -> s
  | exception _ -> ""

let tmp_out =
  lazy
    (let f = Filename.temp_file "haltsql-bundles" ".out" in
     at_exit (fun () -> try Sys.remove f with Sys_error _ -> ());
     f)

(* Runs a command, returns (exit code, stdout+stderr). *)
let run prog args =
  let out = Lazy.force tmp_out in
  let cmd = Filename.quote_command prog args ~stdout:out ~stderr:out in
  let code = Sys.command cmd in
  (code, read_all out)

let docker args = run "docker" args

let docker_ok args =
  match docker args with
  | 0, out -> out
  | code, out ->
      failwith
        (Printf.sprintf "docker %s failed (%d): %s" (String.concat " " args) code out)

let available =
  lazy
    (match Sys.getenv_opt "HALTSQL_SKIP_DOCKER" with
    | Some ("1" | "true" | "yes") -> Error "HALTSQL_SKIP_DOCKER is set"
    | _ -> (
        match docker [ "info"; "--format"; "{{.ServerVersion}}" ] with
        | 0, _ -> Ok ()
        | _, out ->
            Error
              ("Docker is not available: "
              ^ String.trim
                  (if String.length out > 200 then String.sub out 0 200 else out))))

let started : string list ref = ref []
let remove name = ignore (docker [ "rm"; "-f"; "-v"; name ])

let cleanup () =
  List.iter remove !started;
  started := []

let () = at_exit cleanup
let image_present img = fst (docker [ "image"; "inspect"; img ]) = 0

let ensure_image img =
  if not (image_present img) then begin
    log "pulling %s" img;
    ignore (docker_ok [ "pull"; img ])
  end

(* docker run -d --name haltsql-bundles-<name> ... *)
let start ~name ~image args cmd =
  let full = prefix ^ name in
  remove full;
  ensure_image image;
  ignore (docker_ok ([ "run"; "-d"; "--name"; full ] @ args @ [ image ] @ cmd));
  started := full :: !started;
  full

let stop name = ignore (docker_ok [ "stop"; "-t"; "2"; name ])
let restart name = ignore (docker_ok [ "start"; name ])

let rec mkdir_p d =
  if not (Sys.file_exists d) then begin
    mkdir_p (Filename.dirname d);
    Unix.mkdir d 0o755
  end

let write ?(perm = 0o644) path contents =
  mkdir_p (Filename.dirname path);
  Out_channel.with_open_gen [ Open_wronly; Open_creat; Open_trunc; Open_binary ] perm path
    (fun oc -> Out_channel.output_string oc contents);
  Unix.chmod path perm

let workdir =
  lazy
    (let d =
       Filename.concat (Sys.getcwd ()) (Printf.sprintf "docker-tmp-%d" (Unix.getpid ()))
     in
     mkdir_p d;
     Unix.chmod d 0o755;
     at_exit (fun () -> ignore (run "rm" [ "-rf"; d ]));
     d)

let path p = Filename.concat (Lazy.force workdir) p

let random_hex n =
  let ic = open_in_bin "/dev/urandom" in
  let s = really_input_string ic n in
  close_in ic;
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq s)))

let openssl args =
  match run "openssl" args with
  | 0, _ -> ()
  | c, out ->
      failwith
        (Printf.sprintf "openssl %s failed (%d): %s" (String.concat " " args) c out)

(* bcrypt hash for htpasswd / docker_auth, with the host's htpasswd or, failing
   that, the one in the httpd image. *)
let bcrypt ~user ~password =
  let line =
    match run "htpasswd" [ "-Bbn"; user; password ] with
    | 0, out -> out
    | _ ->
        docker_ok
          [
            "run";
            "--rm";
            "--entrypoint";
            "htpasswd";
            "httpd:2-alpine";
            "-Bbn";
            user;
            password;
          ]
  in
  let line = String.trim line in
  match String.index_opt line ':' with
  | Some i -> String.sub line (i + 1) (String.length line - i - 1)
  | None -> failwith "unexpected htpasswd output"

(* Waits until [check ()] holds (up to [timeout] seconds). *)
let wait_until ?(timeout = 60.) ~what check =
  let deadline = Unix.gettimeofday () +. timeout in
  let rec go () =
    if check () then ()
    else if Unix.gettimeofday () > deadline then failwith ("timed out waiting for " ^ what)
    else begin
      Unix.sleepf 0.3;
      go ()
    end
  in
  go ()

let http_status ?ctx url =
  match
    Lwt_main.run (Haltsql_cloud.Http.request ?ctx ~timeout:2. `GET (Uri.of_string url))
  with
  | Ok r -> Some r.status
  | Error _ -> None

let wait_http ?ctx ~what url = wait_until ~what (fun () -> http_status ?ctx url <> None)

(* ------------------------------------------------------------- services *)

let registry_image = "registry:2"
let minio_image = "pgsty/minio:latest"
let auth_image = "cesanta/docker_auth:1"
let nginx_image = "nginx:alpine"
let oras_image = "ghcr.io/oras-project/oras:v1.2.0"
let basic_user = "haltsql-ci"
let basic_password = lazy (random_hex 12)
let token_user = "pusher"
let token_password = lazy (random_hex 12)
let minio_user = "haltsqlbundles"
let minio_password = lazy (random_hex 16)
let https_token = lazy (random_hex 16)

let start_anon_registry () =
  ignore
    (start ~name:"reg-anon" ~image:registry_image
       [ "-p"; Printf.sprintf "127.0.0.1:%d:5000" port_anon ]
       []);
  wait_http ~what:"registry (anonymous)"
    (Printf.sprintf "http://127.0.0.1:%d/v2/" port_anon)

let start_basic_registry () =
  let hash = bcrypt ~user:basic_user ~password:(Lazy.force basic_password) in
  write (path "htpasswd/htpasswd") (Printf.sprintf "%s:%s\n" basic_user hash);
  ignore
    (start ~name:"reg-basic" ~image:registry_image
       [
         "-p";
         Printf.sprintf "127.0.0.1:%d:5000" port_basic;
         "-v";
         path "htpasswd" ^ ":/auth:ro";
         "-e";
         "REGISTRY_AUTH=htpasswd";
         "-e";
         "REGISTRY_AUTH_HTPASSWD_REALM=haltsql-test";
         "-e";
         "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd";
       ]
       []);
  wait_http ~what:"registry (htpasswd)"
    (Printf.sprintf "http://127.0.0.1:%d/v2/" port_basic)

let start_token_registry () =
  let d = path "token" in
  mkdir_p d;
  openssl
    [
      "req";
      "-x509";
      "-newkey";
      "rsa:2048";
      "-nodes";
      "-keyout";
      Filename.concat d "token.key";
      "-out";
      Filename.concat d "token.crt";
      "-days";
      "2";
      "-subj";
      "/CN=haltsql-test-token";
    ];
  Unix.chmod (Filename.concat d "token.key") 0o644;
  let hash = bcrypt ~user:token_user ~password:(Lazy.force token_password) in
  write
    (Filename.concat d "auth_config.yml")
    (String.concat "\n"
       [
         "server:";
         "  addr: \":5001\"";
         "token:";
         "  issuer: \"haltsql-test-auth\"";
         "  expiration: 900";
         "  certificate: \"/config/token.crt\"";
         "  key: \"/config/token.key\"";
         "users:";
         Printf.sprintf "  \"%s\":" token_user;
         Printf.sprintf "    password: \"%s\"" hash;
         "  \"\": {}";
         "acl:";
         Printf.sprintf "  - match: {account: \"%s\"}" token_user;
         "    actions: [\"*\"]";
         "  - match: {account: \"\"}";
         "    actions: [\"pull\"]";
         "";
       ]);
  ignore
    (start ~name:"auth" ~image:auth_image
       [
         "-p"; Printf.sprintf "127.0.0.1:%d:5001" port_token_auth; "-v"; d ^ ":/config:ro";
       ]
       [ "/config/auth_config.yml" ]);
  ignore
    (start ~name:"reg-token" ~image:registry_image
       [
         "-p";
         Printf.sprintf "127.0.0.1:%d:5000" port_token_registry;
         "-v";
         d ^ ":/certs:ro";
         "-e";
         "REGISTRY_AUTH=token";
         "-e";
         Printf.sprintf "REGISTRY_AUTH_TOKEN_REALM=http://127.0.0.1:%d/auth"
           port_token_auth;
         "-e";
         "REGISTRY_AUTH_TOKEN_SERVICE=haltsql-test-registry";
         "-e";
         "REGISTRY_AUTH_TOKEN_ISSUER=haltsql-test-auth";
         "-e";
         "REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/certs/token.crt";
       ]
       []);
  wait_http ~what:"docker_auth" (Printf.sprintf "http://127.0.0.1:%d/" port_token_auth);
  wait_http ~what:"registry (token)"
    (Printf.sprintf "http://127.0.0.1:%d/v2/" port_token_registry)

let start_minio () =
  ignore
    (start ~name:"minio" ~image:minio_image
       [
         "-p";
         Printf.sprintf "127.0.0.1:%d:9000" port_minio;
         "-p";
         Printf.sprintf "127.0.0.1:%d:9001" port_minio_console;
         "-e";
         "MINIO_ROOT_USER=" ^ minio_user;
         "-e";
         "MINIO_ROOT_PASSWORD=" ^ Lazy.force minio_password;
       ]
       [ "server"; "/data"; "--console-address"; ":9001" ]);
  wait_until ~what:"minio" (fun () ->
      http_status (Printf.sprintf "http://127.0.0.1:%d/minio/health/live" port_minio)
      = Some 200)

let https_container = prefix ^ "https"
let www_dir () = path "www"
let ca_file () = path "tls/ca.crt"

let start_https () =
  let d = path "tls" in
  mkdir_p d;
  let f n = Filename.concat d n in
  openssl
    [
      "req";
      "-x509";
      "-newkey";
      "rsa:2048";
      "-nodes";
      "-keyout";
      f "ca.key";
      "-out";
      f "ca.crt";
      "-days";
      "2";
      "-subj";
      "/CN=HaltSQL bundles test CA";
      "-addext";
      "basicConstraints=critical,CA:TRUE";
      "-addext";
      "keyUsage=critical,keyCertSign,cRLSign";
    ];
  openssl
    [
      "req";
      "-newkey";
      "rsa:2048";
      "-nodes";
      "-keyout";
      f "server.key";
      "-out";
      f "server.csr";
      "-subj";
      "/CN=localhost";
    ];
  write (f "ext.cnf")
    "subjectAltName=DNS:localhost,IP:127.0.0.1\n\
     basicConstraints=CA:FALSE\n\
     keyUsage=critical,digitalSignature,keyEncipherment\n\
     extendedKeyUsage=serverAuth\n";
  openssl
    [
      "x509";
      "-req";
      "-in";
      f "server.csr";
      "-CA";
      f "ca.crt";
      "-CAkey";
      f "ca.key";
      "-CAcreateserial";
      "-out";
      f "server.crt";
      "-days";
      "2";
      "-extfile";
      f "ext.cnf";
    ];
  Unix.chmod (f "server.key") 0o644;
  write (path "nginx/default.conf")
    (Printf.sprintf
       "server {\n\
       \  listen 443 ssl;\n\
       \  server_name localhost;\n\
       \  ssl_certificate /certs/server.crt;\n\
       \  ssl_certificate_key /certs/server.key;\n\
       \  root /srv;\n\
       \  location /private/ {\n\
       \    if ($http_authorization != \"Bearer %s\") { return 401; }\n\
       \  }\n\
        }\n"
       (Lazy.force https_token));
  mkdir_p (www_dir ());
  mkdir_p (Filename.concat (www_dir ()) "private");
  Unix.chmod (www_dir ()) 0o755;
  Unix.chmod (Filename.concat (www_dir ()) "private") 0o755;
  ignore
    (start ~name:"https" ~image:nginx_image
       [
         "-p";
         Printf.sprintf "127.0.0.1:%d:443" port_https;
         "-v";
         www_dir () ^ ":/srv:ro";
         "-v";
         path "nginx" ^ ":/etc/nginx/conf.d:ro";
         "-v";
         d ^ ":/certs:ro";
       ]
       [])

(* oras in a container that shares the anonymous registry's network namespace, so it
   reaches the registry as [oras_anon_registry]. Going through the host
   (host.docker.internal) does not work on Linux: the registry port is published on
   127.0.0.1 only, which the host gateway address cannot reach. *)
let oras_anon_registry = "localhost:5000"

let oras ~workdir args =
  ensure_image oras_image;
  run "docker"
    ([
       "run";
       "--rm";
       "--network";
       "container:" ^ prefix ^ "reg-anon";
       "-v";
       workdir ^ ":/workspace";
       "-w";
       "/workspace";
       oras_image;
     ]
    @ args)
