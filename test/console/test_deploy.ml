(* Deployment artifacts of the console: the Helm chart, the cloud overlays and
   templates, the local stack, the Terraform example and the release workflow. Every
   console config shipped in deploy/ (or rendered by the chart) must pass the console's
   own validation, and the security and sizing properties of the manifests are pinned
   here.

   The chart cases run `helm template` when helm is on PATH and are skipped otherwise;
   HALTSQL_REQUIRE_HELM=1 (set in CI) turns a missing helm into a failure. *)

module C = Haltsql_console

let deploy = "../../deploy"
let chart = deploy ^ "/helm/haltsql-console"
let read_file path = In_channel.with_open_bin path In_channel.input_all

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let yaml_of_string ?(file = "<string>") s =
  match Haltsql.Docload.of_string ~file Haltsql.Docload.Yaml s with
  | Ok j -> j
  | Error errs ->
      Alcotest.failf "%s: %s" file
        (String.concat "; " (List.map Haltsql.Load_error.to_string errs))

let yaml_file path = yaml_of_string ~file:path (read_file path)

let field k (j : Yojson.Safe.t) =
  match j with `Assoc l -> Option.value (List.assoc_opt k l) ~default:`Null | _ -> `Null

let rec path keys j = match keys with [] -> j | k :: r -> path r (field k j)
let list = function `List l -> l | `Null -> [] | j -> [ j ]
let str = function `String s -> s | j -> Yojson.Safe.to_string j

(* The repository root, for files dune does not copy into _build (.github). *)
let repo_root () =
  let rec up d n =
    if Sys.file_exists (Filename.concat d ".github/workflows/release.yml") then Some d
    else if n = 0 then None
    else up (Filename.dirname d) (n - 1)
  in
  up (Sys.getcwd ()) 8

(* ---- console configs ---- *)

(* Validates a console config document the way [Console_config.load] does, with every
   placeholder resolved to a dummy value, then applies the command-line overrides the
   deployment passes. *)
let validate ?listen ?dev ~what (doc : Yojson.Safe.t) =
  let resolve ~scheme:_ ~reference:_ = Ok "x" in
  let lazy_keys = "secrets" :: C.Console_config.lazy_sections in
  let eager =
    match doc with
    | `Assoc l ->
        `Assoc
          (List.map
             (fun (k, v) ->
               if List.mem k lazy_keys then (k, v)
               else (k, C.Console_config.substitute ~resolve v))
             l)
    | d -> d
  in
  match C.Console_config.of_json ~raw:doc eager with
  | exception C.Console_config.Invalid m -> Alcotest.failf "%s: invalid config: %s" what m
  | cfg -> (
      match C.Console_server.apply_overrides ?listen ?dev cfg with
      | Ok cfg -> cfg
      | Error m -> Alcotest.failf "%s: refused at startup: %s" what m)

let loopback_proxy (cfg : C.Console_config.t) =
  match cfg.auth.proxy with
  | None -> Alcotest.fail "no auth.proxy"
  | Some p ->
      let ip s = Option.get (C.Console_config.parse_ip s) in
      Alcotest.(check bool)
        "127.0.0.1 is trusted" true
        (C.Console_config.ip_in_prefixes (ip "127.0.0.1") p.trusted_proxies);
      Alcotest.(check bool)
        "a pod address is not" false
        (C.Console_config.ip_in_prefixes (ip "10.1.2.3") p.trusted_proxies)

let config_tests =
  [
    ( "ECS config passes validation, proxy trusts loopback only (DEP-01)",
      `Quick,
      fun () ->
        let cfg =
          validate ~listen:"127.0.0.1:8090" ~what:"console.ecs.yaml"
            (yaml_file (deploy ^ "/cloud/aws/console/console.ecs.yaml"))
        in
        loopback_proxy cfg );
    ( "local stack runs without dev mode; the bare-binary dev command starts (DEP-03)",
      `Quick,
      fun () ->
        let cfg =
          validate ~listen:"0.0.0.0:8090" ~what:"console.local.yaml"
            (yaml_file (deploy ^ "/console/console.local.yaml"))
        in
        Alcotest.(check bool) "no dev" true (cfg.auth.dev = None);
        let compose = yaml_file (deploy ^ "/console/docker-compose.yaml") in
        let cmd =
          List.map str (list (path [ "services"; "console"; "command" ] compose))
        in
        Alcotest.(check bool) "compose does not pass --dev" false (List.mem "--dev" cmd);
        (* docs/console/deploy.md: --listen 127.0.0.1:8090 --dev admin on the example. *)
        let cfg =
          validate ~listen:"127.0.0.1:8090" ~dev:C.Rbac.Admin ~what:"console.example.yaml"
            (yaml_file (deploy ^ "/console/console.example.yaml"))
        in
        Alcotest.(check bool) "dev is the only method" true (cfg.auth.tokens = []);
        let doc = read_file "../../docs/console/deploy.md" in
        Alcotest.(check bool)
          "documented dev command listens on loopback" true
          (contains doc "--listen 127.0.0.1:8090 --dev admin") );
  ]

(* ---- overlays, templates and docs ---- *)

let console_overlays =
  [
    deploy ^ "/cloud/aws/console/eks.values.yaml";
    deploy ^ "/cloud/gcp/console/gke.values.yaml";
    deploy ^ "/cloud/azure/console/aks.values.yaml";
  ]

let egress_rule_to rules ~cidr ~port =
  List.exists
    (fun r ->
      List.exists
        (fun t -> str (path [ "ipBlock"; "cidr" ] t) = cidr)
        (list (field "to" r))
      && List.exists (fun p -> field "port" p = `Int port) (list (field "ports" r)))
    rules

let selects_console from =
  List.exists
    (fun f ->
      str (path [ "podSelector"; "matchLabels"; "app.kubernetes.io/name" ] f)
      = "haltsql-console")
    from

let cosign_regexp =
  {|'^https://github.com/HaltSQL/HaltSQL/\.github/workflows/release\.yml@refs/tags/v'|}

let o2p_digest = "sha256:d62e2d81c6f5048f652f67c302083be1272c181b971fad80e5a30ebe2b8b75d8"

(* Every `image:`-like reference in a text file. *)
let image_refs text =
  let re =
    Str.regexp
      {|\(quay\.io\|ghcr\.io\|docker\.io\)?[a-z0-9./_-]*\(oauth2-proxy\|haltsql-console\|curlimages/curl\|postgres\):[A-Za-z0-9._@:-]+|}
  in
  let rec go i acc =
    match Str.search_forward re text i with
    | exception Not_found -> List.rev acc
    | j ->
        go (j + String.length (Str.matched_string text)) (Str.matched_string text :: acc)
  in
  go 0 []

let chart_app_version file =
  let c = yaml_file file in
  (str (field "version" c), str (field "appVersion" c))

let manifest_tests =
  [
    ( "overlays keep automation tokens; Terraform applies them last (DEP-06)",
      `Quick,
      fun () ->
        List.iter
          (fun f ->
            let auth = path [ "console"; "config"; "auth" ] (yaml_file f) in
            if field "tokens" auth <> `Null then
              Alcotest.failf "%s sets console.config.auth.tokens (Helm replaces lists)" f)
          console_overlays;
        let tf = read_file (deploy ^ "/terraform/examples/console-kubernetes/main.tf") in
        let pos sub =
          match Str.search_forward (Str.regexp_string sub) tf 0 with
          | i -> i
          | exception Not_found -> Alcotest.failf "main.tf: %S not found" sub
        in
        Alcotest.(check bool)
          "automation_tokens come after values_files" true
          (pos "tokens = var.automation_tokens" > pos "for f in var.values_files") );
    ( "GKE console egress reaches the metadata server (DEP-04)",
      `Quick,
      fun () ->
        let rules =
          list
            (path
               [ "networkPolicy"; "egress"; "extraRules" ]
               (yaml_file (deploy ^ "/cloud/gcp/console/gke.values.yaml")))
        in
        Alcotest.(check bool)
          "169.254.169.252:988" true
          (egress_rule_to rules ~cidr:"169.254.169.252/32" ~port:988);
        Alcotest.(check bool)
          "169.254.169.254:80" true
          (egress_rule_to rules ~cidr:"169.254.169.254/32" ~port:80) );
    ( "verifier network policies admit the console (DEP-05)",
      `Quick,
      fun () ->
        let gke =
          path
            [ "networkPolicy"; "ingressFrom" ]
            (yaml_file (deploy ^ "/cloud/gcp/gke/values-gke.yaml"))
        in
        Alcotest.(check bool) "values-gke.yaml" true (selects_console (list gke));
        List.iter
          (fun f ->
            let np =
              yaml_of_string ~file:f
                (List.hd (Str.split (Str.regexp "^---$") (read_file f)))
            in
            let from =
              List.concat_map
                (fun r -> list (field "from" r))
                (list (path [ "spec"; "ingress" ] np))
            in
            Alcotest.(check bool) f true (selects_console from))
          [
            deploy ^ "/cloud/aws/eks/networkpolicy-shared.yaml";
            deploy ^ "/cloud/azure/aks/networkpolicy-shared.yaml";
          ] );
    ( "Cloud Run console mounts the verifier's config and bundle at its paths (DEP-10)",
      `Quick,
      fun () ->
        let svc = yaml_file (deploy ^ "/cloud/gcp/console/cloudrun-service.yaml") in
        let verifier = yaml_file (deploy ^ "/cloud/gcp/cloudrun/service-internal.yaml") in
        let containers s = list (path [ "spec"; "template"; "spec"; "containers" ] s) in
        let volumes s = list (path [ "spec"; "template"; "spec"; "volumes" ] s) in
        let console =
          List.find (fun c -> str (field "name" c) = "console") (containers svc)
        in
        let vmounts =
          List.concat_map (fun c -> list (field "volumeMounts" c)) (containers verifier)
        in
        let cmounts = list (field "volumeMounts" console) in
        let source mounts vols path_ =
          match List.find_opt (fun m -> str (field "mountPath" m) = path_) mounts with
          | None -> None
          | Some m ->
              List.find_opt (fun v -> field "name" v = field "name" m) vols
              |> Option.map (fun v ->
                  `Assoc
                    (List.remove_assoc "name" (match v with `Assoc l -> l | _ -> [])))
        in
        (* Every bundle the verifier config loads is under a mount the console shares. *)
        let vcfg =
          yaml_file (deploy ^ "/cloud/gcp/cloudrun/haltsql-internal-config.yaml")
        in
        let bundles =
          List.filter_map
            (fun p -> match field "bundle" p with `String b -> Some b | _ -> None)
            (list (field "policies" vcfg))
        in
        Alcotest.(check bool) "the verifier loads a bundle" true (bundles <> []);
        List.iter
          (fun b ->
            let dir = Filename.dirname b in
            let v = source vmounts (volumes verifier) dir
            and c = source cmounts (volumes svc) dir in
            if v = None || v <> c then
              Alcotest.failf "console does not mount %s like the verifier" dir)
          bundles;
        let cfg_dir = "/etc/haltsql/config" in
        let v = source vmounts (volumes verifier) cfg_dir
        and c = source cmounts (volumes svc) cfg_dir in
        Alcotest.(check bool)
          "config at the verifier's path, same secret" true
          (v <> None && v = c) );
    ( "cosign verification is anchored to release.yml on a tag (DEP-12)",
      `Quick,
      fun () ->
        List.iter
          (fun f ->
            let s = read_file f in
            if
              contains s
                "--certificate-identity-regexp 'https://github.com/HaltSQL/HaltSQL/'"
            then Alcotest.failf "%s: unanchored identity regexp" f;
            if not (contains s cosign_regexp) then
              Alcotest.failf "%s: anchored regexp missing" f)
          [ "../../docs/console/deploy.md"; chart ^ "/values.yaml"; chart ^ "/README.md" ]
    );
    ( "task role reads only the console's own secrets, not oauth2-proxy's (DEP-13)",
      `Quick,
      fun () ->
        let pol = Yojson.Safe.from_file (deploy ^ "/cloud/aws/console/iam-policy.json") in
        let secrets =
          List.concat_map
            (fun st ->
              if str (field "Action" st) = "secretsmanager:GetSecretValue" then
                List.map str (list (field "Resource" st))
              else [])
            (list (field "Statement" pol))
        in
        Alcotest.(check bool) "a secrets statement" true (secrets <> []);
        List.iter
          (fun r -> if contains r "*" then Alcotest.failf "wildcard secret resource %s" r)
          secrets;
        let td = read_file (deploy ^ "/cloud/aws/console/console-task-definition.json") in
        Alcotest.(check bool)
          "oauth2-proxy secrets outside haltsql-console/" false
          (contains td "secret:haltsql-console/oauth2") );
    ( "oauth2-proxy templates restrict sign-in to groups (DEP-14)",
      `Quick,
      fun () ->
        List.iter
          (fun f ->
            let s = read_file f in
            if not (contains s "--allowed-group=" || contains s "--google-group=") then
              Alcotest.failf "%s: oauth2-proxy admits every IdP user" f)
          [
            deploy ^ "/cloud/aws/console/console-task-definition.json";
            deploy ^ "/cloud/azure/console/containerapp.yaml";
            deploy ^ "/cloud/gcp/console/cloudrun-service.yaml";
          ] );
    ( "console image tags follow the release version (DEP-17)",
      `Quick,
      fun () ->
        let version, app = chart_app_version (chart ^ "/Chart.yaml") in
        let _, server_app = chart_app_version (deploy ^ "/helm/haltsql/Chart.yaml") in
        Alcotest.(check string) "console chart version = appVersion" app version;
        Alcotest.(check string) "console and haltsql charts in lockstep" server_app app;
        List.iter
          (fun f ->
            List.iter
              (fun r ->
                match Str.bounded_split (Str.regexp_string "haltsql-console:") r 2 with
                | [ _; tag ] ->
                    let tag = List.hd (String.split_on_char '@' tag) in
                    if tag <> app then Alcotest.failf "%s: %s, release is %s" f r app
                | _ -> ())
              (image_refs (read_file f)))
          [
            chart ^ "/Chart.yaml";
            deploy ^ "/cloud/aws/console/Dockerfile.ecs";
            deploy ^ "/cloud/gcp/console/cloudrun-service.yaml";
            deploy ^ "/cloud/azure/console/containerapp.yaml";
          ] );
    ( "third-party images are pinned by digest (DEP-18)",
      `Quick,
      fun () ->
        let files =
          [
            chart ^ "/Chart.yaml";
            deploy ^ "/console/docker-compose.yaml";
            deploy ^ "/cloud/aws/console/console-task-definition.json";
            deploy ^ "/cloud/gcp/console/cloudrun-service.yaml";
            deploy ^ "/cloud/azure/console/containerapp.yaml";
          ]
          @ Option.to_list
              (Option.map
                 (fun r -> Filename.concat r "scripts/console-docker-smoke.sh")
                 (repo_root ()))
        in
        List.iter
          (fun f ->
            List.iter
              (fun r ->
                if (not (contains r "haltsql-console")) && not (contains r "@sha256:")
                then Alcotest.failf "%s: %s is not pinned by digest" f r)
              (image_refs (read_file f)))
          files;
        let v = yaml_file (chart ^ "/values.yaml") in
        Alcotest.(check string)
          "oauth2Proxy.image.digest default" o2p_digest
          (str (path [ "oauth2Proxy"; "image"; "digest" ] v)) );
    ( "release builds the console after the server image, from its cache (DEP-09)",
      `Quick,
      fun () ->
        match repo_root () with
        | None -> print_endline "SKIP: .github not found from the build directory"
        | Some root ->
            let wf = yaml_file (Filename.concat root ".github/workflows/release.yml") in
            let job = path [ "jobs"; "console-image" ] wf in
            Alcotest.(check bool)
              "needs image" true
              (List.mem "image" (List.map str (list (field "needs" job))));
            let push =
              List.find (fun s -> str (field "id" s) = "build") (list (field "steps" job))
            in
            let cache = str (path [ "with"; "cache-from" ] push) in
            Alcotest.(check bool)
              "reads the image job's cache" true (contains cache "type=gha");
            Alcotest.(check bool)
              "and the native static-<arch> caches" true
              (contains cache "scope=static-amd64" && contains cache "scope=static-arm64")
    );
  ]

(* ---- memory sizing ---- *)

(* Live heap bytes per index entry for a realistic server record (raw SQL logged,
   64-hex chain hashes, two codes). *)
let bytes_per_entry () =
  let n = 20_000 in
  let idx = C.Index.create ~max_records:(n + 1) ~retention_seconds:1e9 () in
  Gc.compact ();
  let before = (Gc.stat ()).live_words in
  let now = Unix.gettimeofday () in
  for i = 0 to n - 1 do
    let h k = Haltsql.sha256_hex (Printf.sprintf "%s-%d" k i) in
    let j =
      Helpers.server_record ~request_id:(Printf.sprintf "req-%08d" i)
        ~ts:(now -. float i)
        ~caller:"token:analytics-agent" ~policy:"saas-analytics"
        ~policy_version:("sha256:" ^ h "pv")
        ~allowed:false
        ~codes:[ "PII_COLUMN"; "MISSING_LIMIT" ]
        ~fingerprint:(String.sub (h "fp") 0 16)
        ~sql:
          (Printf.sprintf
             "SELECT o.id, o.total, c.email FROM app.orders o JOIN app.customers c ON \
              c.id = o.customer_id WHERE o.tenant_id = 'tenant-%d' AND o.created_at > \
              now() - interval '7 days' ORDER BY o.created_at DESC"
             (i mod 50))
        ~prev_hash:(h "prev") ~hash:(h "hash") ()
    in
    match
      C.Index.entry_of_json ~verifier:"haltsql-1"
        ~location:
          (Printf.sprintf "s3://acme-audit/haltsql/audit/2026/11/09/part-%d.jsonl#L%d"
             (i / 500) (i mod 500))
        ~seq:i ~now j
    with
    | Some e -> C.Index.add idx e
    | None -> Alcotest.fail "not an audit record"
  done;
  Gc.compact ();
  let after = (Gc.stat ()).live_words in
  ignore (Sys.opaque_identity idx);
  (after - before) * (Sys.word_size / 8) / n

let parse_quantity q =
  let num suffix mult =
    Option.map
      (fun n -> n * mult)
      (int_of_string_opt (String.sub q 0 (String.length q - String.length suffix)))
  in
  let ends s = String.ends_with ~suffix:s q in
  match () with
  | () when ends "Gi" -> num "Gi" (1 lsl 30)
  | () when ends "Mi" -> num "Mi" (1 lsl 20)
  | () -> int_of_string_opt q

let sizing_tests =
  [
    ( "default audit.max_records fits the memory limit (DEP-08)",
      `Slow,
      fun () ->
        let per = bytes_per_entry () in
        Printf.printf "index: %d bytes per entry\n" per;
        let check what values =
          let max_records =
            match path [ "console"; "config"; "audit"; "max_records" ] values with
            | `Int n -> n
            | _ -> Alcotest.failf "%s: console.config.audit.max_records is not set" what
          in
          let limit =
            match
              parse_quantity (str (path [ "resources"; "limits"; "memory" ] values))
            with
            | Some b -> b
            | None -> Alcotest.failf "%s: resources.limits.memory" what
          in
          (* The full index may use at most half the limit: GC headroom, the rest of
             the console (signals, reports, HTTP buffers) and record size variance. *)
          if max_records * per > limit / 2 then
            Alcotest.failf "%s: %d records x %d B > half of %d B" what max_records per
              limit
        in
        let defaults = yaml_file (chart ^ "/values.yaml") in
        check "values.yaml" defaults;
        List.iter
          (fun f ->
            let o = yaml_file f in
            let merged =
              `Assoc
                [
                  ( "console",
                    `Assoc
                      [
                        ( "config",
                          `Assoc
                            [
                              ( "audit",
                                `Assoc
                                  [
                                    ( "max_records",
                                      match
                                        path
                                          [ "console"; "config"; "audit"; "max_records" ]
                                          o
                                      with
                                      | `Null ->
                                          path
                                            [
                                              "console"; "config"; "audit"; "max_records";
                                            ]
                                            defaults
                                      | v -> v );
                                  ] );
                            ] );
                      ] );
                  ( "resources",
                    `Assoc
                      [
                        ( "limits",
                          `Assoc
                            [
                              ( "memory",
                                match path [ "resources"; "limits"; "memory" ] o with
                                | `Null ->
                                    path [ "resources"; "limits"; "memory" ] defaults
                                | v -> v );
                            ] );
                      ] );
                ]
            in
            check f merged)
          console_overlays );
  ]

(* ---- the chart, rendered ---- *)

let helm_available = lazy (Sys.command "helm version --short > /dev/null 2>&1" = 0)

let require_helm () =
  if Lazy.force helm_available then true
  else if Sys.getenv_opt "HALTSQL_REQUIRE_HELM" = Some "1" then
    Alcotest.fail "helm is not on PATH (HALTSQL_REQUIRE_HELM=1)"
  else (
    print_endline "SKIP: helm is not on PATH";
    false)

(* Runs `helm template t <chart> ARGS`; returns (exit status, stdout, stderr). *)
let helm args =
  let out = Filename.temp_file "helm" ".out" and err = Filename.temp_file "helm" ".err" in
  let cmd =
    Filename.quote_command "helm" ~stdout:out ~stderr:err
      ([ "template"; "t"; chart; "--namespace"; "haltsql" ] @ args)
  in
  let code = Sys.command cmd in
  let o = read_file out and e = read_file err in
  Sys.remove out;
  Sys.remove err;
  (code, o, e)

let docs text =
  Str.split (Str.regexp "^---$") text
  |> List.filter (fun d -> String.trim d <> "" && contains d "kind:")
  |> List.map yaml_of_string

let render args =
  match helm args with
  | 0, o, _ -> docs o
  | c, _, e ->
      Alcotest.failf "helm template %s exited %d: %s" (String.concat " " args) c e

let render_fails ~msg args =
  match helm args with
  | 0, _, _ -> Alcotest.failf "helm template %s should fail" (String.concat " " args)
  | _, _, e -> if not (contains e msg) then Alcotest.failf "expected %S in: %s" msg e

let kind k ds = List.filter (fun d -> str (field "kind" d) = k) ds

let one k ds =
  match kind k ds with
  | [ d ] -> d
  | l -> Alcotest.failf "%d %s documents" (List.length l) k

let pod_spec ds = path [ "spec"; "template"; "spec" ] (one "Deployment" ds)

let container name ds =
  List.find
    (fun c -> str (field "name" c) = name)
    (list (field "containers" (pod_spec ds)))

(* Validates the rendered console.yaml with the --listen the Deployment passes. *)
let validate_rendered ~what ds =
  let cm = one "ConfigMap" ds in
  let doc = yaml_of_string ~file:what (str (path [ "data"; "console.yaml" ] cm)) in
  let args = List.map str (list (field "args" (container "console" ds))) in
  let rec listen = function
    | "--listen" :: l :: _ -> Some l
    | _ :: r -> listen r
    | [] -> None
  in
  validate ?listen:(listen args) ~what doc

let sidecar =
  [
    "--set";
    "oauth2Proxy.enabled=true";
    "--set";
    "oauth2Proxy.existingSecret=o2p";
    "--set";
    "oauth2Proxy.oidcIssuerUrl=https://idp.example";
  ]

let tokens_file () =
  let f = Filename.temp_file "tokens" ".yaml" in
  Out_channel.with_open_bin f (fun oc ->
      output_string oc
        "console:\n\
        \  config:\n\
        \    auth:\n\
        \      tokens:\n\
        \        - { name: ci, sha256: \
         91c16f0d6cc1bec3c3603972182a07c66ff4fa71618a975e963d6dbe42b6dd37, role: audit }\n");
  f

let helm_case name f = (name, `Quick, fun () -> if require_helm () then f ())

let chart_tests =
  [
    helm_case "chart configs pass the console's validation (DEP-01, DEP-06)" (fun () ->
        let cfg = validate_rendered ~what:"sidecar" (render sidecar) in
        loopback_proxy cfg;
        let tokens = tokens_file () in
        List.iter
          (fun f ->
            (* An earlier values file's tokens survive the overlay. *)
            let cfg = validate_rendered ~what:f (render [ "-f"; tokens; "-f"; f ]) in
            loopback_proxy cfg;
            Alcotest.(check int) (f ^ ": tokens kept") 1 (List.length cfg.auth.tokens))
          console_overlays;
        Sys.remove tokens);
    helm_case "dev mode cannot be rendered (DEP-02)" (fun () ->
        render_fails ~msg:"console.devRole is not supported"
          [ "--set"; "console.devRole=admin" ];
        render_fails ~msg:"console.devRole is not supported"
          (sidecar @ [ "--set"; "console.devRole=admin" ]);
        List.iter
          (fun a ->
            render_fails ~msg:"extraArgs must not enable dev mode"
              [ "--set-string"; "extraArgs[0]=" ^ a ])
          [ "--dev"; "--dev=admin"; "--de"; "--d=admin" ];
        ignore (render [ "--set-string"; "extraArgs[0]=--debug-nothing" ]));
    helm_case "the token is projected into the console container only (DEP-07)" (fun () ->
        let ds =
          render
            (sidecar
            @ [ "--set"; "rbac.create=true"; "--set"; "rbac.deployments[0]=haltsql" ])
        in
        let spec = pod_spec ds in
        Alcotest.(check bool)
          "no pod-level automount" true
          (field "automountServiceAccountToken" spec = `Bool false);
        let mounts c =
          List.map
            (fun m -> str (field "mountPath" m))
            (list (field "volumeMounts" (container c ds)))
        in
        let sa = "/var/run/secrets/kubernetes.io/serviceaccount" in
        Alcotest.(check bool)
          "console mounts the token" true
          (List.mem sa (mounts "console"));
        Alcotest.(check bool)
          "oauth2-proxy does not" false
          (List.mem sa (mounts "oauth2-proxy"));
        let vol =
          List.find
            (fun v -> str (field "name" v) = "kube-api-access")
            (list (field "volumes" spec))
        in
        let srcs = list (path [ "projected"; "sources" ] vol) in
        Alcotest.(check bool)
          "bound token" true
          (List.exists (fun s -> field "serviceAccountToken" s <> `Null) srcs);
        let ds = render [] in
        Alcotest.(check bool)
          "no token without rbac" false
          (List.exists
             (fun v -> str (field "name" v) = "kube-api-access")
             (list (field "volumes" (pod_spec ds))));
        let rbac = read_file (chart ^ "/templates/rbac.yaml") in
        Alcotest.(check bool)
          "no 'Restarts only' claim" false
          (contains rbac "Restarts only"));
    helm_case
      "pod annotations: no secret hash, no config hash for an external ConfigMap \
       (DEP-15, DEP-16)" (fun () ->
        let ann ds =
          path [ "spec"; "template"; "metadata"; "annotations" ] (one "Deployment" ds)
        in
        let ds = render [ "--set"; "secretEnv.HALTSQL_ADMIN_TOKEN=ci" ] in
        Alcotest.(check bool)
          "checksum/config" true
          (field "checksum/config" (ann ds) <> `Null);
        Alcotest.(check bool)
          "no checksum/secret-env" true
          (field "checksum/secret-env" (ann ds) = `Null);
        let ds = render [ "--set"; "console.existingConfigMap=mine" ] in
        Alcotest.(check bool)
          "no checksum/config with existingConfigMap" true
          (field "checksum/config" (ann ds) = `Null));
    helm_case
      "auth.proxy without the sidecar needs trust and a narrowed NetworkPolicy (DEP-11)"
      (fun () ->
        let proxy = [ "--set"; "console.config.auth.proxy.user_header=X-Email" ] in
        render_fails ~msg:"needs trusted_proxies" proxy;
        let trusted =
          proxy @ [ "--set"; "console.config.auth.proxy.trusted_proxies[0]=10.0.0.0/8" ]
        in
        render_fails ~msg:"set networkPolicy.ingressFrom" trusted;
        let narrowed =
          trusted
          @ [
              "--set";
              "networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.name=ingress";
            ]
        in
        let cfg = validate_rendered ~what:"external proxy" (render narrowed) in
        Alcotest.(check bool) "proxy kept" true (cfg.auth.proxy <> None));
  ]

let () =
  Alcotest.run "console-deploy"
    [
      ("configs", config_tests);
      ("manifests", manifest_tests);
      ("sizing", sizing_tests);
      ("chart", chart_tests);
    ]
