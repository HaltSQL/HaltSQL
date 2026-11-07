(* Hand-written JSON Schemas (draft 2020-12). Every property carries a
   description so editors can show inline help. Keep in sync with the
   decoders in Policy_impl, Config, Catalog_impl and Test_suite; the files in
   schemas/ are regenerated with
   [dune exec --build-dir _build_load test/load/gen_schemas.exe -- schemas/]. *)

type json = Yojson.Safe.t

let base_url = "https://haltsql.dev/schemas/v1/"
let with_desc d fields : json = `Assoc (("description", `String d) :: fields)
let str ?(extra = []) d = with_desc d ([ ("type", `String "string") ] @ extra)
let pattern_str d pat = str d ~extra:[ ("pattern", `String pat) ]
let enum d values = with_desc d [ ("enum", `List (List.map (fun v -> `String v) values)) ]
let const d v = with_desc d [ ("const", `String v) ]

let bool ?default d =
  with_desc d
    (("type", `String "boolean")
    :: (match default with Some b -> [ ("default", `Bool b) ] | None -> []))

let int ?min ?max ?default d =
  with_desc d
    ([ ("type", `String "integer") ]
    @ (match min with Some m -> [ ("minimum", `Int m) ] | None -> [])
    @ (match max with Some m -> [ ("maximum", `Int m) ] | None -> [])
    @ match default with Some m -> [ ("default", `Int m) ] | None -> [])

let arr ?(min_items = 0) ?(unique = false) d items =
  with_desc d
    ([ ("type", `String "array"); ("items", items) ]
    @ (if min_items > 0 then [ ("minItems", `Int min_items) ] else [])
    @ if unique then [ ("uniqueItems", `Bool true) ] else [])

let obj ?(required = []) ?(additional : json = `Bool false) d props =
  with_desc d
    ([
       ("type", `String "object");
       ("properties", `Assoc props);
       ("additionalProperties", additional);
     ]
    @
    if required = [] then []
    else [ ("required", `List (List.map (fun r -> `String r) required)) ])

let map_of d value =
  with_desc d [ ("type", `String "object"); ("additionalProperties", value) ]

let one_of d alts = with_desc d [ ("oneOf", `List alts) ]
let free_obj d = with_desc d [ ("type", `String "object") ]

let doc ~id ~title d ~required props : json =
  `Assoc
    [
      ("$schema", `String "https://json-schema.org/draft/2020-12/schema");
      ("$id", `String (base_url ^ id));
      ("title", `String title);
      ("description", `String d);
      ("type", `String "object");
      ("properties", `Assoc props);
      ("additionalProperties", `Bool false);
      ("required", `List (List.map (fun r -> `String r) required));
    ]

let api_version =
  const "Document format version. Must be \"haltsql.dev/v1\"." "haltsql.dev/v1"

let kind k = const (Printf.sprintf "Document kind. Must be %S." k) k

(* ---------------------------------------------------------------------- *)

let column_list d =
  one_of d
    [
      const "All columns of the table (needs a catalog snapshot to expand SELECT *)." "*";
      arr ~min_items:1 ~unique:true
        "Explicit column names. Unquoted names are lower-cased; use double quotes to \
         keep case."
        (str "Column name.");
    ]

let catalog_tables =
  map_of
    "Tables keyed by \"schema.table\", written exactly as Postgres stores them (no case \
     folding)."
    (obj ~required:[ "columns" ] "One table of the snapshot."
       [
         ( "columns",
           arr ~min_items:1 "Complete column list of the table, in table order."
             (one_of "A column name, or a name with its type."
                [
                  str "Column name.";
                  obj ~required:[ "name" ] "Column with optional type."
                    [
                      ("name", str "Column name.");
                      ("type", str "Postgres type name, e.g. int8, text, uuid.");
                    ];
                ]) );
       ])

let catalog_props ~with_header =
  (if with_header then
     [
       ("apiVersion", api_version);
       ("kind", kind "Catalog");
       ( "metadata",
         free_obj "Free-form information about the snapshot (source, time, tool version)."
       );
     ]
   else [])
  @ [ ("tables", catalog_tables) ]

let catalog =
  doc ~id:"catalog.schema.json" ~title:"HaltSQL catalog snapshot"
    "Schema snapshot used for name resolution and * expansion, e.g. produced by `haltsql \
     schema pull`."
    ~required:[ "tables" ]
    (catalog_props ~with_header:true)

let ctx_placeholder =
  pattern_str
    "Context placeholder: \"${ctx.<field>}\", filled from the request context at verify \
     time."
    "^\\$\\{ctx\\.[A-Za-z_][A-Za-z0-9_]*\\}$"

let table_entry =
  obj ~required:[ "columns" ] "Access rules for one table."
    [
      ("columns", column_list "Readable columns: \"*\" or a list of names.");
      ( "tenant_column",
        str
          "Column that holds the tenant id. Shorthand for tenant_columns when tenancy \
           defines exactly one key." );
      ( "tenant_columns",
        map_of
          "Tenant-scoping columns mapped to tenancy key names, e.g. {org_id: org, \
           workspace_id: workspace}."
          (str "Tenancy key name (from tenancy.keys).") );
      ( "writes",
        obj
          "Writes allowed on this table (also require the statement kind in \
           statements.allow)."
          [
            ( "insert",
              bool ~default:false
                "Allow INSERT (tenant columns must be set to the tenant value)." );
            ( "update",
              one_of "Allow UPDATE: \"*\", a list of updatable columns, or false."
                [
                  const "All columns except tenant columns." "*";
                  arr ~min_items:1 "Updatable columns (never tenant columns)."
                    (str "Column name.");
                  with_desc "UPDATE not allowed." [ ("const", `Bool false) ];
                ] );
            ("delete", bool ~default:false "Allow DELETE (needs the tenant predicate).");
          ] );
    ]

let policy_props () =
  [ ("apiVersion", api_version); ("kind", kind "Policy") ]
  @ [
      ( "metadata",
        obj ~required:[ "name" ] "Identification of the policy."
          [
            ( "name",
              pattern_str
                "Policy name, referenced by Config tokens. Letters, digits, '.', '_', \
                 '-'."
                "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" );
            ("owner", str "Owning team or person.");
            ("description", str "What the policy is for.");
          ] );
      ( "dialect",
        with_desc "SQL dialect: \"postgres\" or a version such as \"postgres-17\"."
          [
            ("type", `String "string");
            ("pattern", `String "^postgres(-[0-9]{2})?$");
            ("default", `String "postgres");
          ] );
      ( "search_path",
        arr ~min_items:1 ~unique:true
          "Schemas used to resolve unqualified table names, in order. The first entry \
           also qualifies unqualified table keys. Default [public]."
          (str "Schema name.") );
      ( "catalog",
        one_of
          "Optional catalog snapshot: a path (relative to the policy file) or an inline \
           snapshot."
          [
            str "Path to a snapshot file (YAML or JSON).";
            obj ~required:[ "tables" ] "Inline snapshot."
              (catalog_props ~with_header:true);
          ] );
      ( "limits",
        obj "Size limits enforced before analysis."
          [
            ( "max_bytes",
              int ~min:1
                ~max:(16 * 1024 * 1024)
                ~default:16384 "Maximum SQL length in bytes." );
            ( "max_depth",
              int ~min:1 ~max:1000 ~default:64 "Maximum parse-tree nesting depth." );
            ( "max_nodes",
              int ~min:1 ~max:10_000_000 ~default:20000 "Maximum parse-tree node count."
            );
            ( "max_joins",
              int ~min:0 ~max:256 ~default:8 "Maximum number of joins per statement." );
          ] );
      ( "statements",
        obj ~required:[ "allow" ] "Statement kinds that may run."
          [
            ( "allow",
              arr ~min_items:1 ~unique:true "Allowed statement kinds. Default [select]."
                (enum "Statement kind." [ "select"; "insert"; "update"; "delete" ]) );
          ] );
      ( "require_limit",
        obj ~required:[ "max" ]
          "Require every SELECT to have a constant LIMIT no larger than max."
          [ ("max", int ~min:1 ~max:100_000_000 "Largest allowed LIMIT.") ] );
      ( "tenancy",
        obj "Tenant isolation settings."
          [
            ( "mode",
              with_desc
                "bound: tenant predicates compare to a $n parameter that HaltSQL binds \
                 (recommended). literal: they compare to a literal equal to the context \
                 value."
                [
                  ("enum", `List [ `String "bound"; `String "literal" ]);
                  ("default", `String "bound");
                ] );
            ( "keys",
              map_of
                "Tenancy keys mapped to context placeholders, e.g. {tenant: \
                 \"${ctx.tenant_id}\"}."
                ctx_placeholder );
            ( "value",
              with_desc "Shorthand for keys: {tenant: <value>}."
                [ ("$ref", `String "#/$defs/ctx_placeholder") ] );
          ] );
      ( "tables",
        map_of
          "Allowed tables keyed by \"table\" or \"schema.table\". Quote names that need \
           case: '\"MixedCase\".\"Orders\"'."
          table_entry );
      ( "functions",
        obj "Allowed functions (everything else is denied)."
          [
            ( "allow",
              arr "Function names, lower-case, optionally schema-qualified."
                (str "Function name.") );
            ( "presets",
              arr ~unique:true "Built-in curated presets."
                (enum "Preset name." (List.map fst Policy_impl.function_presets)) );
          ] );
      ( "operators",
        obj
          "Allowed operators. Default: comparison, arithmetic, ||, LIKE/regex, JSON and \
           array operators."
          [
            ("allow", arr "Replaces the default operator list." (str "Operator symbol."));
            ( "extend",
              arr "Adds operators to the defaults (or to allow)." (str "Operator symbol.")
            );
          ] );
      ( "deny_casts",
        one_of "Denied cast target types. Default: the reg* family and txid_snapshot."
          [
            arr "Replaces the default list." (str "Type name.");
            obj "Extends the default list."
              [ ("extend", arr "Types added to the defaults." (str "Type name.")) ];
          ] );
      ( "allow_explain",
        bool ~default:false "Allow plain EXPLAIN (never ANALYZE) of an allowed statement."
      );
      ( "mode",
        with_desc
          "enforce: deny violations. shadow: report violations but allow (for rollouts)."
          [
            ("enum", `List [ `String "enforce"; `String "shadow" ]);
            ("default", `String "enforce");
          ] );
    ]

let add_defs (j : json) defs : json =
  match j with `Assoc kvs -> `Assoc (kvs @ [ ("$defs", `Assoc defs) ]) | j -> j

let policy =
  add_defs
    (doc ~id:"policy.schema.json" ~title:"HaltSQL policy"
       "What SQL an LLM agent may run: tables, columns, functions, tenancy and limits \
        (PLAN.md §6.5)."
       ~required:[ "apiVersion"; "kind"; "metadata" ]
       (policy_props ()))
    [ ("ctx_placeholder", ctx_placeholder) ]

let inline_policy =
  obj ~required:[ "metadata" ] "An inline Policy document (apiVersion and kind optional)."
    (policy_props ())

let config =
  add_defs
    (doc ~id:"config.schema.json" ~title:"HaltSQL runtime configuration"
       "How HaltSQL runs: listen address, TLS, auth tokens, policies, audit, logging. \
        String values may use ${env:NAME} and ${file:/path} placeholders."
       ~required:[ "apiVersion"; "kind" ]
       [
         ("apiVersion", api_version);
         ("kind", kind "Config");
         ( "server",
           obj "HTTP sidecar settings."
             [
               ( "listen",
                 str "Address as host:port. Default 127.0.0.1:8080. Env: HALTSQL_LISTEN."
               );
               ( "tls",
                 obj "TLS certificate and key (both or neither)."
                   [
                     ("cert", str "Path to the PEM certificate.");
                     ( "key",
                       str "Path to (or ${file:...} contents of) the PEM private key." );
                   ] );
               ( "auth",
                 obj "Bearer-token authentication."
                   [
                     ( "tokens",
                       arr "Accepted tokens; each is pinned to one policy."
                         (obj
                            ~required:[ "name"; "token_sha256"; "policy" ]
                            "One API token."
                            [
                              ("name", str "Token name (shown in audit logs).");
                              ( "token_sha256",
                                str "Lower-case hex SHA-256 of the token (64 characters)."
                              );
                              ("policy", str "Name of the policy this token may use.");
                            ]) );
                     ( "allow_unauthenticated",
                       bool ~default:false
                         "Accept requests without a token (uses default_policy). Local \
                          development only. Env: HALTSQL_ALLOW_UNAUTHENTICATED." );
                   ] );
             ] );
         ( "policies",
           arr "Policies to load, from files or inline."
             (one_of "A policy file or an inline policy."
                [
                  obj ~required:[ "path" ] "Policy file."
                    [
                      ( "path",
                        str
                          "Path to a policy file (YAML or JSON), relative to this config."
                      );
                    ];
                  obj ~required:[ "inline" ] "Inline policy."
                    [ ("inline", inline_policy) ];
                ]) );
         ( "default_policy",
           str "Policy used by unauthenticated requests. Env: HALTSQL_DEFAULT_POLICY." );
         ( "reload",
           obj "Hot reload."
             [ ("watch", bool ~default:false "Reload policy files when they change.") ] );
         ( "audit",
           obj "Audit log."
             [
               ( "sinks",
                 arr "Where audit records go. Default [{type: stdout}]."
                   (one_of "Audit sink."
                      [
                        obj ~required:[ "type" ] "Standard output."
                          [ ("type", const "Sink type." "stdout") ];
                        obj ~required:[ "type"; "path" ] "JSON-lines file."
                          [
                            ("type", const "Sink type." "file");
                            ("path", str "File path, relative to this config.");
                          ];
                      ]) );
               ( "log_raw_sql",
                 bool ~default:false "Include the raw SQL text in audit records." );
             ] );
         ( "telemetry",
           obj "Metrics and tracing."
             [
               ( "metrics",
                 obj "Metrics."
                   [ ("prometheus", bool ~default:true "Expose Prometheus metrics.") ] );
               ( "otlp_endpoint",
                 str "OTLP endpoint (accepted; reserved for a future release)." );
             ] );
         ( "logging",
           obj "Process logs."
             [
               ( "level",
                 enum "Log level. Env: HALTSQL_LOG_LEVEL."
                   [ "debug"; "info"; "warn"; "error" ] );
               ("format", enum "Log format. Env: HALTSQL_LOG_FORMAT." [ "json"; "text" ]);
             ] );
         ( "limits",
           obj "Request limits."
             [
               ( "max_request_bytes",
                 int ~min:1024
                   ~max:(64 * 1024 * 1024)
                   ~default:1_048_576 "Maximum HTTP request body size." );
             ] );
       ])
    [ ("ctx_placeholder", ctx_placeholder) ]

let scenario =
  doc ~id:"scenario.schema.json" ~title:"HaltSQL lab scenario"
    "Declarative enterprise test environment for haltlab (PLAN.md §8.2)."
    ~required:[ "apiVersion"; "kind"; "metadata" ]
    [
      ("apiVersion", api_version);
      ("kind", kind "Scenario");
      ( "metadata",
        obj ~required:[ "name" ] ~additional:(`Bool true)
          "Identification of the scenario."
          [
            ("name", str "Scenario name.");
            ("description", str "What the scenario exercises.");
          ] );
      ( "environment",
        obj ~additional:(`Bool true) "Infrastructure to emulate."
          [
            ( "postgres",
              arr "Postgres server versions; the scenario runs once per version."
                (with_desc "Major version, e.g. 17."
                   [ ("type", `String "integer"); ("minimum", `Int 13) ]) );
            ( "topology",
              enum "Deployment shape."
                [
                  "embedded";
                  "sidecar";
                  "k8s-sidecar";
                  "service";
                  "proxy";
                  "proxy-behind-pgbouncer";
                ] );
            ( "pooler",
              free_obj "Connection pooler settings, e.g. {pgbouncer: transaction}." );
            ("tls", free_obj "TLS settings, e.g. {internal_ca: true, rotate_every: 10m}.");
            ( "identity",
              free_obj "Identity settings, e.g. {oidc: keycloak, client_certs: true}." );
            ("faults", arr "Faults to inject during the run." (str "Fault name."));
          ] );
      ( "schema",
        one_of "Database schema: a SQL file or a generator."
          [
            str "Path to a SQL schema file.";
            obj ~additional:(`Bool true) "Generated schema."
              [
                ("generate", free_obj "Generator settings, e.g. {tables: 400, seed: 7}.");
              ];
          ] );
      ( "data",
        obj ~additional:(`Bool true) "Data generator settings."
          [
            ("scale", with_desc "Scale factor." [ ("type", `String "number") ]);
            ("tenants", int ~min:1 "Number of tenants.");
            ("skew", str "Tenant size distribution, e.g. zipf(1.2).");
            ("seed", int "Random seed (runs are deterministic).");
          ] );
      ("policies", arr "Policy files used by the scenario." (str "Path to a policy file."));
      ( "workloads",
        arr "Traffic to run."
          (with_desc
             "One workload, e.g. {benign: {source: nl2sql-corpus, queries: 50000}}."
             [
               ("type", `String "object");
               ("minProperties", `Int 1);
               ("maxProperties", `Int 1);
             ]) );
      ( "expect",
        obj ~additional:(`Bool true) "Pass/fail thresholds."
          [
            ("escapes", int ~min:0 "Allowed isolation escapes (should be 0).");
            ("side_effects", int ~min:0 "Allowed side effects (should be 0).");
            ("false_positive_rate", free_obj "e.g. {max: 0.02}.");
            ( "latency_p99_ms",
              free_obj "p99 latency budgets per topology, e.g. {sidecar: 3}." );
          ] );
    ]

let all =
  [
    ("policy.schema.json", policy);
    ("config.schema.json", config);
    ("catalog.schema.json", catalog);
    ("scenario.schema.json", scenario);
  ]
