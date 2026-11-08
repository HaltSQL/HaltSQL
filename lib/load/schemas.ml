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

let policy_ref d = str d

let ctx_fields d =
  arr ~unique:true d (pattern_str "Context field name." "^[A-Za-z_][A-Za-z0-9_]*$")

let batch_schema =
  obj "Batching of audit records into objects."
    [
      ("max_records", int ~min:1 ~max:100_000 ~default:500 "Records per object at most.");
      ( "max_seconds",
        int ~min:1 ~max:3600 ~default:10 "Seconds before a partial batch is flushed." );
    ]

let on_error_schema =
  with_desc
    "What to do when the sink cannot be written: fail_closed refuses requests (HTTP \
     503); buffer keeps records in memory and retries."
    [
      ("enum", `List [ `String "fail_closed"; `String "buffer" ]);
      ("default", `String "fail_closed");
    ]

let prefix_schema =
  str
    ~extra:[ ("default", `String "haltsql/audit/") ]
    "Object key prefix (no leading '/')."

let tls_schema =
  obj "TLS for the HTTP server. cert and key are required together."
    [
      ("cert", str "Path to the PEM certificate chain (or inline PEM).");
      ("key", str "Path to (or ${file:...} contents of) the PEM private key.");
      ("client_ca", str "PEM CA bundle used to verify client certificates (mTLS).");
      ( "client_auth",
        with_desc
          "Whether to request client certificates. optional/required need client_ca."
          [
            ("enum", `List [ `String "none"; `String "optional"; `String "required" ]);
            ("default", `String "none");
          ] );
      ( "min_version",
        with_desc "Minimum TLS version."
          [
            ("enum", `List [ `String "1.2"; `String "1.3"; `Float 1.2; `Float 1.3 ]);
            ("default", `String "1.2");
          ] );
    ]

let groups_schema =
  obj ~required:[ "map" ]
    "Select the policy from the token's groups: the first map entry whose group the \
     token has wins, else default. Use instead of policy / policy_claim."
    [
      ( "claim",
        str
          ~extra:[ ("default", `String "groups") ]
          "Claim holding the groups (a string or an array of strings; exact name, then \
           dot path)." );
      ( "map",
        arr ~min_items:1 "Ordered group -> policy rules."
          (obj ~required:[ "group"; "policy" ] "One rule."
             [
               ("group", str "Group name (exact match)."); ("policy", str "Policy name.");
             ]) );
      ("default", str "Policy when no group matches. Default: reject the token.");
    ]

let oidc_schema =
  obj
    ~required:[ "name"; "issuer"; "audiences" ]
    "An OpenID Connect provider whose JWTs are accepted as bearer tokens."
    [
      ("name", str "Unique provider name (shown in audit logs).");
      ("issuer", str "Issuer URL (https; http only with allow_insecure_http).");
      ( "audiences",
        arr ~min_items:1 ~unique:true "Accepted aud values (at least one)."
          (str "Audience.") );
      ( "jwks_uri",
        str "JWKS URL. Default: discovered from issuer/.well-known/openid-configuration."
      );
      ( "algorithms",
        arr ~min_items:1
          "Accepted signature algorithms. Default [RS256, ES256]. none and HS* are \
           rejected."
          (enum "Algorithm."
             [ "RS256"; "RS384"; "RS512"; "PS256"; "ES256"; "ES384"; "EdDSA" ]) );
      ( "leeway_seconds",
        int ~min:0 ~max:300 ~default:60 "Clock skew tolerance for exp/nbf/iat." );
      ( "jwks_cache_seconds",
        int ~min:10 ~max:86400 ~default:300 "How long fetched keys are cached." );
      ("policy", policy_ref "Pinned policy name (use this or policy_claim).");
      ("policy_claim", str "Claim whose value names the policy (needs allowed_policies).");
      ( "allowed_policies",
        arr ~min_items:1 ~unique:true "Policies policy_claim may select."
          (str "Policy name.") );
      ("policy_from_groups", groups_schema);
      ( "context_claims",
        map_of
          "Context field -> claim path (exact claim name first, then a dot path like \
           org.id)."
          (str "Claim path.") );
      ( "required_claims",
        map_of
          "Claims that must match: a string (equal, or contained in an array / \
           space-separated value) or a list (all contained)."
          (one_of "Expected value(s)."
             [
               str "Required value.";
               arr ~min_items:1 "All required values." (str "Value.");
             ]) );
      ( "request_context_fields",
        ctx_fields "Context fields the request body may still supply. Default []." );
      ( "allow_insecure_http",
        bool ~default:false "Allow http issuer/jwks URLs. Tests only." );
    ]

let mtls_schema =
  obj
    "Client-certificate identities. Requires server.tls.client_ca and client_auth \
     optional/required."
    [
      ( "identities",
        arr "Accepted client identities."
          (obj ~required:[ "policy" ] "One identity: spiffe_id or subject_cn."
             [
               ( "spiffe_id",
                 str "Exact SPIFFE ID URI SAN, e.g. spiffe://corp.example/ns/a/sa/b." );
               ("subject_cn", str "Exact certificate subject common name.");
               ("policy", policy_ref "Policy this identity is pinned to.");
               ( "context",
                 map_of "Static context values for this identity."
                   (one_of "Context value."
                      [
                        str "A value.";
                        int "A value.";
                        arr ~min_items:1 "A set of values." (str "A value.");
                      ]) );
               ( "request_context_fields",
                 ctx_fields "Context fields the request body may still supply." );
             ]) );
    ]

let s3_sink =
  obj
    ~required:[ "type"; "bucket"; "region" ]
    "Amazon S3 (or S3-compatible) object storage."
    [
      ("type", const "Sink type." "s3");
      ("bucket", str "Bucket name.");
      ("prefix", prefix_schema);
      ("region", str "AWS region, e.g. us-east-1.");
      ("endpoint", str "Custom endpoint URL (MinIO, tests).");
      ( "object_lock",
        obj ~required:[ "mode"; "retain_days" ]
          "S3 Object Lock retention for written objects."
          [
            ("mode", enum "Retention mode." [ "GOVERNANCE"; "COMPLIANCE" ]);
            ("retain_days", int ~min:1 ~max:36500 "Retention period in days.");
          ] );
      ("batch", batch_schema);
      ( "credentials",
        obj "Where AWS credentials come from."
          [
            ( "source",
              with_desc "Credential source."
                [
                  ( "enum",
                    `List
                      [
                        `String "env";
                        `String "static";
                        `String "web_identity";
                        `String "instance";
                      ] );
                  ("default", `String "env");
                ] );
            ("access_key_id", str "Access key id (static only; use a secret placeholder).");
            ( "secret_access_key",
              str "Secret access key (static only; use a secret placeholder)." );
            ("session_token", str "Session token (static only, optional).");
          ] );
      ( "spool_dir",
        str
          "Local directory (relative to the config file) where records are spooled \
           before upload and the hash-chain head is persisted, so the chain and object \
           sequence continue across restarts. One directory per sink." );
      ("on_error", on_error_schema);
    ]

let gcs_sink =
  obj ~required:[ "type"; "bucket" ] "Google Cloud Storage."
    [
      ("type", const "Sink type." "gcs");
      ("bucket", str "Bucket name.");
      ("prefix", prefix_schema);
      ("batch", batch_schema);
      ( "credentials",
        obj "Where Google credentials come from."
          [
            ( "source",
              with_desc "Credential source."
                [
                  ("enum", `List [ `String "metadata"; `String "service_account_file" ]);
                  ("default", `String "metadata");
                ] );
            ("file", str "Service account JSON key file (service_account_file only).");
          ] );
      ( "spool_dir",
        str "Local spool directory, as for s3 sinks (relative to the config file)." );
      ("on_error", on_error_schema);
    ]

let otlp_schema =
  obj ~required:[ "endpoint" ] "OpenTelemetry (OTLP/HTTP) export."
    [
      ("endpoint", str "Collector URL, e.g. http://collector:4318.");
      ( "headers",
        map_of
          "Extra HTTP headers (values may use secret placeholders; redacted in config \
           show)."
          (str "Header value.") );
      ( "service_name",
        str ~extra:[ ("default", `String "haltsql") ] "service.name resource attribute."
      );
      ("traces", bool ~default:true "Export traces.");
      ("metrics", bool ~default:true "Export metrics.");
      ( "export_interval_seconds",
        int ~min:1 ~max:3600 ~default:15 "Metric export interval." );
      ("timeout_seconds", int ~min:1 ~max:300 ~default:5 "Export request timeout.");
    ]

let secrets_schema =
  obj
    "Secret providers for ${vault:...}, ${aws-sm:...} and ${gcp-sm:...} placeholders. \
     Values here may only use ${env:...} and ${file:...}."
    [
      ( "vault",
        obj ~required:[ "address"; "auth" ] "HashiCorp Vault."
          [
            ("address", str "Vault URL (https; http only for loopback).");
            ("namespace", str "Vault Enterprise namespace.");
            ( "auth",
              obj ~required:[ "method" ] "How HaltSQL logs in to Vault."
                [
                  ("method", enum "Auth method." [ "token"; "kubernetes"; "approle" ]);
                  ("token", str "Vault token (method token).");
                  ("role", str "Vault role (method kubernetes).");
                  ("role_id", str "AppRole role id (method approle).");
                  ("secret_id", str "AppRole secret id (method approle).");
                  ( "jwt_path",
                    str
                      ~extra:
                        [
                          ( "default",
                            `String "/var/run/secrets/kubernetes.io/serviceaccount/token"
                          );
                        ]
                      "Service account token file (method kubernetes)." );
                  ("mount", str "Auth mount path. Default kubernetes or approle.");
                ] );
            ("ca_file", str "CA bundle for the Vault server certificate.");
          ] );
      ( "aws",
        obj ~required:[ "region" ] "AWS Secrets Manager."
          [
            ("region", str "AWS region."); ("endpoint", str "Custom endpoint URL (tests).");
          ] );
      ( "gcp",
        obj "Google Secret Manager."
          [
            ("project", str "Default project for short secret names.");
            ("endpoint", str "Custom endpoint URL (tests).");
          ] );
    ]

let stream_batch_schema =
  obj "Batching of audit records into one request."
    [
      ("max_records", int ~min:1 ~max:100_000 ~default:500 "Records per request at most.");
      ( "max_bytes",
        int ~min:1024
          ~max:(100 * 1024 * 1024)
          ~default:(5 * 1024 * 1024)
          "Request body bytes at most." );
      ( "flush_interval_ms",
        int ~min:10 ~max:60_000 ~default:1000
          "Milliseconds before a partial batch is sent." );
    ]

let stream_on_error_schema =
  with_desc
    "What to do when the sink cannot be written: fail_closed refuses requests (HTTP \
     503); buffer keeps up to max_buffer_records in memory and retries; drop discards \
     records (counted in metrics; not fail closed)."
    [
      ("enum", `List [ `String "fail_closed"; `String "buffer"; `String "drop" ]);
      ("default", `String "fail_closed");
    ]

let max_buffer_schema =
  int ~min:1 ~max:1_000_000
    "Records kept in memory while the sink is down (on_error buffer only; at least \
     batch.max_records). Default 10000."

let ca_tls_schema d =
  obj d
    [ ("ca_file", str "PEM CA bundle (path relative to this config, or inline PEM).") ]

let es_sink =
  obj ~required:[ "type" ]
    "Elasticsearch or OpenSearch (bulk API). Needs url or urls, and index or data_stream."
    [
      ("type", const "Sink type." "elasticsearch");
      ("url", str "Cluster URL (https; http only for loopback). Use url or urls.");
      ( "urls",
        arr ~min_items:1 ~unique:true "Several cluster node URLs (use url or urls)."
          (str "Node URL (https; http only for loopback).") );
      ("index", str "Target index (lower case). Use index or data_stream.");
      ("data_stream", str "Target data stream (lower case). Use index or data_stream.");
      ( "auth",
        obj "Credentials: api_key, or username and password (use secret placeholders)."
          [
            ("api_key", str "Encoded API key (sent as Authorization: ApiKey ...).");
            ("username", str "Basic auth user name.");
            ("password", str "Basic auth password.");
          ] );
      ("pipeline", str "Ingest pipeline to run on each record.");
      ("tls", ca_tls_schema "TLS settings (https URLs only).");
      ("timeout_ms", int ~min:100 ~max:120_000 ~default:10_000 "Request timeout.");
      ("batch", stream_batch_schema);
      ("on_error", stream_on_error_schema);
      ("max_buffer_records", max_buffer_schema);
    ]

let kafka_sink =
  obj
    ~required:[ "type"; "brokers"; "topic" ]
    "Apache Kafka topic (one message per audit record)."
    [
      ("type", const "Sink type." "kafka");
      ( "brokers",
        arr ~min_items:1 ~unique:true "Bootstrap brokers." (str "Broker as host:port.") );
      ("topic", str "Topic name (letters, digits, '.', '_', '-').");
      ("client_id", str ~extra:[ ("default", `String "haltsql") ] "Kafka client id.");
      ( "acks",
        with_desc "Acknowledgements required: all (default) or 1 (leader only)."
          [
            ("enum", `List [ `String "all"; `Int 1; `String "1" ]);
            ("default", `String "all");
          ] );
      ( "tls",
        obj "TLS to the brokers."
          [
            ("enabled", bool ~default:true "Use TLS (default true when tls is given).");
            ("ca_file", str "PEM CA bundle for the broker certificates.");
            ("cert_file", str "Client certificate (with key_file).");
            ("key_file", str "Client private key (with cert_file).");
          ] );
      ( "sasl",
        obj
          ~required:[ "mechanism"; "username"; "password" ]
          "SASL authentication. PLAIN needs tls unless every broker is loopback."
          [
            ( "mechanism",
              enum "SASL mechanism." [ "plain"; "scram-sha-256"; "scram-sha-512" ] );
            ("username", str "SASL user name.");
            ("password", str "SASL password (use a secret placeholder).");
          ] );
      ("batch", stream_batch_schema);
      ("on_error", stream_on_error_schema);
      ("max_buffer_records", max_buffer_schema);
    ]

let bundle_source_entry =
  obj
    ~required:[ "bundle_source"; "public_keys" ]
    "Signed policy bundle fetched from a registry, S3 or HTTPS and polled for updates \
     (verified by the server before use)."
    [
      ( "bundle_source",
        obj "Where the bundle comes from: exactly one of oci, s3 or https."
          [
            ( "oci",
              str
                "OCI artifact: registry/repository:tag or registry/repository@sha256:..."
            );
            ( "plain_http",
              bool ~default:false "Talk plain http to the registry (loopback only)." );
            ( "s3",
              obj ~required:[ "bucket"; "key"; "region" ] "S3 (or S3-compatible) object."
                [
                  ("bucket", str "Bucket name.");
                  ("key", str "Object key of the .haltsqlbundle.");
                  ("region", str "AWS region.");
                  ("endpoint", str "Custom endpoint URL (MinIO).");
                  ( "credentials",
                    obj "Where AWS credentials come from (as for s3 audit sinks)."
                      [
                        ( "source",
                          enum "Credential source."
                            [ "env"; "static"; "web_identity"; "instance" ] );
                        ("access_key_id", str "Access key id (static only).");
                        ("secret_access_key", str "Secret access key (static only).");
                        ("session_token", str "Session token (static only, optional).");
                      ] );
                ] );
            ("https", str "HTTPS URL of the .haltsqlbundle (http only for loopback).");
          ] );
      ( "public_keys",
        arr ~min_items:1 "Trusted ed25519 public keys (mandatory)." (str "Public key.") );
      ("name_prefix", str "Prefix added to the names of the policies in this bundle.");
      ( "poll_interval_s",
        int ~min:10 ~max:86_400 ~default:60 "Seconds between update checks." );
      ( "cache_dir",
        str "Directory for the last verified bundle (relative to this config)." );
      ( "auth",
        obj "Registry or HTTPS credentials: token, or username and password."
          [
            ("token", str "Bearer token.");
            ("username", str "User name.");
            ("password", str "Password.");
          ] );
    ]

let opa_schema =
  obj ~required:[ "url"; "decision_path" ]
    "Open Policy Agent check after HaltSQL allows a query. OPA can only further deny; it \
     never allows a query HaltSQL denied."
    [
      ("url", str "OPA base URL (https; http only for loopback).");
      ("decision_path", str "Decision below /v1/data, e.g. haltsql/allow.");
      ("timeout_ms", int ~min:10 ~max:5000 ~default:500 "Decision request timeout.");
      ( "on_error",
        with_desc
          "When OPA cannot be reached or answers badly: deny (default) or keep HaltSQL's \
           verdict."
          [
            ("enum", `List [ `String "deny"; `String "allow_haltsql_verdict" ]);
            ("default", `String "deny");
          ] );
      ( "headers",
        map_of "Extra HTTP headers (values may use secret placeholders; redacted)."
          (str "Header value.") );
      ("tls", ca_tls_schema "TLS settings (https url only).");
    ]

let admin_schema =
  obj "Admin API (GET /v1/admin/report, GET /v1/admin/status)."
    [
      ("enabled", bool ~default:false "Serve the admin endpoints.");
      ( "callers",
        arr ~unique:true "Callers allowed (required when enabled)."
          (pattern_str "token:<name>, oidc:<provider> or mtls:<spiffe-id or CN>."
             "^(token|oidc|mtls):.+$") );
      ( "report_window",
        pattern_str "Report window, 1m to 30d. Default 24h." "^[0-9]+[smhd]$" );
      ( "max_tracked_queries",
        int ~min:1 ~max:1_000_000 ~default:10_000
          "Distinct query fingerprints tracked for the report." );
    ]

let config =
  add_defs
    (doc ~id:"config.schema.json" ~title:"HaltSQL runtime configuration"
       "How HaltSQL runs: listen address, TLS, auth tokens, policies, audit, logging. \
        String values may use ${env:NAME}, ${file:/path}, ${vault:path#field}, \
        ${aws-sm:id[#key]} and ${gcp-sm:name[#key]} placeholders."
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
               ("tls", tls_schema);
               ("admin", admin_schema);
               ( "auth",
                 obj "Caller authentication: static bearer tokens, OIDC JWTs, mTLS."
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
                     ("oidc", arr "OpenID Connect providers." oidc_schema);
                     ("mtls", mtls_schema);
                   ] );
             ] );
         ( "policies",
           arr "Policies to load: files, inline, signed bundles or remote bundle sources."
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
                  obj ~required:[ "bundle"; "public_keys" ]
                    "Signed policy bundle (verified by the server before use)."
                    [
                      ( "bundle",
                        str "Path to a .haltsqlbundle file, relative to this config." );
                      ( "public_keys",
                        arr ~min_items:1
                          "Trusted ed25519 public keys: file paths, inline PEM, or \
                           base64 of the 32 raw bytes."
                          (str "Public key.") );
                      ( "name_prefix",
                        str "Prefix added to the names of the policies in this bundle." );
                    ];
                  bundle_source_entry;
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
                          [
                            ("type", const "Sink type." "stdout");
                            ("on_error", on_error_schema);
                          ];
                        obj ~required:[ "type"; "path" ] "JSON-lines file."
                          [
                            ("type", const "Sink type." "file");
                            ("path", str "File path, relative to this config.");
                            ("on_error", on_error_schema);
                          ];
                        s3_sink;
                        gcs_sink;
                        es_sink;
                        kafka_sink;
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
                 str
                   "Legacy shorthand for telemetry.otlp.endpoint (use one or the other)."
               );
               ("otlp", otlp_schema);
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
         ("secrets", secrets_schema);
         ("opa", opa_schema);
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
