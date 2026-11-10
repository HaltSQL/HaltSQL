EN = "lib/pgwire/enforce.ml"
SE = "lib/pgwire/session.ml"
SS = "lib/pgwire/stmt_state.ml"
UP = "lib/pgwire/upstream.ml"
SV = "lib/pgwire/server.ml"
SC = "lib/scram/haltsql_scram.ml"
BUILD = "opam exec -- dune build test/proxy test/scram bin/proxy"

MUTANTS = [
    # ---- enforcement decisions ----
    ("proxy: denied simple query forwarded", EN,
     "if not v.allowed then (v, Error (of_verdict ~sqlstate v))\n  else if v.bind_params",
     "if (not v.allowed) && false then (v, Error (of_verdict ~sqlstate v))\n  else if v.bind_params"),
    ("proxy: denied Parse forwarded", EN,
     "if v.allowed then (v, Ok ()) else (v, Error (of_verdict ~sqlstate v))",
     "if v.allowed || true then (v, Ok ()) else (v, Error (of_verdict ~sqlstate v))"),
    ("proxy: simple query with unbound tenancy parameter forwarded", EN,
     "else if v.bind_params <> [] then", "else if v.bind_params <> [] && false then"),
    ("proxy: tenant parameter NOT overwritten at Bind (client value kept)", EN,
     "| Some value -> Some (context_text value)\n                | None -> p)",
     "| Some value -> ignore (context_text value); p\n                | None -> p)"),
    ("proxy: rewritten Bind discarded, original payload forwarded", SE,
     "(if v.bind_params = [] then Wire.frame 'B' payload",
     "(if v.bind_params = [] || true then Wire.frame 'B' payload"),
    ("proxy: binary-format tenancy parameter accepted", EN,
     "match Wire.param_format b (k - 1) with", "match (ignore (Wire.param_format b (k - 1)); 0) with"),
    ("proxy: Bind with too few parameters not refused", EN,
     "if k < 1 || k > n then", "if (k < 1 || k > n) && false then"),
    ("proxy: conflicting tenancy values for one parameter accepted", EN,
     "else if List.exists (fun (k', value') -> k' = k && value' <> value) bps then",
     "else if List.exists (fun (k', value') -> k' = k && value' <> value) bps && false then"),
    ("proxy: client-declared type kept for tenancy parameter", EN,
     "if List.mem_assoc (i + 1) bps then 0 else ty", "if List.mem_assoc (i + 1) bps && false then 0 else ty"),
    ("proxy: backslash not escaped in tenant array value", EN,
     "if c = '\"' || c = '\\\\' then Buffer.add_char b '\\\\';", "if c = '\"' then Buffer.add_char b '\\\\';"),
    ("proxy: any all-letters statement counts as transaction control", EN,
     "    | _ -> false\n\nlet tx_verdict", "    | _ -> true\n\nlet tx_verdict"),
    ("proxy: transaction control character filter removed", EN,
     "  then false\n  else\n    let toks =", "  then (match sql with \"\" -> false | _ -> String.length s >= 5 && String.sub s 0 5 = \"BEGIN\")\n  else\n    let toks ="),
    ("proxy: transaction control allowed although allow_transaction_control is off (simple)", SE,
     "Enforce.simple ~sqlstate:(sqlstate s)\n                ~allow_tx:s.sh.cfg.allow_transaction_control b sql)",
     "Enforce.simple ~sqlstate:(sqlstate s)\n                ~allow_tx:(s.sh.cfg.allow_transaction_control || true) b sql)"),
    ("proxy: transaction control allowed although off (extended)", SE,
     "Enforce.parse ~sqlstate:(sqlstate s)\n                ~allow_tx:s.sh.cfg.allow_transaction_control b p.query)",
     "Enforce.parse ~sqlstate:(sqlstate s)\n                ~allow_tx:(s.sh.cfg.allow_transaction_control || true) b p.query)"),
    # ---- statement state ----
    ("proxy: Bind to unknown statement forwarded", SE,
     "let* d = local_denial s ~event:\"bind\" ~stmt:b.bstmt d in\n            deny_extended s d)\n  | 'D' ->",
     "let* _ = local_denial s ~event:\"bind\" ~stmt:b.bstmt d in\n            forward s (Wire.frame 'B' payload))\n  | 'D' ->"),
    ("proxy: re-Parse of an existing named statement allowed", SE,
     "| Stmt_state.Found _ ->\n                    let d =", "| Stmt_state.Found _ when false ->\n                    let d ="),
    ("proxy: Close does not forget the statement verdict", SS,
     "  Hashtbl.remove t.committed name;\n  push t (Op_close_stmt name)", "  push t (Op_close_stmt name)"),
    ("proxy: CloseComplete does not forget the statement verdict", SS,
     "      Hashtbl.remove t.committed name;\n      Ok ()", "      ignore name;\n      Ok ()"),
    ("proxy: statement closed in the same segment still found", SS,
     "  | Some _ -> Missing\n", "  | Some _ -> (match Hashtbl.find_opt t.committed name with Some v -> Found v | None -> Missing)\n"),
    ("proxy: statement with a pending earlier op resolved from stale table", SS,
     "      if !earlier then Wait\n      else", "      if !earlier && false then Wait\n      else"),
    ("proxy: simple query does not drop the unnamed statement verdict", SE,
     "                Stmt_state.drop_unnamed s.st;\n", ""),
    ("proxy: pipelined statement limit removed", SS,
     "if Queue.length t.segs >= t.max_pending then raise Overflow;", "if Queue.length t.segs >= t.max_pending && false then raise Overflow;"),
    ("proxy: failed Parse still commits its verdict (error drops nothing)", SS,
     "let on_error t =\n  drop_head_ops t;", "let on_error t =\n  ignore drop_head_ops;"),
    # ---- protocol surface ----
    ("proxy: function-call message forwarded", SE,
     "let* d = local_denial s ~event:\"function_call\" d in\n        deny_simple s d",
     "let* _ = local_denial s ~event:\"function_call\" d in\n        forward s (Wire.frame tag payload)"),
    ("proxy: client COPY data forwarded", SE,
     "fatal \"08P01\" \"COPY sub-protocol is not allowed through haltsql-proxy\"",
     "forward s (Wire.frame tag payload)"),
    ("proxy: upstream COPY mode relayed", SE,
     "fatal \"08P01\"\n          \"upstream entered COPY mode; COPY is not allowed through haltsql-proxy\"",
     "raw ()"),
    ("proxy: replication connection not refused", SE,
     "if List.mem_assoc \"replication\" params then", "if List.mem_assoc \"replication\" params && false then"),
    ("proxy: application_name not validated before reaching upstream", SE,
     "| Some a when valid_app_name a -> Some a", "| Some a when valid_app_name a || true -> Some a"),
    ("proxy: other database name accepted", SE,
     "if database <> cfg.upstream.database then", "if database <> cfg.upstream.database && false then"),
    ("proxy: TLS not required although tls.required", SE,
     "| Some t when t.tls_required && not tls_on ->", "| Some t when t.tls_required && (not tls_on) && false ->"),
    ("proxy: plaintext pipelined after SSLRequest accepted", SE,
     "if Io.buffered s.client > 0 then\n              (* plaintext pipelined", "if Io.buffered s.client > 0 && false then\n              (* plaintext pipelined"),
    ("proxy: unexpected upstream auth/key message relayed mid-session", SE,
     "| 'R' | 'K' | 'v' ->\n        fatal \"08P01\" (Printf.sprintf \"unexpected message %C from upstream\" tag)",
     "| 'R' | 'K' | 'v' -> raw ()"),
    # ---- search_path pin ----
    ("proxy: search_path not sent in upstream startup", UP,
     "| Some (Ok v) -> Lwt.return [ (\"search_path\", v) ]", "| Some (Ok v) -> ignore v; Lwt.return []"),
    ("proxy: pg_temp not appended to the pinned search_path", UP,
     "if List.mem \"pg_temp\" schemas then schemas else schemas @ [ \"pg_temp\" ]",
     "if List.mem \"pg_temp\" schemas || true then schemas else schemas @ [ \"pg_temp\" ]"),
    ("proxy: SHOW search_path answer not compared", SE,
     "| Some v when Upstream.search_path_matches ~expected:(search_path s) v ->\n            Lwt.return payload",
     "| Some v when Upstream.search_path_matches ~expected:(search_path s) v || true ->\n            Lwt.return payload"),
    ("proxy: missing SHOW search_path answer tolerated", SE,
     "| None -> fatal \"08P01\" \"upstream did not answer SHOW search_path\")", "| None -> Lwt.return payload)"),
    ("proxy: upstream refusing SHOW search_path tolerated", SE,
     "fatal \"08006\" \"haltsql-proxy: could not confirm the upstream search_path\"", "loop value"),
    ("proxy: search_path ParameterStatus change ignored", SE,
     "| \"search_path\" when not (Upstream.search_path_matches ~expected:(search_path s) v) ->",
     "| \"search_path\" when false && not (Upstream.search_path_matches ~expected:(search_path s) v) ->"),
    ("proxy: search_path comparison folds quoted names", UP,
     "| Some j -> after (skip j) (Buffer.contents b :: acc)", "| Some j -> after (skip j) (String.lowercase_ascii (Buffer.contents b) :: acc)"),
    ("proxy: search_path comparison ignores order", UP,
     "parse_search_path v = Some expected",
     "Option.map (List.sort compare) (parse_search_path v) = Some (List.sort compare expected)"),
    ("proxy: quote in schema name not doubled when pinning", UP,
     "      if c = '\"' then Buffer.add_char b '\"';\n", ""),
    ("proxy: standard_conforming_strings=off tolerated", SE,
     "| \"standard_conforming_strings\" when v <> \"on\" ->", "| \"standard_conforming_strings\" when v <> \"on\" && false ->"),
    ("proxy: upstream client_encoding change tolerated", SE,
     "| \"client_encoding\" when String.uppercase_ascii v <> \"UTF8\" ->", "| \"client_encoding\" when String.uppercase_ascii v <> \"UTF8\" && false ->"),
    # ---- session lifetime / reload ----
    ("proxy: max_session_lifetime never enforced", SE,
     "if l <= 0. then never ()", "if l <= 0. || true then never ()"),
    ("proxy: termination grace never expires", SE,
     "(Lwt_unix.sleep s.sh.cfg.limits.termination_grace);", "(Lwt_unix.sleep (1e6 +. s.sh.cfg.limits.termination_grace));"),
    ("proxy: session ended mid-transaction (boundary not awaited)", SE,
     "let at_boundary s = s.tx_status = 'I' && Stmt_state.in_flight s.st = 0", "let at_boundary s = (s.tx_status = 'I' || true) && Stmt_state.in_flight s.st = 0"),
    ("proxy: message after end request still verified and forwarded", SE,
     "if s.ending <> None && at_boundary s then (\n    (* the session is ending", "if s.ending <> None && at_boundary s && false then (\n    (* the session is ending"),
    ("proxy: reload never terminates changed sessions", SV,
     "if not cfg.reload.terminate_changed_sessions then false", "if (not cfg.reload.terminate_changed_sessions) || true then false"),
    ("proxy: reload terminates although terminate_changed_sessions is off", SV,
     "if not cfg.reload.terminate_changed_sessions then false", "if (not cfg.reload.terminate_changed_sessions) && false then false"),
    ("proxy: changed credentials do not end the session", SE,
     "if credential <> l.credential then Some \"its credentials changed\"", "if credential <> l.credential && false then Some \"its credentials changed\""),
    ("proxy: changed policy version does not end the session", SE,
     "else if b.policy.version <> old.policy.version then Some \"its policy changed\"", "else if b.policy.version <> old.policy.version && false then Some \"its policy changed\""),
    ("proxy: rebinding to another policy does not end the session", SE,
     "else if b.policy_name <> old.policy_name then Some \"it is bound to another policy\"", "else if b.policy_name <> old.policy_name && false then Some \"it is bound to another policy\""),
    ("proxy: changed context does not end the session", SE,
     "then Some \"its context changed\"", "then (if true then None else Some \"its context changed\")"),
    ("proxy: removed user keeps its session", SE,
     "| None -> Error \"its user was removed\")", "| None -> Ok (l.credential, l.live_binding))"),
    ("proxy: changed client CA does not end certificate sessions", SE,
     "&& client_ca cfg <> client_ca l.live_cfg", "&& client_ca cfg <> client_ca l.live_cfg && false"),
    ("proxy: session authenticated across a reload not re-checked", SV,
     "if shared.generation <> t.gen.generation then ignore (end_if_stale t l)", "if shared.generation <> t.gen.generation && false then ignore (end_if_stale t l)"),
    # ---- connection limits ----
    ("proxy: per-IP unauthenticated cap removed", SV,
     "else if per_ip > 0 && preauth_count t ip >= per_ip then (", "else if per_ip > 0 && preauth_count t ip >= per_ip && false then ("),
    ("proxy: authenticated sessions keep counting against the pre-auth cap", SV,
     "            no_longer_pending ();\n            Hashtbl.replace t.live n l;", "            Hashtbl.replace t.live n l;"),
    ("proxy: max_connections not enforced", SV,
     "else if Hashtbl.length t.conns >= t.gen.cfg.limits.max_connections then (", "else if Hashtbl.length t.conns >= t.gen.cfg.limits.max_connections && false then ("),
    ("proxy: client cert without clientAuth EKU accepted", SV,
     "List.exists (fun u -> u = `Client_auth || u = `Any) usages", "List.exists (fun u -> u = `Client_auth || u = `Any || true) usages"),
    ("proxy: idle timeout never fires", SE,
     "if Stmt_state.in_flight s.st > 0 then wait ()", "if Stmt_state.in_flight s.st > 0 || true then wait ()"),
    # ---- upstream authentication ----
    ("proxy: MD5 password sent over plaintext upstream", UP,
     "| Wire.Auth_md5 _, None when Io.tls io = None && not u.allow_insecure_auth ->",
     "| Wire.Auth_md5 _, None when Io.tls io = None && (not u.allow_insecure_auth) && false ->"),
    ("proxy: cleartext password sent over plaintext upstream", UP,
     "if Io.tls io = None then\n              fail\n                \"upstream requested a cleartext", "if Io.tls io = None && false then\n              fail\n                \"upstream requested a cleartext"),
    ("proxy: upstream AuthOk accepted in the middle of SCRAM", UP,
     "| Wire.Auth_ok, Some _ -> fail \"upstream skipped SCRAM server verification\"", "| Wire.Auth_ok, Some _ -> Lwt.return_unit"),
    ("proxy: upstream SCRAM server signature not verified", UP,
     "            | Error m -> fail \"%s\" m\n            | Ok () -> loop ~scram:None)", "            | Error _ -> loop ~scram:None\n            | Ok () -> loop ~scram:None)"),
    ("proxy: upstream without TLS accepted although tls.mode requires it", UP,
     "fail \"upstream server does not support TLS but upstream.tls.mode requires it\"", "Lwt.return plain"),
    ("proxy: unencrypted bytes after upstream TLS accept tolerated", UP,
     "if Io.buffered plain > 0 then\n            fail \"upstream sent unencrypted", "if Io.buffered plain > 0 && false then\n            fail \"upstream sent unencrypted"),
    ("proxy: verify-full with unverifiable host name proceeds", UP,
     "            | Tls_verify_full ->\n                (* without a name or an IP the authenticator checks the chain only:\n                   fail closed *)\n                Error\n                  (Printf.sprintf\n                     \"upstream host %s cannot be verified (neither an IP address nor a \\\n                      valid DNS host name); tls.mode verify-full needs one\"\n                     u.host)\n            | Tls_require | Tls_disable -> Ok (None, None)))",
     "            | Tls_verify_full | Tls_require | Tls_disable -> Ok (None, None)))"),
    # ---- cancel ----
    ("proxy: cancel key not compared", SE,
     "if Sec.ct_equal (enc k) (enc key) then (", "if Sec.ct_equal (enc k) (enc key) || true then ("),
    ("proxy: cancel entry survives the session", SE,
     "(match s.proxy_pid with Some p -> Hashtbl.remove sh.cancel_table p | None -> ());", "(match s.proxy_pid with Some p -> ignore (p, sh.cancel_table) | None -> ());"),
    ("proxy: client receives the upstream's real cancel key", SE,
     "let* () = Io.write s.client (Wire.backend_key_data ~pid ~key) in", "let* () = Io.write s.client (ignore (pid, key); Wire.backend_key_data ~pid:upid ~key:ukey) in"),
    # ---- audit ----
    ("proxy: audit failure does not refuse the statement", SE,
     "Lwt.return (Error (audit_refusal ()))", "Lwt.return (ignore (audit_refusal ()); Ok ())"),
    ("proxy: no audit record for Execute", SE,
     "let* a = audit_execute s ~portal ~max_rows in", "let* a = Lwt.return (ignore (audit_execute, portal, max_rows); Ok ()) in"),
    ("proxy: denied statements audited as allowed", SE,
     "(\"allowed\", `Bool (Result.is_ok r));", "(\"allowed\", `Bool (Result.is_ok r || true));"),
    ("proxy: raw SQL always written to the audit log", SE,
     "@ if s.sh.cfg.log_raw_sql then [ (\"sql\", `String sql) ] else [])", "@ if s.sh.cfg.log_raw_sql || true then [ (\"sql\", `String sql) ] else [])"),
    ("proxy: proxy-level denial not audited", SE,
     "  let+ r = audit_local s ~event ?stmt d in\n  match r with Ok () -> d | Error refusal -> refusal",
     "  let+ r = Lwt.return (ignore (audit_local, s, event, stmt); Ok ()) in\n  match r with Ok () -> d | Error refusal -> refusal"),
    ("proxy: Execute audit names no statement", SE,
     "(\"statement\", str (of_portal (fun p -> p.p_stmt)));", "(\"statement\", str (of_portal (fun p -> ignore p.p_stmt; \"\")));"),
    # ---- client authentication (SCRAM) ----
    ("scram: server accepts any proof for a real user", SC,
     "if ok && t.real then Ok (\"v=\" ^ b64_encode server_sig)", "if (ok || true) && t.real then Ok (\"v=\" ^ b64_encode server_sig)"),
    ("scram: mock (unknown) user can complete the exchange", SC,
     "if ok && t.real then Ok (\"v=\" ^ b64_encode server_sig)", "if ok && (t.real || true) then Ok (\"v=\" ^ b64_encode server_sig)"),
    ("proxy: unknown user with a valid mock exchange is authenticated as nobody -> rejected", SE,
     "`String (if u = None then \"unknown user\" else \"bad proof\")", "`String (if u = None then \"bad proof\" else \"bad proof\")"),
    ("scram: channel-binding data (c=) not compared", SC,
     "if not (equal_ct cb (b64_encode t.client_gs2_header)) then", "if (not (equal_ct cb (b64_encode t.client_gs2_header))) && false then"),
    ("scram: p= channel binding request reported as malformed instead of unsupported", SC,
     "| Some _ when len >= 2 && client_first.[0] = 'p' && client_first.[1] = '=' ->\n        Error Channel_binding_unsupported",
     "| Some _ when len >= 2 && client_first.[0] = 'p' && client_first.[1] = '=' ->\n        Error Malformed_client_first"),
    ("scram: unknown gs2 flag accepted", SC,
     "match gs2_flag with 'n' | 'y' -> Ok () | _ -> Error Malformed_client_first", "match gs2_flag with 'n' | 'y' -> Ok () | _ -> Ok ()"),
    ("scram: client-final nonce not compared", SC,
     "else if not (equal_ct r t.nonce) then Error Nonce_mismatch", "else if (not (equal_ct r t.nonce)) && false then Error Nonce_mismatch"),
    ("scram: authzid accepted", SC,
     "| Some _ -> Error Authzid_unsupported", "| Some i -> Ok (String.sub rest (i + 1) (String.length rest - i - 1))"),
    ("scram: mandatory extension m= ignored by server", SC,
     "| Some (('m', _) :: _) -> Error Unsupported_extension\n    | Some (('n', _) :: ('r', r) :: _) ->", "| Some (('m', _) :: ('n', _) :: ('r', r) :: _)\n    | Some (('n', _) :: ('r', r) :: _) ->"),
    ("scram: client accepts a server nonce that does not extend its own", SC,
     "if String.length r > String.length cf.nonce && String.starts_with ~prefix:cf.nonce r\n    then Ok ()",
     "if String.length r > String.length cf.nonce || String.starts_with ~prefix:cf.nonce r\n    then Ok ()"),
    ("scram: client accepts any server signature", SC,
     "| Some got when equal_ct got expected -> Ok ()", "| Some got when equal_ct got expected || true -> Ok ()"),
    ("scram: client accepts low iteration counts (downgrade)", SC,
     "| Some n when n < min_iterations || n > max_iterations ->", "| Some n when (n < min_iterations && false) || n > max_iterations ->"),
    ("scram: client accepts huge iteration counts (DoS)", SC,
     "| Some n when n < min_iterations || n > max_iterations ->", "| Some n when n < min_iterations || (n > max_iterations && false) ->"),
    ("scram: server-final with e= after v= accepted", SC,
     "| Some (('v', v) :: rest) when not (List.mem_assoc 'e' rest) -> (", "| Some (('v', v) :: rest) when not (List.mem_assoc 'e' rest) || true -> ("),
    ("scram: verifier with short keys accepted", SC,
     "                 && String.length stored_key = 32\n", ""),
    ("proxy: client cert CN identity matches any certificate", SE,
     "| Subject_cn c -> cn = Some c", "| Subject_cn c -> cn = Some c || cn <> None"),
    ("proxy: client SPIFFE identity taken from first of several URI SANs", SE,
     "| [ u ] when String.length u >= plen && String.sub u 0 plen = prefix -> Some u", "| u :: _ when String.length u >= plen && String.sub u 0 plen = prefix -> Some u"),
    ("proxy: cert auth without a client certificate proceeds to mismatch path only", SE,
     "              | None ->\n                  log s Plog.Warn \"certificate identity not authorized\" [];\n                  fatal \"28000\" \"certificate identity is not authorized\")))",
     "              | None -> (\n                  match ids with\n                  | id :: _ -> Lwt.return (Identity id.id_match, \"\", id.id_binding)\n                  | [] -> fatal \"28000\" \"certificate identity is not authorized\"))))"),
]

# Mutants that change nothing a test can observe, with the reason.
EQUIVALENT = {'proxy: Close does not forget the statement verdict': 'redundant triple: lookup returns Missing '
                                                       'for a statement closed in the current '
                                                       'segment, Wait for an earlier one, and '
                                                       'CloseComplete removes it',
 'proxy: CloseComplete does not forget the statement verdict': 'redundant with the removal at '
                                                               'Close',
 'proxy: client cert without clientAuth EKU accepted': 'redundant: ocaml-tls refuses a '
                                                       'serverAuth-only client certificate itself '
                                                       '(new test test_cert_rejected passes with '
                                                       "the proxy's check removed)",
 'proxy: failed Parse still commits its verdict (error drops nothing)': 'redundant: on_ready drops '
                                                                        "the head segment's ops "
                                                                        'too, and no ParseComplete '
                                                                        'can arrive between the '
                                                                        'error and ReadyForQuery',
 'proxy: message after end request still verified and forwarded': 'covers a scheduling window only '
                                                                  '(the terminator ends the '
                                                                  'session in the same tick); not '
                                                                  'deterministically observable',
 'proxy: rebinding to another policy does not end the session': 'redundant: two policies with '
                                                                'different names always differ in '
                                                                'version (the name is part of the '
                                                                'hashed document)',
 'proxy: statement closed in the same segment still found': 'redundant with the removal at Close',
 'proxy: unencrypted bytes after upstream TLS accept tolerated': 'same client-visible outcome: the '
                                                                 'buffered plaintext is discarded '
                                                                 'when the transport is replaced '
                                                                 'and the handshake fails; only '
                                                                 'the log text differs',
 'proxy: unknown user with a valid mock exchange is authenticated as nobody -> rejected': 'log '
                                                                                          'text '
                                                                                          'only (a '
                                                                                          'mutant '
                                                                                          'that '
                                                                                          'should '
                                                                                          'not '
                                                                                          'have '
                                                                                          'been '
                                                                                          'written)',
 'proxy: verify-full with unverifiable host name proceeds': 'unreachable through a loaded config: '
                                                            'Proxy_config rejects such hosts for '
                                                            'verify-full',
 'scram: mock (unknown) user can complete the exchange': 'unreachable: a valid proof for the mock '
                                                         'verifier needs a SHA-256 preimage of a '
                                                         'key derived from a random secret'}
