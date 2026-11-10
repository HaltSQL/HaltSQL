(* Control mappings for evidence packs and GET /api/v1/evidence/controls.

   Wording follows docs/security/compliance.md (the E1..E10 evidence ids are that page's).
   Every mapping links a HaltSQL or console feature to a control that the customer
   operates; HaltSQL holds no certification and the auditor decides. *)

type control = {
  id : string;
  name : string;
  what : string;  (** what HaltSQL and the console do for this control *)
  evidence : string list;  (** where the evidence is, in a pack or in the console *)
}

let disclaimer =
  "HaltSQL is open-source, self-hosted software. It is not certified or attested under \
   SOC 2, ISO/IEC 27001, HIPAA, GDPR or any other framework, and this mapping does not \
   claim that it is. It maps HaltSQL features to controls that you operate. Whether a \
   control is met depends on how you configure, run and monitor HaltSQL together with \
   your other controls; that judgement stays with you and your auditor."

let frameworks = [ "soc2"; "iso27001"; "gdpr"; "hipaa" ]

let framework_name = function
  | "soc2" -> "SOC 2 (Trust Services Criteria)"
  | "iso27001" -> "ISO/IEC 27001:2022 Annex A"
  | "gdpr" -> "GDPR"
  | "hipaa" -> "HIPAA Security Rule"
  | f -> f

(* Evidence pointers shared by several controls. *)
let e_records = "records/<verifier>.jsonl: one audit record per decision (E2)"
let e_chains = "chains.json: hash-chain verification of the included records (E1)"
let e_policies = "policies.json: policy versions seen in records and loaded now (E5, E6)"
let e_activity = "activity.jsonl: who viewed or changed what in the console, and why"
let e_exceptions = "exceptions.json: approved PII exceptions with owner, ticket, expiry"
let e_data = "Data classification: tagged columns and the policies that allow them"
let e_fleet = "Fleet: verifier readiness, bundle sync and audit sink health (E5)"
let e_signals = "Signals and cases: detected anomalies and their handling"
let e_ci = "Policy CI results and signed bundles in the policy repository (E3, E4)"
let c id name what evidence = { id; name; what; evidence }

let soc2 =
  [
    c "CC6.1" "Logical access security over protected information assets"
      "Policy allowlists of tables, columns, functions and statement kinds; tenant \
       predicate proof; each identity pinned to one policy. The console shows which \
       tagged columns any policy allows."
      [ e_policies; e_records; e_data; e_exceptions ];
    c "CC6.3" "Authorization and modification of access"
      "Each identity pinned to one policy; policy changes go through a pull request, \
       policy CI and signing; console roles and reasons for sensitive views."
      [ e_policies; e_activity; e_ci ];
    c "CC7.2" "Monitoring of system components for anomalies"
      "Audit records per decision, verified hash chains, signals for deny spikes, \
       cross-tenant attempts and broken chains."
      [ e_records; e_chains; e_signals ];
    c "CC8.1" "Change management"
      "Policies in version control, tested in CI, built into signed bundles; the policy \
       version is in every decision; shadow mode for staged rollout."
      [ e_policies; e_ci; e_activity ];
    c "A1.2" "Environmental protections, backup and recovery infrastructure"
      "Verifier readiness and audit sink health (buffering, failing) are monitored; \
       verifiers fail closed when audit cannot be written."
      [ e_fleet; e_chains ];
  ]

let iso27001 =
  [
    c "A.5.15" "Access control"
      "Allowlist policies; deny by default for tables, columns and functions."
      [ e_policies; e_data; e_exceptions ];
    c "A.8.2" "Privileged access rights"
      "Admin API limited to listed callers; console permissions by role, sensitive views \
       (raw SQL) need a reason and are logged."
      [ e_activity; "Access: roles, permission matrix and group mapping" ];
    c "A.8.15" "Logging"
      "One audit record per decision, fail-closed by default; raw SQL off by default; \
       hash-chained records."
      [ e_records; e_chains ];
    c "A.8.16" "Monitoring activities"
      "Signals over the audit stream, fleet health, shadow reports."
      [ e_signals; e_fleet; e_records ];
    c "A.8.32" "Change management"
      "Signed, versioned policy bundles with source commit; policy version in every \
       decision."
      [ e_policies; e_ci ];
  ]

let gdpr =
  [
    c "Art. 5(1)(f)" "Integrity and confidentiality"
      "Tenant isolation proof; column allowlists keep tagged personal data out of agent \
       queries; hash-chained audit records."
      [ e_chains; e_data; e_exceptions ];
    c "Art. 25" "Data protection by design and by default"
      "Deny by default; raw SQL not logged by default; tagged columns blocked unless an \
       approved exception exists."
      [ e_policies; e_data; e_exceptions ];
    c "Art. 30" "Records of processing activities"
      "Audit records tie every decision to a caller, policy and version; the activity \
       log records console access. Audit records themselves may contain personal data \
       (caller identity)."
      [ e_records; e_activity ];
    c "Art. 32" "Security of processing"
      "Access restriction, encryption in transit, audit and fail-closed behaviour."
      [ e_records; e_chains; e_policies ];
  ]

let hipaa =
  [
    c "164.308(a)(1)(ii)(D)" "Information system activity review"
      "Audit records, signals and shadow reports support regular review of agent \
       activity."
      [ e_records; e_signals; e_activity ];
    c "164.312(a)(1)" "Access control"
      "Policy allowlists, tenant scoping and policy pinning for the agent access path."
      [ e_policies; e_data; e_exceptions ];
    c "164.312(b)" "Audit controls"
      "One audit record per decision, fail-closed by default, chain verification."
      [ e_records; e_chains ];
    c "164.312(c)(1)" "Integrity"
      "Write statements denied unless the policy allows them; side-effecting functions \
       and data-modifying CTEs denied."
      [ e_policies; e_records ];
  ]

let for_framework = function
  | "soc2" -> Some soc2
  | "iso27001" -> Some iso27001
  | "gdpr" -> Some gdpr
  | "hipaa" -> Some hipaa
  | _ -> None

let control_to_json x =
  `Assoc
    [
      ("id", `String x.id);
      ("name", `String x.name);
      ("what", `String x.what);
      ("evidence", Api.strings x.evidence);
    ]

let to_json framework controls =
  `Assoc
    [
      ("framework", `String framework);
      ("framework_name", `String (framework_name framework));
      ("disclaimer", `String disclaimer);
      ("controls", `List (List.map control_to_json controls));
    ]
