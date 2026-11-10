(* Console roles and the permission matrix (docs/console/api.md#roles). *)

type role = Dev | Analyst | Owner | Audit | Admin

let all_roles = [ Dev; Analyst; Owner; Audit; Admin ]

let role_to_string = function
  | Dev -> "dev"
  | Analyst -> "analyst"
  | Owner -> "owner"
  | Audit -> "audit"
  | Admin -> "admin"

let role_of_string = function
  | "dev" -> Some Dev
  | "analyst" -> Some Analyst
  | "owner" -> Some Owner
  | "audit" -> Some Audit
  | "admin" -> Some Admin
  | _ -> None

let role_label = function
  | Dev -> "Agent developer"
  | Analyst -> "Security analyst"
  | Owner -> "Policy owner"
  | Audit -> "Compliance"
  | Admin -> "Platform admin"

(* Display precedence only: picks the primary [role] shown for a person in several mapped
   groups. It never decides access; permissions are the union of every mapped role's
   grants ([grant_union]). *)
let precedence = function Admin -> 5 | Owner -> 4 | Audit -> 3 | Analyst -> 2 | Dev -> 1

(** The highest-precedence role of a non-empty list (display only). *)
let primary = function
  | [] -> invalid_arg "Rbac.primary: no roles"
  | r :: rs ->
      List.fold_left (fun a b -> if precedence b > precedence a then b else a) r rs

type grant = No | Yes | With_reason

let grant_to_string = function No -> "no" | Yes -> "yes" | With_reason -> "reason"

type permission =
  | Use_playground
  | Search_queries
  | See_raw_sql
  | Pause_caller
  | Propose_changes
  | Approve_change
  | Approve_exception
  | Build_evidence
  | Restart_verifiers
  | Manage_access
  | Write_cases
  | View_activity

let all_permissions =
  [
    Use_playground;
    Search_queries;
    See_raw_sql;
    Pause_caller;
    Propose_changes;
    Approve_change;
    Approve_exception;
    Build_evidence;
    Restart_verifiers;
    Manage_access;
    Write_cases;
    View_activity;
  ]

let permission_id = function
  | Use_playground -> "use_playground"
  | Search_queries -> "search_queries"
  | See_raw_sql -> "see_raw_sql"
  | Pause_caller -> "pause_caller"
  | Propose_changes -> "propose_changes"
  | Approve_change -> "approve_change"
  | Approve_exception -> "approve_exception"
  | Build_evidence -> "build_evidence"
  | Restart_verifiers -> "restart_verifiers"
  | Manage_access -> "manage_access"
  | Write_cases -> "write_cases"
  | View_activity -> "view_activity"

let permission_name = function
  | Use_playground -> "Use the Playground"
  | Search_queries -> "Search queries, hashes only"
  | See_raw_sql -> "See raw SQL"
  | Pause_caller -> "Pause a caller"
  | Propose_changes -> "Accept suggestions, open PRs"
  | Approve_change -> "Approve a policy change"
  | Approve_exception -> "Approve a PII exception"
  | Build_evidence -> "Build evidence packs"
  | Restart_verifiers -> "Restart verifiers"
  | Manage_access -> "Manage roles and integrations"
  | Write_cases -> "Open and update cases"
  | View_activity -> "See the activity log"

(* The matrix, one record per permission. Every permission and every role is named
   explicitly, so the compiler checks the matrix is total. *)
type row = { dev : grant; analyst : grant; owner : grant; audit : grant; admin : grant }

let row = function
  | Use_playground -> { dev = Yes; analyst = Yes; owner = Yes; audit = No; admin = Yes }
  | Search_queries -> { dev = Yes; analyst = Yes; owner = Yes; audit = Yes; admin = Yes }
  | See_raw_sql ->
      {
        dev = No;
        analyst = With_reason;
        owner = With_reason;
        audit = With_reason;
        admin = No;
      }
  | Pause_caller ->
      { dev = No; analyst = With_reason; owner = No; audit = No; admin = With_reason }
  | Propose_changes -> { dev = Yes; analyst = Yes; owner = Yes; audit = No; admin = Yes }
  | Approve_change -> { dev = No; analyst = No; owner = Yes; audit = No; admin = No }
  | Approve_exception -> { dev = No; analyst = No; owner = Yes; audit = No; admin = No }
  | Build_evidence -> { dev = No; analyst = Yes; owner = Yes; audit = Yes; admin = No }
  | Restart_verifiers ->
      { dev = No; analyst = No; owner = No; audit = No; admin = With_reason }
  | Manage_access -> { dev = No; analyst = No; owner = No; audit = No; admin = Yes }
  | Write_cases -> { dev = No; analyst = Yes; owner = Yes; audit = No; admin = Yes }
  | View_activity -> { dev = No; analyst = Yes; owner = Yes; audit = Yes; admin = Yes }

let grant role perm =
  let r = row perm in
  match role with
  | Dev -> r.dev
  | Analyst -> r.analyst
  | Owner -> r.owner
  | Audit -> r.audit
  | Admin -> r.admin

let grant_rank = function No -> 0 | With_reason -> 1 | Yes -> 2

(** The best grant any of [roles] has for [perm]: [Yes] beats [With_reason] beats [No]. A
    person in several mapped groups gets the union of those roles' permissions. *)
let grant_union roles perm =
  List.fold_left
    (fun acc r ->
      let g = grant r perm in
      if grant_rank g > grant_rank acc then g else acc)
    No roles

let permissions_json_union roles =
  `Assoc
    (List.map
       (fun p -> (permission_id p, `String (grant_to_string (grant_union roles p))))
       all_permissions)

let permissions_json role = permissions_json_union [ role ]

let matrix_json () =
  `List
    (List.map
       (fun p ->
         `Assoc
           [
             ("id", `String (permission_id p));
             ("name", `String (permission_name p));
             ( "grants",
               `Assoc
                 (List.map
                    (fun r -> (role_to_string r, `String (grant_to_string (grant r p))))
                    all_roles) );
           ])
       all_permissions)
