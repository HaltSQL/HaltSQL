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

(* When a person is in several mapped groups the most privileged role wins. *)
let precedence = function Admin -> 5 | Owner -> 4 | Audit -> 3 | Analyst -> 2 | Dev -> 1

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

(* Columns: dev, analyst, owner, audit, admin. 'y' yes, 'r' with a reason, 'n' no. *)
let row = function
  | Use_playground -> "yyyny"
  | Search_queries -> "yyyyy"
  | See_raw_sql -> "nrrrn"
  | Pause_caller -> "nrnnr"
  | Propose_changes -> "yyyny"
  | Approve_change -> "nnynn"
  | Approve_exception -> "nnynn"
  | Build_evidence -> "nyyyn"
  | Restart_verifiers -> "nnnny"
  | Manage_access -> "nnnny"
  | Write_cases -> "nyyny"

let column = function Dev -> 0 | Analyst -> 1 | Owner -> 2 | Audit -> 3 | Admin -> 4

let grant role perm =
  match (row perm).[column role] with 'y' -> Yes | 'r' -> With_reason | _ -> No

let permissions_json role =
  `Assoc
    (List.map
       (fun p -> (permission_id p, `String (grant_to_string (grant role p))))
       all_permissions)

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
