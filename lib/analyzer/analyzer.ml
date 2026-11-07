(** Policy analysis of one parsed statement (deny by default).

    Rule families (see the module that implements each):
    - A statement kinds, EXPLAIN ............................ here / {!Rules}
    - B SELECT hygiene (locking, INTO, unsupported nodes) ... {!Walk}
    - C require_limit on the outermost SELECT ............... {!Rules.check_limit}
    - D name resolution and scopes .......................... {!Scope}, {!Walk}
    - E column permissions (incl. [*] and whole-row) ........ {!Walk.read_col},
      {!Walk.read_whole}
    - F functions and SQL value functions ................... {!Rules}
    - G operators ........................................... {!Rules}
    - H casts ............................................... {!Rules}
    - I join budget ......................................... here (counted by {!Walk})
    - J parameters must be bound by tenancy ................. here
    - K tenancy proofs ...................................... {!Tenancy}
    - L data-modifying CTEs ................................. {!Walk.walk_cte}
    - M writes .............................................. {!Walk},
      {!Tenancy.check_insert_value}

    All violations are collected (identical reasons are de-duplicated); any exception is
    turned into a single [E_INTERNAL] reason (fail closed). *)

open Haltsql_core

type analysis = {
  reasons : Reason.t list;
  statement_kind : Policy.stmt_kind option;
  tables : string list;
  columns : string list;
  bind_params : (int * Context.value) list;
}

let explain_has_analyze analyze options =
  ignore options;
  analyze

let rec top (env : Env.t) (stmt : Ast.stmt) : Policy.stmt_kind option =
  match stmt with
  | Ast.Select s ->
      Rules.check_stmt_kind env Policy.Select s.sel_loc;
      ignore (Walk.walk_select env Walk.empty_cx ~outermost:true s);
      Some Policy.Select
  | Ast.Insert i ->
      Rules.check_stmt_kind env Policy.Insert i.ins_loc;
      ignore (Walk.walk_insert env Walk.empty_cx i);
      Some Policy.Insert
  | Ast.Update u ->
      Rules.check_stmt_kind env Policy.Update u.upd_loc;
      ignore (Walk.walk_update env Walk.empty_cx u);
      Some Policy.Update
  | Ast.Delete d ->
      Rules.check_stmt_kind env Policy.Delete d.del_loc;
      ignore (Walk.walk_delete env Walk.empty_cx d);
      Some Policy.Delete
  | Ast.Explain { analyze; options; stmt; loc } ->
      if not env.policy.allow_explain then
        Env.emit env ~loc ~rule:"statement.explain" Reason.E_STATEMENT_KIND
          "EXPLAIN is not allowed by this policy"
          ~hint:"Send the query itself, without EXPLAIN."
      else if explain_has_analyze analyze options then
        Env.emit env ~loc ~rule:"statement.explain" Reason.E_STATEMENT_KIND
          "EXPLAIN ANALYZE executes the statement and is never allowed"
          ~hint:"Use plain EXPLAIN without ANALYZE.";
      top env stmt
  | Ast.Other { kind; loc } when Util.is_unsupported_kind kind ->
      (* The parser marks constructs it cannot map precisely as
         [Other {kind = "Unsupported:<what>"}]. *)
      Env.emit env ~loc ~rule:"syntax.unsupported" Reason.E_UNSUPPORTED
        (Printf.sprintf "%s is not supported by HaltSQL's analyzer and is denied"
           (Util.unsupported_what kind))
        ~hint:
          "Rewrite the statement using plain SELECT / INSERT ... VALUES / UPDATE / \
           DELETE.";
      None
  | Ast.Other { kind; loc } ->
      Env.emit env ~loc ~rule:"statement.kind" Reason.E_STATEMENT_KIND
        (Printf.sprintf "%s statements are not allowed" kind)
        ~hint:
          (Printf.sprintf "Only these statement kinds are allowed: %s."
             (Rules.allowed_kinds_text env));
      None

let finalize (env : Env.t) kind : analysis =
  (* Rule I *)
  let max_joins = env.policy.limits.max_joins in
  if env.joins > max_joins then
    Env.emit env ~rule:"joins.budget" Reason.E_JOIN_BUDGET
      (Printf.sprintf "the statement uses %d joins; the policy allows at most %d"
         env.joins max_joins)
      ~hint:
        "Reduce the number of joined relations (split the question into smaller queries).";
  (* Bindings: one value per parameter. *)
  let bindings = List.rev env.bindings in
  let bound_ns =
    List.sort_uniq Int.compare (List.map (fun (b : Env.binding) -> b.b_param) bindings)
  in
  let bind_params =
    List.filter_map
      (fun n ->
        match List.filter (fun (b : Env.binding) -> b.b_param = n) bindings with
        | [] -> None
        | first :: _ as bs ->
            let values = Util.dedupe (List.map (fun (b : Env.binding) -> b.b_value) bs) in
            (match values with
            | [] | [ _ ] -> ()
            | _ :: _ :: _ ->
                Env.emit env ~loc:first.b_loc ~rule:"tenancy.param_conflict"
                  Reason.E_TENANT_MISMATCH
                  (Printf.sprintf
                     "parameter $%d would have to be bound to different tenant values" n)
                  ~hint:
                    "Use a separate $n placeholder for each tenancy key / value shape.");
            Some (n, first.b_value))
      bound_ns
  in
  (* Rule J *)
  let params =
    List.sort_uniq (fun (a, _) (b, _) -> Int.compare a b) (List.rev env.params)
  in
  List.iter
    (fun (n, loc) ->
      if not (List.mem n bound_ns) then
        match env.policy.tenancy.mode with
        | Policy.Bound ->
            Env.emit env ~loc ~rule:"params.unbound" Reason.E_PARAM_UNBOUND
              (Printf.sprintf
                 "parameter $%d is not a tenant placeholder, so its value is unknown" n)
              ~hint:
                "Use $n placeholders only as the value of a tenant predicate (e.g. \
                 o.tenant_id = $1); write other values as literals."
        | Policy.Literal ->
            Env.emit env ~loc ~rule:"params.unbound" Reason.E_PARAM_UNBOUND
              (Printf.sprintf
                 "parameter $%d cannot be bound: this policy uses literal tenancy mode" n)
              ~hint:"Write values as literals; do not use $n placeholders.")
    params;
  (* Rule J, second half: a tenant placeholder may appear only as the value of a
     tenant predicate. Any other occurrence ([$1::float8 IS NOT NULL],
     [$1 = 'x'::name], ...) lets the query change the type PostgreSQL infers for
     the parameter, and therefore how the bound tenant value is compared. *)
  let proof_locs = List.map (fun (b : Env.binding) -> (b.b_param, b.b_ploc)) bindings in
  let reported = ref [] in
  List.iter
    (fun (n, loc) ->
      if
        List.mem n bound_ns
        && (not (List.mem (n, loc) proof_locs))
        && not (List.mem n !reported)
      then begin
        reported := n :: !reported;
        Env.emit env ~loc ~rule:"params.tenant_reuse" Reason.E_PARAM_UNBOUND
          (Printf.sprintf
             "tenant placeholder $%d is used outside a tenant predicate; it may only \
              appear as the value of the tenant comparison"
             n)
          ~hint:
            "Use each tenant placeholder only in its tenant predicate (e.g. o.tenant_id \
             = $1); do not cast it or compare it to anything else."
      end)
    (List.rev env.params);
  {
    reasons = Util.dedupe (List.rev env.reasons);
    statement_kind = kind;
    tables = Util.sort_uniq_strings env.tables;
    columns = Util.sort_uniq_strings env.columns;
    bind_params;
  }

let analyze (policy : Policy.t) (ctx : Context.t) (stmt : Ast.stmt) : analysis =
  try
    let env = Env.create policy ctx in
    let kind = top env stmt in
    finalize env kind
  with e ->
    {
      reasons =
        [
          Reason.make ~rule:"internal" Reason.E_INTERNAL
            ("internal analyzer error: " ^ Printexc.to_string e)
            ~hint:"This is a HaltSQL bug; the statement is denied (fail closed).";
        ];
      statement_kind = None;
      tables = [];
      columns = [];
      bind_params = [];
    }
