(** Typed PostgreSQL AST — the subset of the libpg_query parse tree that HaltSQL
    understands.

    Design rule: anything the converter does not map precisely becomes an [Unsupported_*]
    constructor carrying the original node name. The analyzer denies every [Unsupported_*]
    node (fail closed), so an unknown construct can never be silently accepted.

    Identifiers are exactly as the Postgres scanner produced them: unquoted identifiers
    are already folded to lower case, quoted identifiers keep their case, and [U&"..."]
    escapes are already decoded. *)

type loc = int
(** Byte offset into the original SQL string, or [-1] when unknown. *)

type qname = { schema : string option; name : string }
(** A possibly schema-qualified name. Catalog-qualified names ([db.schema.table]) are
    represented as [Unsupported_from]. *)

type alias = { aliasname : string; colnames : string list }
type set_op = Union | Intersect | Except
type join_kind = Inner | Left | Right | Full | Cross
type bool_op = And | Or | Not

type sublink_kind =
  | Exists  (** [EXISTS (subquery)] *)
  | Any  (** [x op ANY (subquery)] and [x IN (subquery)] *)
  | All  (** [x op ALL (subquery)] *)
  | Expr  (** scalar subquery [(SELECT ...)] *)
  | Array_sublink  (** [ARRAY(SELECT ...)] *)
  | Other_sublink of string  (** ROWCOMPARE, MULTIEXPR, CTE — denied *)

type aexpr_kind =
  | Op  (** ordinary binary/unary operator: [=], [<], [+], [||], ... *)
  | Op_any  (** [x op ANY (array)] *)
  | Op_all  (** [x op ALL (array)] *)
  | Distinct  (** [IS DISTINCT FROM] *)
  | Not_distinct  (** [IS NOT DISTINCT FROM] *)
  | Nullif
  | In  (** [x IN (list)] / [x NOT IN (list)]; [name] is ["="] or ["<>"] *)
  | Like
  | Ilike
  | Similar
  | Between
  | Not_between
  | Between_sym
  | Not_between_sym

type const =
  | Int of string  (** kept as text to avoid overflow issues *)
  | Float of string
  | String of string
  | Bool of bool
  | Bit_string of string
  | Null

type field = Name of string | Star

type type_name = {
  type_names : string list;  (** e.g. [["pg_catalog"; "int4"]] or [["regclass"]] *)
  array_bounds : int;  (** number of array dimensions, 0 if not an array *)
  type_loc : loc;
}

type stmt =
  | Select of select
  | Insert of insert
  | Update of update
  | Delete of delete
  | Explain of { analyze : bool; options : string list; stmt : stmt; loc : loc }
  | Other of { kind : string; loc : loc }
      (** Any other statement node (DDL, DO, CALL, COPY, SET, LOCK, ...), carrying the
          libpg_query node name, e.g. ["CreateStmt"]. *)

and select = {
  with_ : with_clause option;
  body : select_body;
  order_by : sort_by list;
  limit_count : expr option;  (** [LIMIT n] / [FETCH FIRST n ROWS] *)
  limit_all : bool;  (** [LIMIT ALL] was written explicitly *)
  limit_offset : expr option;
  locking : string list;  (** e.g. [["FOR UPDATE"]]; empty when absent *)
  sel_loc : loc;
}

and select_body =
  | Simple of simple_select
  | Values of expr list list
  | Set_op of { op : set_op; all : bool; larg : select; rarg : select }

and simple_select = {
  distinct : expr list option;
      (** [None] = no DISTINCT, [Some []] = DISTINCT, [Some es] = DISTINCT ON (es) *)
  targets : target list;
  into : bool;  (** [SELECT ... INTO new_table] *)
  from : from_item list;
  where : expr option;
  group_by : expr list;
  having : expr option;
  windows : window_def list;  (** named WINDOW clauses *)
}

and target = { expr : expr; alias : string option; target_loc : loc }
and sort_by = { sort_expr : expr; sort_loc : loc }

and window_def = {
  win_name : string option;
  partition_by : expr list;
  win_order_by : sort_by list;
  win_loc : loc;
}

and from_item =
  | Relation of { rel : qname; alias : alias option; inh : bool; loc : loc }
      (** A base relation or CTE reference; [inh = false] means [ONLY t]. *)
  | Subquery of { lateral : bool; query : select; alias : alias option; loc : loc }
  | Function of {
      lateral : bool;
      calls : expr list;  (** each is a [Func_call] (or Unsupported) *)
      ordinality : bool;
      alias : alias option;
      loc : loc;
    }
  | Join of {
      kind : join_kind;
      natural : bool;
      left : from_item;
      right : from_item;
      quals : expr option;
      using : string list;
      alias : alias option;
      loc : loc;
    }
  | Unsupported_from of { node : string; loc : loc }
      (** TABLESAMPLE, XMLTABLE, JSON_TABLE, ROWS FROM, 3-part names, ... *)

and with_clause = { recursive : bool; ctes : cte list; with_loc : loc }

and cte = {
  cte_name : string;
  cte_colnames : string list;
  cte_query : stmt;  (** may be a data-modifying statement *)
  cte_loc : loc;
}

and expr =
  | Column_ref of { fields : field list; loc : loc }
      (** [a], [t.a], [s.t.a], [t.*], [*] *)
  | Const of { value : const; loc : loc }
  | Param of { number : int; loc : loc }  (** [$n] *)
  | A_expr of {
      kind : aexpr_kind;
      name : string list;  (** operator name, e.g. [["="]] or [["pg_catalog"; "="]] *)
      lexpr : expr option;
      rexpr : expr option;
      loc : loc;
    }
  | Bool_expr of { op : bool_op; args : expr list; loc : loc }
  | Func_call of {
      fname : qname;
      args : expr list;
      agg_star : bool;
      agg_distinct : bool;
      agg_filter : expr option;
      agg_order : sort_by list;
      over : window_def option;
      variadic : bool;
      loc : loc;
    }
  | Type_cast of { arg : expr; type_name : type_name; loc : loc }
  | Sub_link of {
      kind : sublink_kind;
      testexpr : expr option;
      oper : string list;
      subselect : select;
      loc : loc;
    }
  | Case of {
      arg : expr option;
      whens : (expr * expr) list;
      default : expr option;
      loc : loc;
    }
  | Null_test of { arg : expr; is_null : bool; loc : loc }
  | Boolean_test of { arg : expr; test : string; loc : loc }
      (** [test] is e.g. ["IS_TRUE"], ["IS_NOT_UNKNOWN"] *)
  | Coalesce of { args : expr list; loc : loc }
  | Min_max of { greatest : bool; args : expr list; loc : loc }
  | Row of { args : expr list; loc : loc }
  | Array of { elements : expr list; loc : loc }
  | Indirection of { arg : expr; subscripts : expr list; fields : field list; loc : loc }
      (** [(expr)[i]], [(expr).field], [(expr).*] *)
  | Collate of { arg : expr; collation : string list; loc : loc }
  | Sql_value of { op : string; loc : loc }
      (** CURRENT_DATE, CURRENT_TIMESTAMP, CURRENT_USER, SESSION_USER, ... *)
  | Unsupported of { node : string; loc : loc }

and insert = {
  ins_with : with_clause option;
  ins_rel : qname;
  ins_alias : alias option;
  ins_cols : string list;
  ins_source : select option;  (** [None] = DEFAULT VALUES *)
  on_conflict : bool;
  ins_returning : target list;
  ins_loc : loc;
}

and update = {
  upd_with : with_clause option;
  upd_rel : qname;
  upd_alias : alias option;
  set : (string * expr) list;
  upd_from : from_item list;
  upd_where : expr option;
  upd_returning : target list;
  upd_loc : loc;
}

and delete = {
  del_with : with_clause option;
  del_rel : qname;
  del_alias : alias option;
  using : from_item list;
  del_where : expr option;
  del_returning : target list;
  del_loc : loc;
}

let qname_to_string { schema; name } =
  match schema with None -> name | Some s -> s ^ "." ^ name

let stmt_loc = function
  | Select s -> s.sel_loc
  | Insert i -> i.ins_loc
  | Update u -> u.upd_loc
  | Delete d -> d.del_loc
  | Explain { loc; _ } | Other { loc; _ } -> loc
