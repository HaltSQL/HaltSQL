package haltsql

import (
	"context"
	"database/sql"
	"regexp"
	"sort"
	"strings"
)

// Querier is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Execer is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// TxBeginner is satisfied by *sql.DB and *sql.Conn.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// GuardOption configures the Guarded* functions.
type GuardOption func(*guardOpts)

type guardOpts struct {
	verify      []VerifyOption
	onVerdict   func(*Verdict)
	literal     bool
	shadow      bool
	settings    map[string]string
	hasSettings bool
}

// GuardVerify passes options to Verify (e.g. WithPolicy, WithRequestID).
func GuardVerify(opts ...VerifyOption) GuardOption {
	return func(g *guardOpts) { g.verify = append(g.verify, opts...) }
}

// OnVerdict is called with every verdict (allowed or denied) before anything
// runs; use it for audit logging.
func OnVerdict(f func(*Verdict)) GuardOption { return func(g *guardOpts) { g.onVerdict = f } }

// AllowShadow runs SQL that a shadow-mode policy would deny (the verdict is
// allowed with ShadowReasons set). Without it the guard returns a *DeniedError
// for such a verdict, so switching a policy to shadow on the server cannot by
// itself turn enforcement off in this application. Use it for shadow rollouts.
func AllowShadow() GuardOption { return func(g *guardOpts) { g.shadow = true } }

// ArrayLiteralArgs binds sets as Postgres array literals (for lib/pq).
func ArrayLiteralArgs() GuardOption { return func(g *guardOpts) { g.literal = true } }

// TxSettings adds transaction-local settings to GuardedQueryTx and
// GuardedExecTx: each entry is applied with set_config(name, value, true)
// before the verified statement, in name order. Use it for row-level security
// ("app.tenant_id") or a "statement_timeout". A "search_path" given here has
// no effect when the verdict reports one: the pin is applied last.
//
// GuardedQuery and GuardedExec own no transaction; they return a usage error
// when this option is passed.
func TxSettings(settings map[string]string) GuardOption {
	return func(g *guardOpts) {
		g.hasSettings = true
		if g.settings == nil {
			g.settings = map[string]string{}
		}
		for k, v := range settings {
			g.settings[k] = v
		}
	}
}

var settingNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

type setting struct{ name, value string }

// authorize verifies sqlText and returns the verdict, its driver arguments and
// the caller's transaction settings, or the error that forbids running it.
func authorize(ctx context.Context, hc *Client, sqlText string, vctx Context, opts []GuardOption, tx bool) (*Verdict, []any, []setting, error) {
	if hc == nil {
		return nil, nil, nil, usageErr("nil haltsql client")
	}
	var g guardOpts
	for _, o := range opts {
		o(&g)
	}
	if g.hasSettings && !tx {
		return nil, nil, nil, usageErr("TxSettings needs GuardedQueryTx or GuardedExecTx")
	}
	settings := make([]setting, 0, len(g.settings)+1)
	for name, value := range g.settings {
		if !settingNameRE.MatchString(name) {
			return nil, nil, nil, usageErr("invalid setting name %q", name)
		}
		settings = append(settings, setting{name, value})
	}
	sort.Slice(settings, func(i, j int) bool { return settings[i].name < settings[j].name })
	v, err := hc.Verify(ctx, sqlText, vctx, g.verify...)
	if err != nil {
		return nil, nil, nil, err
	}
	if g.onVerdict != nil {
		g.onVerdict(v)
	}
	if !v.Allowed || (len(v.ShadowReasons) > 0 && !g.shadow) {
		return v, nil, nil, &DeniedError{Verdict: v}
	}
	var args []any
	if g.literal {
		args, err = v.ArgsArrayLiteral()
	} else {
		args, err = v.Args()
	}
	if err != nil {
		return v, nil, nil, err
	}
	return v, args, settings, nil
}

func guard(ctx context.Context, hc *Client, sqlText string, vctx Context, opts []GuardOption) (*Verdict, []any, error) {
	v, args, _, err := authorize(ctx, hc, sqlText, vctx, opts, false)
	return v, args, err
}

// GuardedQuery is the low-level form: it verifies sqlText and, only if it is
// allowed, runs exactly that string with one db.QueryContext call, binding the
// verdict's bind params as $1..$n. On denial it returns a *DeniedError; on any
// HaltSQL failure an *Error. In both cases nothing is sent to the database.
//
// GuardedQuery does not pin the search path. The verifier resolved unqualified
// table names against Verdict.Policy.SearchPath; this function sends one
// statement on whatever session db gives it, so a role or database default
// (ALTER ROLE ... SET search_path) can make a verified "orders" read a
// different table than the one the policy lists. Use it only when the session
// already uses the policy's search path (set on the connection, the role or
// the database) or the SQL names every table with its schema. Otherwise use
// GuardedQueryTx, which pins it.
func GuardedQuery(ctx context.Context, hc *Client, db Querier, sqlText string, vctx Context, opts ...GuardOption) (*sql.Rows, *Verdict, error) {
	if db == nil {
		return nil, nil, usageErr("nil database handle")
	}
	v, args, err := guard(ctx, hc, sqlText, vctx, opts)
	if err != nil {
		return nil, v, err
	}
	rows, err := db.QueryContext(ctx, sqlText, args...)
	return rows, v, err
}

// GuardedExec is GuardedQuery for statements that return no rows (writes
// allowed by a write policy). Like GuardedQuery it does not pin the search
// path; GuardedExecTx does.
func GuardedExec(ctx context.Context, hc *Client, db Execer, sqlText string, vctx Context, opts ...GuardOption) (sql.Result, *Verdict, error) {
	if db == nil {
		return nil, nil, usageErr("nil database handle")
	}
	v, args, err := guard(ctx, hc, sqlText, vctx, opts)
	if err != nil {
		return nil, v, err
	}
	res, err := db.ExecContext(ctx, sqlText, args...)
	return res, v, err
}

// SearchPathSetting returns the value that pins the verdict's search path:
// each schema of Policy.SearchPath double-quoted (embedded quotes doubled),
// joined with ", ". ok is false when the engine did not report a search path.
//
// GuardedQueryTx and GuardedExecTx apply it for you. If you run verified SQL
// yourself, execute "SELECT set_config('search_path', $1, true)" with this
// value in the same transaction, before the verified statement.
func (v *Verdict) SearchPathSetting() (value string, ok bool) {
	if v == nil || v.Policy.SearchPath == nil {
		return "", false
	}
	quoted := make([]string, len(v.Policy.SearchPath))
	for i, schema := range v.Policy.SearchPath {
		quoted[i] = `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	}
	return strings.Join(quoted, ", "), true
}

// pinnedTx runs fn in a transaction that uses the verdict's search path:
// BeginTx (read-only for a select), the caller's settings, the pin, fn,
// Commit. Any error rolls the transaction back.
func pinnedTx(ctx context.Context, db TxBeginner, v *Verdict, settings []setting, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: v.StatementKind == "select"})
	if err != nil {
		return err
	}
	// The pin goes last so that it wins over a search_path in settings.
	if pin, ok := v.SearchPathSetting(); ok {
		settings = append(settings, setting{"search_path", pin})
	}
	for _, s := range settings {
		if _, err = tx.ExecContext(ctx, "SELECT set_config($1, $2, true)", s.name, s.value); err != nil {
			break
		}
	}
	if err == nil {
		err = fn(tx)
	}
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// GuardedQueryTx verifies sqlText and, only if it is allowed, runs exactly
// that string in a transaction that uses the verdict's search path. Use this
// form unless you have a reason not to.
//
// db is a *sql.DB or a *sql.Conn. On one connection the function sends:
//
//  1. BeginTx, read-only when Verdict.StatementKind is "select";
//  2. SELECT set_config(name, value, true) for each entry of TxSettings;
//  3. SELECT set_config('search_path', <Verdict.Policy.SearchPath>, true),
//     every schema quoted as an identifier. It is transaction-local: the
//     session's own search path is back afterwards. Skipped when the verdict
//     has no search path (an engine older than the field);
//  4. the verified string, unchanged, with the verdict's bind params;
//  5. Commit. On any error it rolls back and returns the error.
//
// A *sql.Rows must not outlive its transaction, so the rows are handed to fn
// inside it instead of being returned: read them there. fn must not keep rows
// after it returns; the function closes them and reports rows.Err(). An error
// from fn rolls the transaction back and is returned unchanged.
//
// On denial it returns a *DeniedError; on any HaltSQL failure an *Error. In
// both cases no transaction is opened and nothing is sent to the database.
func GuardedQueryTx(ctx context.Context, hc *Client, db TxBeginner, sqlText string, vctx Context, fn func(rows *sql.Rows) error, opts ...GuardOption) (*Verdict, error) {
	if db == nil {
		return nil, usageErr("nil database handle")
	}
	if fn == nil {
		return nil, usageErr("nil rows function")
	}
	v, args, settings, err := authorize(ctx, hc, sqlText, vctx, opts, true)
	if err != nil {
		return v, err
	}
	return v, pinnedTx(ctx, db, v, settings, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, sqlText, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if err := fn(rows); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		return rows.Err()
	})
}

// GuardedExecTx is GuardedQueryTx for statements that return no rows (writes
// allowed by a write policy): the same pinned transaction, read-only only if
// the verdict is for a select. The result is returned after Commit.
func GuardedExecTx(ctx context.Context, hc *Client, db TxBeginner, sqlText string, vctx Context, opts ...GuardOption) (sql.Result, *Verdict, error) {
	if db == nil {
		return nil, nil, usageErr("nil database handle")
	}
	v, args, settings, err := authorize(ctx, hc, sqlText, vctx, opts, true)
	if err != nil {
		return nil, v, err
	}
	var res sql.Result
	err = pinnedTx(ctx, db, v, settings, func(tx *sql.Tx) error {
		var execErr error
		res, execErr = tx.ExecContext(ctx, sqlText, args...)
		return execErr
	})
	if err != nil {
		return nil, v, err
	}
	return res, v, nil
}
