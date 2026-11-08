package haltsql

import (
	"context"
	"database/sql"
)

// Querier is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Execer is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// GuardOption configures GuardedQuery / GuardedExec.
type GuardOption func(*guardOpts)

type guardOpts struct {
	verify    []VerifyOption
	onVerdict func(*Verdict)
	literal   bool
}

// GuardVerify passes options to Verify (e.g. WithPolicy, WithRequestID).
func GuardVerify(opts ...VerifyOption) GuardOption {
	return func(g *guardOpts) { g.verify = append(g.verify, opts...) }
}

// OnVerdict is called with every verdict (allowed or denied) before anything
// runs; use it for audit logging.
func OnVerdict(f func(*Verdict)) GuardOption { return func(g *guardOpts) { g.onVerdict = f } }

// ArrayLiteralArgs binds sets as Postgres array literals (for lib/pq).
func ArrayLiteralArgs() GuardOption { return func(g *guardOpts) { g.literal = true } }

func guard(ctx context.Context, hc *Client, sqlText string, vctx Context, opts []GuardOption) (*Verdict, []any, error) {
	if hc == nil {
		return nil, nil, usageErr("nil haltsql client")
	}
	var g guardOpts
	for _, o := range opts {
		o(&g)
	}
	v, err := hc.Verify(ctx, sqlText, vctx, g.verify...)
	if err != nil {
		return nil, nil, err
	}
	if g.onVerdict != nil {
		g.onVerdict(v)
	}
	if !v.Allowed {
		return v, nil, &DeniedError{Verdict: v}
	}
	var args []any
	if g.literal {
		args, err = v.ArgsArrayLiteral()
	} else {
		args, err = v.Args()
	}
	if err != nil {
		return v, nil, err
	}
	return v, args, nil
}

// GuardedQuery verifies sqlText and, only if it is allowed, runs exactly that
// string with db.QueryContext, binding the verdict's bind params as $1..$n.
// On denial it returns a *DeniedError; on any HaltSQL failure an *Error. In
// both cases nothing is sent to the database.
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
// allowed by a write policy).
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
