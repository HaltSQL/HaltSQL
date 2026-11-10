package haltsql

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

// GuardedQueryTx / GuardedExecTx with the recording driver: the exact
// statements, their order, and what happens on errors. The pgxtest module
// checks the same paths against Postgres.

const txSQL = "  SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50 -- c\n"
const setConfig = "SELECT set_config($1, $2, true)"

// txClient answers every Verify with the recorded allow verdict (search path
// [app], $1 = acme) for txSQL, changed by patch.
func txClient(t *testing.T, patch func(m map[string]any)) *Client {
	t.Helper()
	v := findVector(t, "allowed_bound_single_tenant")
	body := mutate(t, v.Response, func(m map[string]any) {
		m["sql_sha256"] = shaHex(txSQL)
		if patch != nil {
			patch(m)
		}
	})
	return mustNew(t, newFake(t, replay(200, body)).srv.URL)
}

func policyOf(m map[string]any) map[string]any { return m["policy"].(map[string]any) }

func kind(k string) func(map[string]any) {
	return func(m map[string]any) { m["statement_kind"] = k }
}

func noRows(*sql.Rows) error { return nil }

func argValues(c recCall) []any {
	out := make([]any, len(c.args))
	for i, a := range c.args {
		out[i] = a.Value
	}
	return out
}

func TestGuardedQueryTxStatementsInOrder(t *testing.T) {
	db, d := recDB(t)
	seen, got := 0, 0
	v, err := GuardedQueryTx(context.Background(), txClient(t, nil), db, txSQL, Context{"tenant_id": "acme"},
		func(rows *sql.Rows) error {
			for rows.Next() {
				got++
			}
			return rows.Err()
		},
		TxSettings(map[string]string{"search_path": "public", "app.tenant_id": "acme"}),
		OnVerdict(func(*Verdict) { seen++ }))
	if err != nil || v == nil || !v.Allowed || seen != 1 || got != 1 {
		t.Fatalf("err=%v verdict=%+v seen=%d rows=%d", err, v, seen, got)
	}
	want := []string{"BEGIN READ ONLY", setConfig, setConfig, setConfig, txSQL, "COMMIT"}
	if !reflect.DeepEqual(d.queries(), want) {
		t.Fatalf("statements = %q\nwant %q", d.queries(), want)
	}
	// Caller settings in name order, then the pin: it must come last.
	for i, w := range [][]any{{"app.tenant_id", "acme"}, {"search_path", "public"}, {"search_path", `"app"`}} {
		if got := argValues(d.calls[1+i]); !reflect.DeepEqual(got, w) {
			t.Errorf("set_config #%d args = %v, want %v", i+1, got, w)
		}
	}
	if got := argValues(d.calls[4]); !reflect.DeepEqual(got, []any{"acme"}) {
		t.Errorf("query args = %v", got)
	}
}

func TestGuardedExecTxWriteIsNotReadOnly(t *testing.T) {
	for _, k := range []string{"insert", "update", "delete"} {
		db, d := recDB(t)
		res, v, err := GuardedExecTx(context.Background(), txClient(t, kind(k)), db, txSQL, Context{"tenant_id": "acme"})
		if err != nil || res == nil || v == nil {
			t.Fatalf("%s: res=%v v=%v err=%v", k, res, v, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Errorf("%s: rows affected = %d", k, n)
		}
		want := []string{"BEGIN", setConfig, txSQL, "COMMIT"}
		if !reflect.DeepEqual(d.queries(), want) {
			t.Fatalf("%s: statements = %q", k, d.queries())
		}
		if got := argValues(d.calls[2]); !reflect.DeepEqual(got, []any{"acme"}) {
			t.Errorf("%s: exec args = %v", k, got)
		}
	}
	// A select verdict is read-only for GuardedExecTx too.
	db, d := recDB(t)
	if _, _, err := GuardedExecTx(context.Background(), txClient(t, nil), db, txSQL, nil); err != nil || d.queries()[0] != "BEGIN READ ONLY" {
		t.Fatalf("err=%v statements=%q", err, d.queries())
	}
}

func TestSearchPathSettingQuotesIdentifiers(t *testing.T) {
	v := &Verdict{Policy: PolicyRef{SearchPath: []string{"app", `we"ird`, "Mixed", "a,b", ""}}}
	if got, ok := v.SearchPathSetting(); !ok || got != `"app", "we""ird", "Mixed", "a,b", ""` {
		t.Fatalf("setting = %q, %v", got, ok)
	}
	// An empty list is still pinned (to an empty path); only an absent field is not.
	if got, ok := (&Verdict{Policy: PolicyRef{SearchPath: []string{}}}).SearchPathSetting(); !ok || got != "" {
		t.Fatalf("empty list: %q, %v", got, ok)
	}
	for _, none := range []*Verdict{nil, {}} {
		if got, ok := none.SearchPathSetting(); ok || got != "" {
			t.Fatalf("no search path: %q, %v", got, ok)
		}
	}
	db, d := recDB(t)
	c := txClient(t, func(m map[string]any) { policyOf(m)["search_path"] = []any{"app", `we"ird`, "Mixed"} })
	if _, err := GuardedQueryTx(context.Background(), c, db, txSQL, nil, noRows); err != nil {
		t.Fatal(err)
	}
	if got := argValues(d.calls[1]); !reflect.DeepEqual(got, []any{"search_path", `"app", "we""ird", "Mixed"`}) {
		t.Fatalf("pin args = %v", got)
	}
}

// A verdict from an engine that does not report search_path still runs, in a
// transaction, without the pin.
func TestGuardedTxWithoutSearchPathDoesNotPin(t *testing.T) {
	noPath := func(m map[string]any) { delete(policyOf(m), "search_path") }
	db, d := recDB(t)
	v, err := GuardedQueryTx(context.Background(), txClient(t, noPath), db, txSQL, nil, noRows)
	if err != nil || v.Policy.SearchPath != nil {
		t.Fatalf("err=%v search path=%v", err, v.Policy.SearchPath)
	}
	if want := []string{"BEGIN READ ONLY", txSQL, "COMMIT"}; !reflect.DeepEqual(d.queries(), want) {
		t.Fatalf("statements = %q", d.queries())
	}
	db, d = recDB(t)
	c := txClient(t, func(m map[string]any) { noPath(m); kind("update")(m) })
	if _, _, err := GuardedExecTx(context.Background(), c, db, txSQL, nil, TxSettings(map[string]string{"search_path": "app"})); err != nil {
		t.Fatal(err)
	}
	if want := []string{"BEGIN", setConfig, txSQL, "COMMIT"}; !reflect.DeepEqual(d.queries(), want) {
		t.Fatalf("statements = %q", d.queries())
	}
	if got := argValues(d.calls[1]); !reflect.DeepEqual(got, []any{"search_path", "app"}) {
		t.Fatalf("caller setting args = %v", got)
	}
}

func TestGuardedTxRollsBackOnError(t *testing.T) {
	boom := errors.New("boom")
	failOn := func(q string) func(string) error {
		return func(got string) error {
			if got == q {
				return boom
			}
			return nil
		}
	}
	last := func(d *recDriver) string { q := d.queries(); return q[len(q)-1] }
	for _, failing := range []string{setConfig, txSQL} {
		db, d := recDB(t)
		d.fail = failOn(failing)
		called := false
		_, err := GuardedQueryTx(context.Background(), txClient(t, nil), db, txSQL, nil,
			func(*sql.Rows) error { called = true; return nil })
		if !errors.Is(err, boom) || called || last(d) != "ROLLBACK" {
			t.Fatalf("query, %q fails: err=%v called=%v statements=%q", failing, err, called, d.queries())
		}
		if failing == setConfig && len(d.queries()) != 3 {
			t.Fatalf("the statement ran without its pin: %q", d.queries())
		}
		db, d = recDB(t)
		d.fail = failOn(failing)
		res, _, err := GuardedExecTx(context.Background(), txClient(t, kind("delete")), db, txSQL, nil)
		if !errors.Is(err, boom) || res != nil || last(d) != "ROLLBACK" {
			t.Fatalf("exec, %q fails: res=%v err=%v statements=%q", failing, res, err, d.queries())
		}
	}

	// An error from the rows function rolls back and is returned unchanged.
	db, d := recDB(t)
	mine := errors.New("stop")
	_, err := GuardedQueryTx(context.Background(), txClient(t, nil), db, txSQL, nil, func(*sql.Rows) error { return mine })
	if err != mine || last(d) != "ROLLBACK" {
		t.Fatalf("err=%v statements=%q", err, d.queries())
	}

	// A failed BEGIN sends nothing else; a failed COMMIT is reported.
	db, d = recDB(t)
	d.fail = failOn("BEGIN READ ONLY")
	if _, err := GuardedQueryTx(context.Background(), txClient(t, nil), db, txSQL, nil, noRows); !errors.Is(err, boom) || len(d.queries()) != 1 {
		t.Fatalf("failed BEGIN: err=%v statements=%q", err, d.queries())
	}
	db, d = recDB(t)
	d.fail = failOn("COMMIT")
	if res, _, err := GuardedExecTx(context.Background(), txClient(t, kind("insert")), db, txSQL, nil); !errors.Is(err, boom) || res != nil {
		t.Fatalf("failed COMMIT: res=%v err=%v", res, err)
	}
}

func TestGuardedTxNeverOpensATransactionWithoutAnAllow(t *testing.T) {
	denied := findVector(t, "denied_multi_statement")
	shadow := func(m map[string]any) {
		m["shadow_reasons"] = []any{map[string]any{"code": "E_TENANT_MISSING", "message": "m", "rule": "r"}}
	}
	cases := []struct {
		name   string
		c      *Client
		sql    string
		denied bool
	}{
		{"denied", mustNew(t, newFake(t, replay(200, denied.Response)).srv.URL, WithToken(*denied.Token)), denied.Request.SQL, true},
		{"shadow would-deny", txClient(t, shadow), txSQL, true},
		{"sidecar error", mustNew(t, newFake(t, replay(500, []byte(`{"error":{"code":"INTERNAL","message":"boom"}}`))).srv.URL, WithRetries(0, 0, 0)), txSQL, false},
		{"verdict for other SQL", txClient(t, func(m map[string]any) { m["sql_sha256"] = shaHex("SELECT 1") }), txSQL, false},
	}
	for _, tc := range cases {
		db, d := recDB(t)
		called := false
		v, err := GuardedQueryTx(context.Background(), tc.c, db, tc.sql, Context{"tenant_id": "acme"},
			func(*sql.Rows) error { called = true; return nil })
		if err == nil || IsDenied(err) != tc.denied || called || (tc.denied && (v == nil || v.Allowed && len(v.ShadowReasons) == 0)) {
			t.Errorf("%s: query: v=%+v err=%v called=%v", tc.name, v, err, called)
		}
		res, _, err := GuardedExecTx(context.Background(), tc.c, db, tc.sql, Context{"tenant_id": "acme"})
		if err == nil || IsDenied(err) != tc.denied || res != nil {
			t.Errorf("%s: exec: res=%v err=%v", tc.name, res, err)
		}
		if len(d.queries()) != 0 {
			t.Errorf("%s: reached the database: %q", tc.name, d.queries())
		}
	}
	// AllowShadow opts in, as for GuardedQuery.
	db, d := recDB(t)
	if _, err := GuardedQueryTx(context.Background(), txClient(t, shadow), db, txSQL, nil, noRows, AllowShadow()); err != nil || len(d.queries()) != 4 {
		t.Fatalf("AllowShadow: err=%v statements=%q", err, d.queries())
	}
}

func TestGuardedTxUsageErrors(t *testing.T) {
	db, d := recDB(t)
	f := newFake(t, replay(500, []byte(`{}`)))
	c := mustNew(t, f.srv.URL, WithRetries(0, 0, 0))
	ctx := context.Background()
	for _, name := range []string{"", "bad name", "x;y", "a..b", "1a", "a.", `a"b`} {
		bad := TxSettings(map[string]string{name: "v"})
		if _, err := GuardedQueryTx(ctx, c, db, txSQL, nil, noRows, bad); !IsKind(err, KindUsage) {
			t.Errorf("setting name %q: err = %v", name, err)
		}
		if _, _, err := GuardedExecTx(ctx, c, db, txSQL, nil, bad); !IsKind(err, KindUsage) {
			t.Errorf("setting name %q: err = %v", name, err)
		}
	}
	if _, err := GuardedQueryTx(ctx, c, nil, txSQL, nil, noRows); !IsKind(err, KindUsage) {
		t.Errorf("nil db: %v", err)
	}
	if _, err := GuardedQueryTx(ctx, c, db, txSQL, nil, nil); !IsKind(err, KindUsage) {
		t.Errorf("nil rows function: %v", err)
	}
	if _, _, err := GuardedExecTx(ctx, c, nil, txSQL, nil); !IsKind(err, KindUsage) {
		t.Errorf("nil db: %v", err)
	}
	if _, err := GuardedQueryTx(ctx, nil, db, txSQL, nil, noRows); !IsKind(err, KindUsage) {
		t.Errorf("nil client: %v", err)
	}
	// The single-statement functions own no transaction: settings would be lost.
	some := TxSettings(map[string]string{"app.tenant_id": "acme"})
	if rows, _, err := GuardedQuery(ctx, c, db, txSQL, nil, some); !IsKind(err, KindUsage) || rows != nil {
		t.Errorf("GuardedQuery with TxSettings: %v", err)
	}
	if res, _, err := GuardedExec(ctx, c, db, txSQL, nil, some); !IsKind(err, KindUsage) || res != nil {
		t.Errorf("GuardedExec with TxSettings: %v", err)
	}
	if f.count() != 0 || len(d.queries()) != 0 {
		t.Fatalf("usage errors reached the sidecar (%d) or the database (%q)", f.count(), d.queries())
	}
}
