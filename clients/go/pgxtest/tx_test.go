package pgxtest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaltSQL/HaltSQL/clients/go/haltsql"
	"github.com/jackc/pgx/v5/pgconn"
)

// GuardedQueryTx / GuardedExecTx against Postgres: the pinned search path
// decides which table the verified SQL reads.

const ordersSQL = "SELECT id FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50"

// txClient answers Verify for sqlText with the recorded allow verdict (search
// path [app], $1 = acme, a select), changed by patch.
func txClient(t *testing.T, sqlText string, patch func(m map[string]any)) *haltsql.Client {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(loadVector(t, "allowed_bound_single_tenant").Response, &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(sqlText))
	m["sql_sha256"] = hex.EncodeToString(sum[:])
	if !strings.Contains(sqlText, "$1") {
		m["bind_params"] = []any{}
	}
	if patch != nil {
		patch(m)
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c, err := haltsql.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func searchPath(schemas ...string) func(map[string]any) {
	return func(m map[string]any) {
		p := m["policy"].(map[string]any)
		if schemas == nil {
			delete(p, "search_path")
			return
		}
		p["search_path"] = schemas
	}
}

func kind(k string) func(map[string]any) {
	return func(m map[string]any) { m["statement_kind"] = k }
}

// ints collects the first column of every row.
func ints(dst *[]int64) func(*sql.Rows) error {
	return func(rows *sql.Rows) error {
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			*dst = append(*dst, id)
		}
		return nil
	}
}

// txSetup adds a decoy public.orders and oddly named schemas to the fixture,
// and returns a pool whose sessions start with search_path = public, app (as
// ALTER ROLE ... SET search_path would give them): the decoy comes first.
func txSetup(t *testing.T) *sql.DB {
	t.Helper()
	admin := setup(t)
	for _, s := range []string{
		"CREATE TABLE public.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text, customer_id int)",
		"INSERT INTO public.orders VALUES (666,'acme','decoy',1)",
		`CREATE SCHEMA "Mixed"`,
		`CREATE TABLE "Mixed".orders (id int PRIMARY KEY, tenant_id text NOT NULL)`,
		`INSERT INTO "Mixed".orders VALUES (50,'acme')`,
		`CREATE SCHEMA "we""ird, app"`,
		`CREATE TABLE "we""ird, app".orders (id int PRIMARY KEY, tenant_id text NOT NULL)`,
		`INSERT INTO "we""ird, app".orders VALUES (70,'acme')`,
	} {
		mustExec(t, admin, s)
	}
	db, err := sql.Open("pgx", dsn(dbName)+"&search_path=public,app")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { db.Close() })
	return db
}

func queryTx(t *testing.T, db haltsql.TxBeginner, sqlText string, patch func(map[string]any), opts ...haltsql.GuardOption) []int64 {
	t.Helper()
	var ids []int64
	if _, err := haltsql.GuardedQueryTx(context.Background(), txClient(t, sqlText, patch), db, sqlText, nil, ints(&ids), opts...); err != nil {
		t.Fatal(err)
	}
	return ids
}

func showPath(t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) string {
	t.Helper()
	var sp string
	if err := q.QueryRowContext(context.Background(), "SHOW search_path").Scan(&sp); err != nil {
		t.Fatal(err)
	}
	return sp
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestPgxGuardedTx(t *testing.T) {
	db := txSetup(t)
	ctx := context.Background()

	t.Run("the session default points at the decoy and the low-level form follows it", func(t *testing.T) {
		if sp := showPath(t, db); sp != "public,app" {
			t.Fatalf("session search_path = %q", sp)
		}
		rows, _, err := haltsql.GuardedQuery(ctx, txClient(t, ordersSQL, nil), db, ordersSQL, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var ids []int64
		if err := ints(&ids)(rows); err != nil || fmt.Sprint(ids) != "[666]" {
			t.Fatalf("ids = %v, %v", ids, err)
		}
	})

	t.Run("pinned: reads the policy's table, not the decoy", func(t *testing.T) {
		if ids := queryTx(t, db, ordersSQL, nil); fmt.Sprint(ids) != "[1 2]" {
			t.Fatalf("*sql.DB: ids = %v", ids)
		}
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if ids := queryTx(t, conn, ordersSQL, nil); fmt.Sprint(ids) != "[1 2]" {
			t.Fatalf("*sql.Conn: ids = %v", ids)
		}
	})

	t.Run("the pin is transaction-local", func(t *testing.T) {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if ids := queryTx(t, conn, ordersSQL, nil); fmt.Sprint(ids) != "[1 2]" {
			t.Fatalf("ids = %v", ids)
		}
		if sp := showPath(t, conn); sp != "public,app" {
			t.Fatalf("search_path after the call = %q", sp)
		}
		var id int64
		if err := conn.QueryRowContext(ctx, "SELECT id FROM orders").Scan(&id); err != nil || id != 666 {
			t.Fatalf("the session no longer reads its own table: %d, %v", id, err)
		}
	})

	t.Run("a search_path in TxSettings does not override the pin; other settings apply", func(t *testing.T) {
		q := "SELECT id, current_setting('app.tenant_id'), current_setting('search_path') FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50"
		var got []string
		_, err := haltsql.GuardedQueryTx(ctx, txClient(t, q, nil), db, q, nil, func(rows *sql.Rows) error {
			for rows.Next() {
				var id int64
				var tenant, sp string
				if err := rows.Scan(&id, &tenant, &sp); err != nil {
					return err
				}
				got = append(got, fmt.Sprintf("%d %s %s", id, tenant, sp))
			}
			return nil
		}, haltsql.TxSettings(map[string]string{"search_path": "public, app", "app.tenant_id": "acme"}))
		if err != nil || fmt.Sprint(got) != `[1 acme "app" 2 acme "app"]` {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("upper-case and quoted schema names are pinned as identifiers", func(t *testing.T) {
		for want, schemas := range map[string][]string{
			"[50]": {"Mixed"},
			"[70]": {`we"ird, app`},
		} {
			if ids := queryTx(t, db, ordersSQL, searchPath(schemas...)); fmt.Sprint(ids) != want {
				t.Errorf("search path %q: ids = %v, want %s", schemas, ids, want)
			}
		}
		if ids := queryTx(t, db, ordersSQL, searchPath("nosuch", `we"ird, app`, "app")); fmt.Sprint(ids) != "[70]" {
			t.Errorf("ids = %v", ids)
		}
	})

	t.Run("a verdict without search_path runs under the session's search path", func(t *testing.T) {
		if ids := queryTx(t, db, ordersSQL, searchPath()); fmt.Sprint(ids) != "[666]" {
			t.Fatalf("ids = %v", ids)
		}
		ids := queryTx(t, db, ordersSQL, searchPath(), haltsql.TxSettings(map[string]string{"search_path": "app"}))
		if fmt.Sprint(ids) != "[1 2]" {
			t.Fatalf("with a caller search_path: ids = %v", ids)
		}
	})

	t.Run("Postgres receives the verified string byte for byte", func(t *testing.T) {
		for _, q := range []string{
			"  SELECT current_query(), $1::text /* c */ -- tenant $1\n ",
			"\n\tSELECT current_query() -- no params\n\n",
		} {
			var got string
			_, err := haltsql.GuardedQueryTx(ctx, txClient(t, q, nil), db, q, nil, func(rows *sql.Rows) error {
				if !rows.Next() {
					return errors.New("no row")
				}
				dest := []any{&got}
				if cols, _ := rows.Columns(); len(cols) == 2 {
					dest = append(dest, new(string))
				}
				return rows.Scan(dest...)
			})
			if err != nil || got != q {
				t.Errorf("current_query() = %q, %v; want %q", got, err, q)
			}
		}
	})

	t.Run("an error rolls back and leaves the connection usable", func(t *testing.T) {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		bad := "SELECT 1 / (id - id) FROM orders WHERE tenant_id = $1"
		var ids []int64
		_, err = haltsql.GuardedQueryTx(ctx, txClient(t, bad, nil), conn, bad, nil, ints(&ids))
		if sqlState(err) != "22012" {
			t.Fatalf("err = %v", err)
		}
		// Not left in an aborted transaction, and the session search path is back.
		if sp := showPath(t, conn); sp != "public,app" {
			t.Fatalf("search_path = %q", sp)
		}
		if ids := queryTx(t, conn, ordersSQL, nil); fmt.Sprint(ids) != "[1 2]" {
			t.Fatalf("ids = %v", ids)
		}

		// An error from the rows function undoes a write that already returned rows.
		ins := "INSERT INTO orders VALUES (300, $1, 'new', 1) RETURNING id"
		stop := errors.New("stop")
		_, err = haltsql.GuardedQueryTx(ctx, txClient(t, ins, kind("insert")), conn, ins, nil, func(rows *sql.Rows) error {
			if !rows.Next() {
				return errors.New("no row")
			}
			return stop
		})
		if err != stop {
			t.Fatalf("err = %v", err)
		}
		// A failing write leaves nothing behind either.
		ins2 := "INSERT INTO orders SELECT g, $1, 'x', 1 FROM generate_series(100, 103) g WHERE 10 / (103 - g) > 0"
		if res, _, err := haltsql.GuardedExecTx(ctx, txClient(t, ins2, kind("insert")), conn, ins2, nil); sqlState(err) != "22012" || res != nil {
			t.Fatalf("res = %v, err = %v", res, err)
		}
		if n := count(t, db, "app.orders"); n != 3 {
			t.Fatalf("app.orders has %d rows", n)
		}
		if ids := queryTx(t, conn, ordersSQL, nil); fmt.Sprint(ids) != "[1 2]" {
			t.Fatalf("ids = %v", ids)
		}
	})

	t.Run("a select verdict runs read-only; an allowed write is committed", func(t *testing.T) {
		ins := "INSERT INTO orders VALUES (200, $1, 'new', 1)"
		for _, run := range []func() error{
			func() error {
				_, err := haltsql.GuardedQueryTx(ctx, txClient(t, ins, nil), db, ins, nil, func(*sql.Rows) error { return nil })
				return err
			},
			func() error {
				_, _, err := haltsql.GuardedExecTx(ctx, txClient(t, ins, nil), db, ins, nil)
				return err
			},
		} {
			if err := run(); sqlState(err) != "25006" { // read_only_sql_transaction
				t.Fatalf("write under a select verdict: err = %v", err)
			}
		}
		if n := count(t, db, "app.orders"); n != 3 {
			t.Fatalf("app.orders has %d rows", n)
		}
		res, v, err := haltsql.GuardedExecTx(ctx, txClient(t, ins, kind("insert")), db, ins, nil)
		if err != nil || v.StatementKind != "insert" {
			t.Fatalf("v = %+v, err = %v", v, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("rows affected = %d", n)
		}
		// Committed, and into the policy's table rather than the decoy.
		var tenant string
		if err := db.QueryRow("SELECT tenant_id FROM app.orders WHERE id = 200").Scan(&tenant); err != nil || tenant != "acme" {
			t.Fatalf("tenant = %q, %v", tenant, err)
		}
		if n := count(t, db, "public.orders"); n != 1 {
			t.Fatalf("the decoy has %d rows", n)
		}
		mustExec(t, db, "DELETE FROM app.orders WHERE id = 200")
	})

	t.Run("denied and shadow would-deny verdicts never reach Postgres", func(t *testing.T) {
		del := "DELETE FROM orders"
		shadow := func(m map[string]any) {
			m["shadow_reasons"] = []any{map[string]any{"code": "E_TENANT_MISSING", "message": "m", "rule": "r"}}
			m["statement_kind"] = "delete"
		}
		denied := loadVector(t, "denied_multi_statement")
		for name, c := range map[string]*haltsql.Client{
			"shadow": txClient(t, del, shadow),
			"denied": client(t, denied),
		} {
			q := del
			if name == "denied" {
				q = denied.Request.SQL
			}
			var de *haltsql.DeniedError
			if _, err := haltsql.GuardedQueryTx(ctx, c, db, q, nil, func(*sql.Rows) error { return nil }); !errors.As(err, &de) {
				t.Errorf("%s: query err = %v", name, err)
			}
			if _, _, err := haltsql.GuardedExecTx(ctx, c, db, q, nil); !errors.As(err, &de) {
				t.Errorf("%s: exec err = %v", name, err)
			}
		}
		if a, p := count(t, db, "app.orders"), count(t, db, "public.orders"); a != 3 || p != 1 {
			t.Fatalf("rows: app.orders %d, public.orders %d", a, p)
		}
	})
}
