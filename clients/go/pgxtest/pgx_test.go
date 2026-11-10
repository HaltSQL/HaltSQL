package pgxtest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/HaltSQL/HaltSQL/clients/go/haltsql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const dbName = "haltsql_polyglot_go"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func dsn(db string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&connect_timeout=2",
		env("HALTSQL_PGUSER", "postgres"), env("HALTSQL_PGPASSWORD", "haltlab"),
		env("HALTSQL_PGHOST", "localhost"), env("HALTSQL_PGPORT", "5417"), db)
}

type vector struct {
	Name     string          `json:"name"`
	Token    *string         `json:"token"`
	Status   int             `json:"status"`
	Response json.RawMessage `json:"response"`
	Request  *struct {
		SQL     string         `json:"sql"`
		Context map[string]any `json:"context"`
	} `json:"request"`
}

func loadVector(t *testing.T, name string) vector {
	b, err := os.ReadFile("../haltsql/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf struct{ Vectors []vector }
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	for _, v := range vf.Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no vector %s", name)
	return vector{}
}

// setup creates the test database, or skips when Postgres is unreachable.
// With HALTSQL_REQUIRE_POSTGRES=1 (set in CI) unreachable is a failure.
func setup(t *testing.T) *sql.DB {
	t.Helper()
	admin, err := sql.Open("pgx", dsn("postgres"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		if os.Getenv("HALTSQL_REQUIRE_POSTGRES") == "1" {
			t.Fatalf("HALTSQL_REQUIRE_POSTGRES=1 but Postgres is not reachable: %v", err)
		}
		t.Skipf("skipping: Postgres not reachable (%v); run: make -C lab up", err)
	}
	mustExec(t, admin, "DROP DATABASE IF EXISTS "+dbName)
	mustExec(t, admin, "CREATE DATABASE "+dbName)
	db, err := sql.Open("pgx", dsn(dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		mustExec(t, admin, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		admin.Close()
	})
	for _, s := range []string{
		"CREATE SCHEMA app",
		"CREATE TABLE app.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text, customer_id int)",
		"INSERT INTO app.orders VALUES (1,'acme','open',1),(2,'acme','paid',1),(3,'globex','open',2)",
		"CREATE SCHEMA intapp",
		"CREATE TABLE intapp.orders (id int PRIMARY KEY, tenant_id bigint NOT NULL)",
		"INSERT INTO intapp.orders VALUES (10,42),(11,42),(12,7)",
		"CREATE SCHEMA reporting",
		"CREATE TABLE reporting.revenue_daily (org_id text, day date, revenue_cents bigint, currency text)",
		"INSERT INTO reporting.revenue_daily VALUES ('acme','2026-01-01',100,'USD'),('acme-eu','2026-01-01',200,'EUR'),('globex','2026-01-01',999,'USD')",
	} {
		mustExec(t, db, s)
	}
	return db
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func client(t *testing.T, v vector) *haltsql.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(v.Status)
		_, _ = w.Write(v.Response)
	}))
	t.Cleanup(srv.Close)
	c, err := haltsql.New(srv.URL, haltsql.WithToken(*v.Token))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// queryIDs runs a guarded query on one connection with the given search_path.
func queryCol[T any](t *testing.T, db *sql.DB, searchPath string, v vector) []T {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SET search_path = "+searchPath); err != nil {
		t.Fatal(err)
	}
	rows, _, err := haltsql.GuardedQuery(ctx, client(t, v), conn, v.Request.SQL, haltsql.Context(v.Request.Context))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []T
	for rows.Next() {
		dest := make([]any, len(cols))
		var first T
		dest[0] = &first
		for i := 1; i < len(cols); i++ {
			dest[i] = new(any)
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		out = append(out, first)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPgxGuardedQuery(t *testing.T) {
	db := setup(t)

	t.Run("bound text tenant", func(t *testing.T) {
		ids := queryCol[int64](t, db, "app", loadVector(t, "allowed_bound_single_tenant"))
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		if fmt.Sprint(ids) != "[1 2]" {
			t.Fatalf("ids = %v", ids)
		}
	})

	t.Run("integer context binds into a bigint column", func(t *testing.T) {
		ids := queryCol[int64](t, db, "intapp", loadVector(t, "allowed_integer_context"))
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		if fmt.Sprint(ids) != "[10 11]" {
			t.Fatalf("ids = %v", ids)
		}
	})

	t.Run("set-valued tenant binds a text array for ANY($1)", func(t *testing.T) {
		orgs := queryCol[string](t, db, "reporting, public", loadVector(t, "allowed_set_valued_tenant"))
		sort.Strings(orgs)
		if fmt.Sprint(orgs) != "[acme acme-eu]" {
			t.Fatalf("orgs = %v", orgs)
		}
	})

	t.Run("denied statement never reaches Postgres", func(t *testing.T) {
		v := loadVector(t, "denied_multi_statement")
		_, _, err := haltsql.GuardedQuery(context.Background(), client(t, v), db, v.Request.SQL, haltsql.Context(v.Request.Context))
		var de *haltsql.DeniedError
		if !errors.As(err, &de) {
			t.Fatalf("err = %v", err)
		}
		var n int
		if err := db.QueryRow("SELECT count(*) FROM app.orders").Scan(&n); err != nil || n != 3 {
			t.Fatalf("orders count = %d, %v", n, err)
		}
	})
}
