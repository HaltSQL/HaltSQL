package haltsql

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type vectorFile struct {
	Healthz  json.RawMessage `json:"healthz"`
	Readyz   json.RawMessage `json:"readyz"`
	Policies json.RawMessage `json:"policies"`
	Vectors  []vector        `json:"vectors"`
}

type vector struct {
	Name    string  `json:"name"`
	Token   *string `json:"token"`
	Request *struct {
		SQL     string         `json:"sql"`
		Context map[string]any `json:"context"`
		Policy  string         `json:"policy"`
	} `json:"request"`
	Status   int             `json:"status"`
	Response json.RawMessage `json:"response"`
	Expect   struct {
		Allowed    bool     `json:"allowed"`
		Codes      []string `json:"codes"`
		Positional []any    `json:"positional"`
		ErrorCode  *string  `json:"error_code"`
	} `json:"expect"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	return vf
}

func findVector(t *testing.T, name string) vector {
	t.Helper()
	for _, v := range loadVectors(t).Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no vector %s", name)
	return vector{}
}

type recorded struct {
	method, path, auth, body string
}

type fake struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []recorded
	n    atomic.Int32
}

func newFake(t *testing.T, h func(n int, w http.ResponseWriter, r *http.Request)) *fake {
	f := &fake{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.Header.Get("Authorization"), string(b)})
		f.mu.Unlock()
		n := int(f.n.Add(1))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-1")
		h(n, w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) count() int { return int(f.n.Load()) }

func replay(status int, body []byte) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

func fastRetries() Option { return WithRetries(2, time.Millisecond, 5*time.Millisecond) }

func mustNew(t *testing.T, url string, opts ...Option) *Client {
	t.Helper()
	c, err := New(url, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// normalize JSON-decoded expectations ([]any of string / []any) for comparison.
func normPositional(in []any) []any {
	out := make([]any, len(in))
	for i, x := range in {
		if arr, ok := x.([]any); ok {
			s := make([]string, len(arr))
			for j, e := range arr {
				s[j] = e.(string)
			}
			out[i] = s
		} else {
			out[i] = x
		}
	}
	return out
}

func TestRecordedVectors(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.Vectors) < 10 {
		t.Fatalf("expected at least 10 vectors, got %d", len(vf.Vectors))
	}
	for _, v := range vf.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			f := newFake(t, replay(v.Status, v.Response))
			opts := []Option{fastRetries()}
			if v.Token != nil {
				opts = append(opts, WithToken(*v.Token))
			}
			c := mustNew(t, f.srv.URL, opts...)
			sqlText, vctx, vopts := "SELECT 1", Context{}, []VerifyOption{}
			if v.Request != nil {
				sqlText = v.Request.SQL
				for k, x := range v.Request.Context {
					vctx[k] = x
				}
				if v.Request.Policy != "" {
					vopts = append(vopts, WithPolicy(v.Request.Policy))
				}
			}
			verdict, err := c.Verify(context.Background(), sqlText, vctx, vopts...)
			if v.Status == 200 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if verdict.Allowed != v.Expect.Allowed {
					t.Fatalf("allowed = %v, want %v", verdict.Allowed, v.Expect.Allowed)
				}
				if got := verdict.Codes(); !reflect.DeepEqual(got, append([]string{}, v.Expect.Codes...)) {
					t.Fatalf("codes = %v, want %v", got, v.Expect.Codes)
				}
				args, aerr := verdict.Args()
				if v.Expect.Allowed {
					if aerr != nil {
						t.Fatal(aerr)
					}
					if want := normPositional(v.Expect.Positional); !reflect.DeepEqual(args, want) {
						t.Fatalf("args = %#v, want %#v", args, want)
					}
				} else if !IsKind(aerr, KindUsage) {
					t.Fatalf("Args on denied verdict: err = %v, want usage error", aerr)
				}
				// Round trip: re-encoding bind params gives the wire form.
				var wire struct {
					BindParams json.RawMessage `json:"bind_params"`
				}
				_ = json.Unmarshal(v.Response, &wire)
				re, _ := json.Marshal(verdict.BindParams)
				if !jsonEqual(t, re, wire.BindParams) {
					t.Fatalf("bind params round trip: %s vs %s", re, wire.BindParams)
				}
			} else {
				var he *Error
				if !errors.As(err, &he) || he.Kind != KindHTTP || he.Status != v.Status || he.Code != *v.Expect.ErrorCode {
					t.Fatalf("err = %#v, want HTTP %d %s", err, v.Status, *v.Expect.ErrorCode)
				}
				if verdict != nil || he.Allowed() {
					t.Fatal("an error must never carry an allow")
				}
			}
			r := f.reqs[0]
			if r.method != "POST" || r.path != "/v1/verify" {
				t.Fatalf("request = %s %s", r.method, r.path)
			}
			wantAuth := ""
			if v.Token != nil {
				wantAuth = "Bearer " + *v.Token
			}
			if r.auth != wantAuth {
				t.Fatalf("auth header = %q, want %q", r.auth, wantAuth)
			}
			if v.Request != nil {
				var sent struct {
					SQL     string         `json:"sql"`
					Context map[string]any `json:"context"`
					Policy  string         `json:"policy"`
				}
				if err := json.Unmarshal([]byte(r.body), &sent); err != nil {
					t.Fatal(err)
				}
				wantCtx := v.Request.Context
				if wantCtx == nil {
					wantCtx = map[string]any{}
				}
				if sent.SQL != v.Request.SQL || sent.Policy != v.Request.Policy || !reflect.DeepEqual(sent.Context, wantCtx) {
					t.Fatalf("sent %s", r.body)
				}
			}
		})
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func TestOperations(t *testing.T) {
	vf := loadVectors(t)
	f := newFake(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write(vf.Healthz)
		case "/readyz":
			_, _ = w.Write(vf.Readyz)
		case "/v1/policies":
			_, _ = w.Write(vf.Policies)
		default:
			w.WriteHeader(404)
		}
	})
	c := mustNew(t, f.srv.URL, WithToken("tok"))
	ctx := context.Background()
	h, err := c.Health(ctx)
	if err != nil || h.Status != "ok" {
		t.Fatalf("health = %+v, %v", h, err)
	}
	rd, err := c.Ready(ctx)
	if err != nil || *rd != (ReadyStatus{Ready: true, Status: "ready", Policies: 2}) {
		t.Fatalf("ready = %+v, %v", rd, err)
	}
	ps, err := c.Policies(ctx)
	if err != nil || len(ps) != 1 || ps[0].Name != "saas-analytics" || ps[0].Mode != "enforce" || !strings.HasPrefix(ps[0].Version, "sha256:") {
		t.Fatalf("policies = %+v, %v", ps, err)
	}
	if f.reqs[0].auth != "" || f.reqs[1].auth != "" || f.reqs[2].auth != "Bearer tok" {
		t.Fatalf("token must be sent only to /v1/*: %+v", f.reqs)
	}
}

func TestReadyNotReadyNotRetried(t *testing.T) {
	f := newFake(t, replay(503, []byte(`{"status":"not_ready","policies":0}`)))
	c := mustNew(t, f.srv.URL, fastRetries())
	rd, err := c.Ready(context.Background())
	if err != nil || rd.Ready || rd.Status != "not_ready" || f.count() != 1 {
		t.Fatalf("ready = %+v, %v, attempts %d", rd, err, f.count())
	}
}

func TestRetry503ThenOK(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	f := newFake(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n < 3 {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"POLICY_UNAVAILABLE","message":"reloading"}}`))
			return
		}
		_, _ = w.Write(v.Response)
	})
	c := mustNew(t, f.srv.URL, fastRetries())
	verdict, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"})
	if err != nil || !verdict.Allowed || f.count() != 3 {
		t.Fatalf("verdict=%v err=%v attempts=%d", verdict, err, f.count())
	}
}

func TestPersistent503(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"error":{"code":"AUDIT_UNAVAILABLE","message":"audit sink down"}}`))
	})
	c := mustNew(t, f.srv.URL, WithRetries(3, time.Millisecond, 5*time.Millisecond))
	_, err := c.Verify(context.Background(), "SELECT 1", nil)
	var he *Error
	if !errors.As(err, &he) || he.Status != 503 || he.Code != "AUDIT_UNAVAILABLE" || f.count() != 4 {
		t.Fatalf("err=%v attempts=%d", err, f.count())
	}
}

func TestNonRetryableStatuses(t *testing.T) {
	for _, st := range []int{400, 401, 403, 404, 413, 500} {
		f := newFake(t, replay(st, []byte(`{"error":{"code":"X","message":"m"}}`)))
		c := mustNew(t, f.srv.URL, fastRetries())
		_, err := c.Verify(context.Background(), "SELECT 1", nil)
		var he *Error
		if !errors.As(err, &he) || he.Status != st || f.count() != 1 {
			t.Fatalf("status %d: err=%v attempts=%d", st, err, f.count())
		}
	}
}

func TestTimeoutRetriedThenError(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	f := newFake(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
		}
		_, _ = w.Write(v.Response)
	})
	c := mustNew(t, f.srv.URL, WithTimeout(50*time.Millisecond), WithRetries(1, time.Millisecond, time.Millisecond))
	_, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"})
	if !IsKind(err, KindTimeout) || f.count() != 2 {
		t.Fatalf("err=%v attempts=%d", err, f.count())
	}
}

func TestConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c := mustNew(t, "http://"+addr, fastRetries())
	_, err = c.Verify(context.Background(), "SELECT 1", nil)
	if !IsKind(err, KindTransport) {
		t.Fatalf("err = %v", err)
	}
}

func TestDroppedConnectionRetried(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	f := newFake(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		_, _ = w.Write(v.Response)
	})
	c := mustNew(t, f.srv.URL, fastRetries())
	verdict, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"})
	if err != nil || !verdict.Allowed || f.count() != 2 {
		t.Fatalf("verdict=%v err=%v attempts=%d", verdict, err, f.count())
	}
}

func TestCallerCancelNotRetried(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	c := mustNew(t, f.srv.URL, WithRetries(5, time.Millisecond, time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := c.Verify(ctx, "SELECT 1", nil)
	if !IsKind(err, KindTransport) || f.count() != 1 {
		t.Fatalf("err=%v attempts=%d", err, f.count())
	}
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func mutate(t *testing.T, raw json.RawMessage, f func(m map[string]any)) []byte {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, _ := json.Marshal(m)
	return b
}

func TestFailClosedOnBadBodies(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	cases := map[string][]byte{
		"not json":        []byte("not json"),
		"array body":      []byte("[" + string(v.Response) + "]"),
		"allowed string":  mutate(t, v.Response, func(m map[string]any) { m["allowed"] = "true" }),
		"allowed null":    mutate(t, v.Response, func(m map[string]any) { m["allowed"] = nil }),
		"missing allowed": mutate(t, v.Response, func(m map[string]any) { delete(m, "allowed") }),
		"allowed + reasons": mutate(t, v.Response, func(m map[string]any) {
			m["reasons"] = []any{map[string]any{"code": "E_TABLE_DENIED", "message": "m", "rule": "r"}}
		}),
		"bad code": mutate(t, findVector(t, "denied_parse_error").Response, func(m map[string]any) {
			m["reasons"] = []any{map[string]any{"code": "nope", "message": "m", "rule": "r"}}
		}),
		"param 0":        mutate(t, v.Response, func(m map[string]any) { m["bind_params"] = []any{map[string]any{"param": 0, "value": "a"}} }),
		"value number":   mutate(t, v.Response, func(m map[string]any) { m["bind_params"] = []any{map[string]any{"param": 1, "value": 7}} }),
		"hash mismatch":  mutate(t, v.Response, func(m map[string]any) { m["sql_sha256"] = shaHex("SELECT 2") }),
		"missing tables": mutate(t, v.Response, func(m map[string]any) { delete(m, "tables") }),
		"missing kind":   mutate(t, v.Response, func(m map[string]any) { delete(m, "statement_kind") }),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, replay(200, body))
			c := mustNew(t, f.srv.URL)
			verdict, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"})
			if verdict != nil || !IsKind(err, KindProtocol) {
				t.Fatalf("verdict=%v err=%v", verdict, err)
			}
		})
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://example.invalid/")
		w.WriteHeader(307)
	})
	c := mustNew(t, f.srv.URL, WithToken("tok"))
	_, err := c.Verify(context.Background(), "SELECT 1", nil)
	var he *Error
	if !errors.As(err, &he) || he.Status != 307 || he.Code != "HTTP_307" || f.count() != 1 {
		t.Fatalf("err=%v", err)
	}
}

func TestOversizedBody(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	big := mutate(t, v.Response, func(m map[string]any) { m["pad"] = strings.Repeat("x", 5000) })
	f := newFake(t, replay(200, big))
	c := mustNew(t, f.srv.URL, WithMaxResponseBytes(1024))
	if _, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"}); !IsKind(err, KindProtocol) {
		t.Fatalf("err=%v", err)
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	body := mutate(t, v.Response, func(m map[string]any) { m["future"] = map[string]any{"a": 1} })
	f := newFake(t, replay(200, body))
	c := mustNew(t, f.srv.URL)
	verdict, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"})
	if err != nil || !verdict.Allowed {
		t.Fatalf("verdict=%v err=%v", verdict, err)
	}
}

func TestTokenNeverInErrors(t *testing.T) {
	const token = "super-secret-token-value"
	f := newFake(t, replay(401, []byte(`{"error":{"code":"UNAUTHORIZED","message":"invalid bearer token"}}`)))
	c := mustNew(t, f.srv.URL, WithToken(token))
	_, err := c.Verify(context.Background(), "SELECT 1", nil)
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(fmt.Sprintf("%+v", err), token) {
		t.Fatalf("err = %v", err)
	}
}

func TestOptionValidation(t *testing.T) {
	bad := []struct {
		url  string
		opts []Option
	}{
		{"ftp://x", nil},
		{"not a url", nil},
		{"http://u:p@h", nil},
		{"http://h", []Option{WithToken("a\r\nX-Evil: 1")}},
		{"http://h", []Option{WithToken("")}},
		{"http://h", []Option{WithTimeout(0)}},
		{"http://h", []Option{WithRetries(-1, 0, 0)}},
		{"http://h", []Option{WithHTTPClient(nil)}},
	}
	for _, b := range bad {
		if _, err := New(b.url, b.opts...); !IsKind(err, KindUsage) {
			t.Errorf("New(%q) err = %v, want usage error", b.url, err)
		}
	}
}

func TestContextValidation(t *testing.T) {
	c := mustNew(t, "http://127.0.0.1:1")
	for _, vctx := range []Context{{"t": 1.5}, {"t": true}, {"t": nil}, {"t": []any{1, map[string]any{}}}, {"t": int64(1) << 60}, {"t": []float32{1}}} {
		if _, err := c.Verify(context.Background(), "SELECT 1", vctx); !IsKind(err, KindUsage) {
			t.Errorf("context %v: err = %v, want usage error", vctx, err)
		}
	}
	if _, err := c.Verify(context.Background(), "SELECT \xff", nil); !IsKind(err, KindUsage) {
		t.Errorf("invalid utf8 accepted: %v", err)
	}
	b, err := encodeContext(Context{"a": "x", "b": 7, "c": []string{"p", "q"}, "d": []int{1, 2}})
	if err != nil || string(b) != `{"a":"x","b":7,"c":["p","q"],"d":[1,2]}` {
		t.Fatalf("encode = %s, %v", b, err)
	}
}

func TestArgsAndArrayLiteral(t *testing.T) {
	v := &Verdict{Allowed: true, BindParams: []BindParam{{Param: 2, Values: []string{"a", `b"c`, `d\e`}, IsSet: true}, {Param: 1, Value: "t"}}}
	args, err := v.Args()
	if err != nil || !reflect.DeepEqual(args, []any{"t", []string{"a", `b"c`, `d\e`}}) {
		t.Fatalf("args = %#v, %v", args, err)
	}
	lit, err := v.ArgsArrayLiteral()
	if err != nil || !reflect.DeepEqual(lit, []any{"t", `{"a","b\"c","d\\e"}`}) {
		t.Fatalf("literal = %#v, %v", lit, err)
	}
	for _, bad := range []*Verdict{
		{Allowed: true, BindParams: []BindParam{{Param: 2, Value: "x"}}},
		{Allowed: true, BindParams: []BindParam{{Param: 1, Value: "x"}, {Param: 1, Value: "y"}}},
		{Allowed: false},
		nil,
	} {
		if _, err := bad.Args(); !IsKind(err, KindUsage) {
			t.Errorf("Args(%+v) err = %v", bad, err)
		}
	}
}

// --- a recording database/sql driver for the guard tests ---

type recDriver struct {
	mu    sync.Mutex
	calls []recCall
}
type recCall struct {
	query string
	args  []driver.NamedValue
}
type recConn struct{ d *recDriver }
type recRows struct{ done bool }

func (d *recDriver) Open(string) (driver.Conn, error) { return &recConn{d}, nil }
func (c *recConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}
func (c *recConn) Close() error              { return nil }
func (c *recConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }
func (c *recConn) CheckNamedValue(*driver.NamedValue) error {
	return nil // accept []string like pgx does
}
func (c *recConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.d.mu.Lock()
	c.d.calls = append(c.d.calls, recCall{q, args})
	c.d.mu.Unlock()
	return &recRows{}, nil
}
func (c *recConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.d.mu.Lock()
	c.d.calls = append(c.d.calls, recCall{q, args})
	c.d.mu.Unlock()
	return driver.RowsAffected(1), nil
}
func (r *recRows) Columns() []string { return []string{"ok"} }
func (r *recRows) Close() error      { return nil }
func (r *recRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(1)
	return nil
}

var drvSeq atomic.Int32

func recDB(t *testing.T) (*sql.DB, *recDriver) {
	d := &recDriver{}
	name := fmt.Sprintf("haltsql-rec-%d", drvSeq.Add(1))
	sql.Register(name, d)
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, d
}

func TestGuardedQueryAllowed(t *testing.T) {
	v := findVector(t, "allowed_set_valued_tenant")
	f := newFake(t, replay(200, v.Response))
	c := mustNew(t, f.srv.URL, WithToken(*v.Token))
	db, d := recDB(t)
	var seen int
	rows, verdict, err := GuardedQuery(context.Background(), c, db, v.Request.SQL,
		Context{"org_ids": []string{"acme", "acme-eu", "acme-us"}}, OnVerdict(func(*Verdict) { seen++ }))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !verdict.Allowed || seen != 1 || len(d.calls) != 1 {
		t.Fatalf("allowed=%v seen=%d calls=%d", verdict.Allowed, seen, len(d.calls))
	}
	call := d.calls[0]
	if call.query != v.Request.SQL || len(call.args) != 1 || call.args[0].Ordinal != 1 ||
		!reflect.DeepEqual(call.args[0].Value, []string{"acme", "acme-eu", "acme-us"}) {
		t.Fatalf("call = %+v", call)
	}
}

func TestGuardedExecArrayLiteral(t *testing.T) {
	v := findVector(t, "allowed_set_valued_tenant")
	f := newFake(t, replay(200, v.Response))
	c := mustNew(t, f.srv.URL, WithToken(*v.Token))
	db, d := recDB(t)
	_, _, err := GuardedExec(context.Background(), c, db, v.Request.SQL,
		Context{"org_ids": []string{"acme", "acme-eu", "acme-us"}}, ArrayLiteralArgs())
	if err != nil {
		t.Fatal(err)
	}
	if got := d.calls[0].args[0].Value; got != `{"acme","acme-eu","acme-us"}` {
		t.Fatalf("arg = %#v", got)
	}
}

func TestGuardedQueryDenied(t *testing.T) {
	v := findVector(t, "denied_column_and_tenant")
	f := newFake(t, replay(200, v.Response))
	c := mustNew(t, f.srv.URL, WithToken(*v.Token))
	db, d := recDB(t)
	rows, verdict, err := GuardedQuery(context.Background(), c, db, v.Request.SQL, Context{"tenant_id": "acme"})
	var de *DeniedError
	if rows != nil || !errors.As(err, &de) || !reflect.DeepEqual(de.Verdict.Codes(), []string{"E_COLUMN_DENIED", "E_TENANT_MISSING"}) {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if verdict == nil || verdict.Allowed || len(d.calls) != 0 {
		t.Fatalf("denied query reached the database: %d calls", len(d.calls))
	}
}

// A shadow-mode policy answers "allowed" with shadow reasons. The guard runs
// such SQL only with AllowShadow.
func TestGuardedQueryShadowNeedsOptIn(t *testing.T) {
	v := findVector(t, "allowed_set_valued_tenant")
	var m map[string]any
	if err := json.Unmarshal(v.Response, &m); err != nil {
		t.Fatal(err)
	}
	m["shadow_reasons"] = []map[string]any{{"code": "E_TENANT_MISSING", "message": "m", "rule": "r"}}
	body, _ := json.Marshal(m)
	f := newFake(t, replay(200, body))
	c := mustNew(t, f.srv.URL, WithToken(*v.Token))
	db, d := recDB(t)
	vctx := Context{"org_ids": []string{"acme", "acme-eu", "acme-us"}}
	rows, _, err := GuardedQuery(context.Background(), c, db, v.Request.SQL, vctx)
	var de *DeniedError
	if rows != nil || !errors.As(err, &de) || len(d.calls) != 0 {
		t.Fatalf("shadow would-deny ran without opt-in: rows=%v err=%v calls=%d", rows, err, len(d.calls))
	}
	if !strings.Contains(de.Error(), "shadow mode would deny: E_TENANT_MISSING") {
		t.Fatalf("error = %q", de.Error())
	}
	rows, _, err = GuardedQuery(context.Background(), c, db, v.Request.SQL, vctx, AllowShadow())
	if err != nil || len(d.calls) != 1 {
		t.Fatalf("AllowShadow: err=%v calls=%d", err, len(d.calls))
	}
	rows.Close()
}

func TestGuardedQuerySidecarError(t *testing.T) {
	f := newFake(t, replay(500, []byte(`{"error":{"code":"INTERNAL","message":"boom"}}`)))
	c := mustNew(t, f.srv.URL, WithRetries(0, 0, 0))
	db, d := recDB(t)
	_, _, err := GuardedQuery(context.Background(), c, db, "SELECT 1", nil)
	if !IsKind(err, KindHTTP) || len(d.calls) != 0 {
		t.Fatalf("err=%v calls=%d", err, len(d.calls))
	}
}
