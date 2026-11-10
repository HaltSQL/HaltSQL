package haltsql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// allowVector replays a recorded allow verdict; verifyAllowed sends its SQL.
var allowVector vector

func allowAll(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(allowVector.Response)
}

func verifyAllowed(t *testing.T, c *Client) (*Verdict, error) {
	t.Helper()
	allowVector = findVector(t, "allowed_bound_single_tenant")
	return c.Verify(context.Background(), allowVector.Request.SQL, Context(allowVector.Request.Context))
}

func TestUntrustedCertificateFailsClosed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(allowAll))
	defer srv.Close()
	c := mustNew(t, srv.URL, WithRetries(0, 0, 0))
	_, err := c.Verify(context.Background(), "SELECT 1", nil)
	if err == nil || !IsKind(err, KindTransport) {
		t.Fatalf("want transport error for an untrusted certificate, got %v", err)
	}
}

func TestWithTLSConfigTrustsPrivateCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(allowAll))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := mustNew(t, srv.URL, WithTLSConfig(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	v, err := verifyAllowed(t, c)
	if err != nil || !v.Allowed {
		t.Fatalf("verify over TLS with private CA: %v %v", v, err)
	}
}

func TestWithTLSConfigMutualTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"UNAUTHORIZED","message":"no client cert"}}`)
			return
		}
		allowAll(w, r)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	// Without a client certificate: the server refuses, and that is an error.
	c := mustNew(t, srv.URL, WithTLSConfig(&tls.Config{RootCAs: pool}))
	if _, err := verifyAllowed(t, c); !IsKind(err, KindHTTP) {
		t.Fatalf("want HTTP 401 error without a client cert, got %v", err)
	}
	// With one (reuse the server's own pair as the client identity).
	cert := srv.TLS.Certificates[0]
	c = mustNew(t, srv.URL, WithTLSConfig(&tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}))
	if v, err := verifyAllowed(t, c); err != nil || !v.Allowed {
		t.Fatalf("verify with client cert: %v %v", v, err)
	}
}

func TestWithTLSConfigValidation(t *testing.T) {
	if _, err := New("https://h", WithTLSConfig(nil)); !IsKind(err, KindUsage) {
		t.Fatalf("nil tls config: %v", err)
	}
	if _, err := New("https://h", WithTLSConfig(&tls.Config{InsecureSkipVerify: true})); !IsKind(err, KindUsage) {
		t.Fatalf("InsecureSkipVerify must be refused: %v", err)
	}
}

func TestInvalidRequestIDIsUsageErrorAndNotSent(t *testing.T) {
	f := newFake(t, func(int, http.ResponseWriter, *http.Request) {})
	c := mustNew(t, f.srv.URL, fastRetries())
	for _, id := range []string{"a\r\nX-Evil: 1", strings.Repeat("x", 201), "café"} {
		if _, err := c.Verify(context.Background(), "SELECT 1", nil, WithRequestID(id)); !IsKind(err, KindUsage) {
			t.Fatalf("request id %q: want usage error, got %v", id, err)
		}
	}
	if f.count() != 0 {
		t.Fatalf("nothing should be sent, got %d requests", f.count())
	}
}

func TestDefaultTimeoutAndUserAgent(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		allowAll(w, r)
	}))
	defer srv.Close()
	c := mustNew(t, srv.URL)
	if c.timeout != 5*time.Second {
		t.Fatalf("default timeout = %s", c.timeout)
	}
	if _, err := verifyAllowed(t, c); err != nil {
		t.Fatal(err)
	}
	if ua != "haltsql-client-go/"+Version {
		t.Fatalf("user agent = %q", ua)
	}
}

// errorText renders an error the ways an application might log it.
func errorText(err error) string {
	var b strings.Builder
	for e := err; e != nil; e = errors.Unwrap(e) {
		fmt.Fprintf(&b, "%v|%+v|%#v\n", e, e, e)
	}
	return b.String()
}

func TestTokenNeverInTransportOrTimeoutErrors(t *testing.T) {
	const token = "super-secret-token-value"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c := mustNew(t, "http://"+addr, WithToken(token), WithRetries(0, 0, 0))
	_, err = c.Verify(context.Background(), "SELECT 1", nil)
	if !IsKind(err, KindTransport) || strings.Contains(errorText(err), token) {
		t.Fatalf("transport error leaks the token or has the wrong kind: %s", errorText(err))
	}

	f := newFake(t, func(_ int, _ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	c = mustNew(t, f.srv.URL, WithToken(token), WithTimeout(30*time.Millisecond), WithRetries(0, 0, 0))
	_, err = c.Verify(context.Background(), "SELECT 1", nil)
	if !IsKind(err, KindTimeout) || strings.Contains(errorText(err), token) {
		t.Fatalf("timeout error leaks the token or has the wrong kind: %s", errorText(err))
	}
}

// Only 503, connection errors and timeouts are retried. A response that was
// received and is unusable (too large) is final.
func TestProtocolErrorsAreNotRetried(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	big := mutate(t, v.Response, func(m map[string]any) { m["pad"] = strings.Repeat("x", 5000) })
	f := newFake(t, replay(200, big))
	c := mustNew(t, f.srv.URL, WithMaxResponseBytes(1024), fastRetries())
	_, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"})
	if !IsKind(err, KindProtocol) || f.count() != 1 {
		t.Fatalf("err=%v attempts=%d, want one attempt", err, f.count())
	}
}

// The size cap must hold without a Content-Length: the body is not read past
// the cap (an endless body is cut off, it does not run into the timeout).
func TestBodyCapOnEndlessChunkedBody(t *testing.T) {
	chunk := []byte(strings.Repeat("x", 1024))
	f := newFake(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			fl.Flush()
		}
	})
	c := mustNew(t, f.srv.URL, WithMaxResponseBytes(4096), WithTimeout(3*time.Second), WithRetries(0, 0, 0))
	start := time.Now()
	_, err := c.Verify(context.Background(), "SELECT 1", nil)
	if !IsKind(err, KindProtocol) || !strings.Contains(err.Error(), "response larger than 4096 bytes") {
		t.Fatalf("err = %v, want the size-cap protocol error", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s: the body was read past the cap", d)
	}
}

// A declared Content-Length above the cap is refused before the body is read.
func TestBodyCapOnDeclaredLength(t *testing.T) {
	f := newFake(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		_, _ = w.Write([]byte(`{"allowed":`))
		w.(http.Flusher).Flush()
		<-r.Context().Done() // never sends the rest
	})
	c := mustNew(t, f.srv.URL, WithMaxResponseBytes(1024), WithTimeout(3*time.Second), WithRetries(0, 0, 0))
	start := time.Now()
	_, err := c.Verify(context.Background(), "SELECT 1", nil)
	if !IsKind(err, KindProtocol) || !strings.Contains(err.Error(), "response larger than 1024 bytes") {
		t.Fatalf("err = %v, want the size-cap protocol error", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s: waited for a body that was already too large", d)
	}
}

// WithTLSConfig must not weaken verification: a pool that does not contain
// the server's CA, or a server name that does not match, fails closed.
func TestWithTLSConfigStillVerifiesTheServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(allowAll))
	defer srv.Close()
	c := mustNew(t, srv.URL, WithTLSConfig(&tls.Config{RootCAs: x509.NewCertPool()}), WithRetries(0, 0, 0))
	if v, err := verifyAllowed(t, c); v != nil || !IsKind(err, KindTransport) {
		t.Fatalf("unknown CA: verdict=%v err=%v, want transport error", v, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c = mustNew(t, srv.URL, WithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "other.invalid"}), WithRetries(0, 0, 0))
	if v, err := verifyAllowed(t, c); v != nil || !IsKind(err, KindTransport) {
		t.Fatalf("wrong server name: verdict=%v err=%v, want transport error", v, err)
	}
}

// Health and Policies succeed only on 200; Ready is true only on 200 + "ready".
func TestOperationsFailClosedOnStatus(t *testing.T) {
	vf := loadVectors(t)
	status := 500
	body := []byte(`{"status":"ok"}`)
	f := newFake(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	c := mustNew(t, f.srv.URL, WithToken("tok"), WithRetries(0, 0, 0))
	ctx := context.Background()
	if h, err := c.Health(ctx); h != nil || !IsKind(err, KindHTTP) {
		t.Fatalf("health on 500: %+v, %v", h, err)
	}
	status, body = 403, vf.Policies
	if ps, err := c.Policies(ctx); ps != nil || !IsKind(err, KindHTTP) {
		t.Fatalf("policies on 403: %+v, %v", ps, err)
	}
	status, body = 503, []byte(`{"status":"ready","policies":2}`)
	if rd, err := c.Ready(ctx); err != nil || rd.Ready {
		t.Fatalf("503 that says ready: %+v, %v", rd, err)
	}
	status, body = 200, []byte(`{"status":"not_ready","policies":0}`)
	if rd, err := c.Ready(ctx); err != nil || rd.Ready {
		t.Fatalf("200 that says not_ready: %+v, %v", rd, err)
	}
	status, body = 500, []byte(`{"status":"ready","policies":2}`)
	if rd, err := c.Ready(ctx); rd != nil || !IsKind(err, KindHTTP) {
		t.Fatalf("ready on 500: %+v, %v", rd, err)
	}
}

// With the hash check off the verdict's own fields are all that is left:
// sql_sha256 must still have the documented shape.
func TestParseVerdictChecksHashShape(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	for _, bad := range []any{"", "abc", strings.ToUpper(shaHex("x")), shaHex("x") + "0", 7, nil} {
		body := mutate(t, v.Response, func(m map[string]any) { m["sql_sha256"] = bad })
		if pv, err := ParseVerdict(body); err == nil {
			t.Fatalf("sql_sha256 %#v accepted: %+v", bad, pv)
		}
		f := newFake(t, replay(200, body))
		c := mustNew(t, f.srv.URL, WithoutSQLHashCheck())
		if pv, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"}); pv != nil || !IsKind(err, KindProtocol) {
			t.Fatalf("sql_sha256 %#v: verdict=%v err=%v", bad, pv, err)
		}
	}
}

// encoding/json decodes a JSON null inside a []string as "": a null in a
// string array must be a protocol error, never an empty bind value.
func TestNullInStringArraysFailsClosed(t *testing.T) {
	v := findVector(t, "allowed_bound_single_tenant")
	cases := map[string]func(m map[string]any){
		"set bind value with a null element": func(m map[string]any) {
			m["bind_params"] = []any{map[string]any{"param": 1, "value": []any{"acme", nil}}}
		},
		"tables with a null element":  func(m map[string]any) { m["tables"] = []any{"app.orders", nil} },
		"columns with a null element": func(m map[string]any) { m["columns"] = []any{nil} },
		"search_path with a null element": func(m map[string]any) {
			m["policy"].(map[string]any)["search_path"] = []any{"app", nil}
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			body := mutate(t, v.Response, f)
			if pv, err := ParseVerdict(body); err == nil {
				t.Fatalf("ParseVerdict accepted %s: %+v", body, pv)
			}
			fk := newFake(t, replay(200, body))
			c := mustNew(t, fk.srv.URL)
			verdict, err := c.Verify(context.Background(), v.Request.SQL, Context{"tenant_id": "acme"})
			if verdict != nil || !IsKind(err, KindProtocol) {
				t.Fatalf("verdict=%+v err=%v", verdict, err)
			}
		})
	}
	// An empty set and an empty search path are still valid.
	body := mutate(t, v.Response, func(m map[string]any) {
		m["bind_params"] = []any{map[string]any{"param": 1, "value": []any{}}}
		m["policy"].(map[string]any)["search_path"] = []any{}
	})
	pv, err := ParseVerdict(body)
	if err != nil || !pv.BindParams[0].IsSet || pv.BindParams[0].Values == nil || len(pv.BindParams[0].Values) != 0 {
		t.Fatalf("empty set: %+v, %v", pv, err)
	}
}
