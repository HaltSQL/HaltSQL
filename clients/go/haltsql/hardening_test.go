package haltsql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
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
