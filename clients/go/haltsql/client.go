package haltsql

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the SDK version, sent in the User-Agent header.
const Version = "0.0.3"

// Client talks to one haltsql-server. It is safe for concurrent use; create
// one per sidecar and share it so keep-alive connections are reused.
type Client struct {
	baseURL      string
	token        string
	hc           *http.Client
	timeout      time.Duration
	maxRetries   int
	baseDelay    time.Duration
	maxDelay     time.Duration
	maxBody      int64
	checkSQLHash bool
}

// Option configures a Client.
type Option func(*Client) error

// WithToken sets the bearer token sent to /v1/*. It must be visible ASCII.
func WithToken(token string) Option {
	return func(c *Client) error {
		if token == "" {
			return usageErr("token must not be empty")
		}
		for i := 0; i < len(token); i++ {
			if token[i] < 0x21 || token[i] > 0x7e {
				return usageErr("token must be visible ASCII")
			}
		}
		c.token = token
		return nil
	}
}

// WithTimeout sets the per-attempt timeout (default 5s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return usageErr("timeout must be positive")
		}
		c.timeout = d
		return nil
	}
}

// WithRetries sets how many times a request is retried after the first
// attempt on 503, connection errors and timeouts (default 2), and the backoff
// bounds (default 100ms doubling, capped at 2s, full jitter).
func WithRetries(maxRetries int, baseDelay, maxDelay time.Duration) Option {
	return func(c *Client) error {
		if maxRetries < 0 || baseDelay < 0 || maxDelay < 0 {
			return usageErr("retry settings must be non-negative")
		}
		c.maxRetries, c.baseDelay, c.maxDelay = maxRetries, baseDelay, maxDelay
		return nil
	}
}

// WithHTTPClient uses a custom *http.Client (for a custom transport or TLS).
// It is copied; redirects are never followed regardless of its settings.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) error {
		if h == nil {
			return usageErr("http client must not be nil")
		}
		cp := *h
		c.hc = &cp
		return nil
	}
}

// WithTLSConfig sets the TLS configuration used to reach an https sidecar:
// RootCAs for a private CA, Certificates for mutual TLS, ServerName, and so
// on. The config is cloned. It replaces the transport with a clone of
// http.DefaultTransport (keep-alive pooling, proxy from the environment)
// using this config, so apply it after WithHTTPClient if you use both.
// Certificate verification stays on unless cfg.InsecureSkipVerify is set,
// which this option refuses.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *Client) error {
		if cfg == nil {
			return usageErr("tls config must not be nil")
		}
		if cfg.InsecureSkipVerify {
			return usageErr("tls config must not set InsecureSkipVerify")
		}
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return usageErr("http.DefaultTransport is not an *http.Transport")
		}
		t := base.Clone()
		t.TLSClientConfig = cfg.Clone()
		if c.hc == nil {
			c.hc = &http.Client{}
		}
		c.hc.Transport = t
		return nil
	}
}

// WithMaxResponseBytes caps the response body size (default 8 MiB).
func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) error {
		if n <= 0 {
			return usageErr("max response bytes must be positive")
		}
		c.maxBody = n
		return nil
	}
}

// WithoutSQLHashCheck disables the check that verdict.sql_sha256 equals the
// SHA-256 of the SQL that was sent. Only for servers that do not echo it.
func WithoutSQLHashCheck() Option {
	return func(c *Client) error { c.checkSQLHash = false; return nil }
}

// New returns a client for the sidecar at baseURL (e.g. http://127.0.0.1:8080).
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, usageErr("baseURL must be an absolute http or https URL")
	}
	if u.User != nil {
		return nil, usageErr("baseURL must not contain credentials; use WithToken")
	}
	c := &Client{
		baseURL:      strings.TrimRight(u.String(), "/"),
		hc:           &http.Client{},
		timeout:      5 * time.Second,
		maxRetries:   2,
		baseDelay:    100 * time.Millisecond,
		maxDelay:     2 * time.Second,
		maxBody:      8 << 20,
		checkSQLHash: true,
	}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	c.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, nil
}

// VerifyOption configures one Verify call.
type VerifyOption func(*verifyOpts)

type verifyOpts struct {
	policy    string
	requestID string
}

// WithPolicy names the policy; with a token it must equal the pinned policy.
func WithPolicy(name string) VerifyOption { return func(o *verifyOpts) { o.policy = name } }

// WithRequestID sends X-Request-Id to correlate with server logs.
func WithRequestID(id string) VerifyOption { return func(o *verifyOpts) { o.requestID = id } }

// Verify checks one SQL string. It returns a verdict (allowed or denied) only
// for a valid HTTP 200 answer; every other outcome is an *Error. Run the SQL
// only when err == nil && verdict.Allowed.
func (c *Client) Verify(ctx context.Context, sqlText string, vctx Context, opts ...VerifyOption) (*Verdict, error) {
	var o verifyOpts
	for _, f := range opts {
		f(&o)
	}
	ctxJSON, err := encodeContext(vctx)
	if err != nil {
		return nil, err
	}
	if !utf8Valid(sqlText) {
		return nil, usageErr("sql must be valid UTF-8")
	}
	if o.requestID != "" && !validRequestID(o.requestID) {
		return nil, usageErr("request id must be at most 200 printable ASCII characters")
	}
	req := struct {
		SQL     string          `json:"sql"`
		Context json.RawMessage `json:"context"`
		Policy  string          `json:"policy,omitempty"`
	}{sqlText, ctxJSON, o.policy}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, usageErr("encoding request: %v", err)
	}
	res, err := c.do(ctx, http.MethodPost, "/v1/verify", body, true, true, o.requestID)
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, httpError(res)
	}
	v, err := ParseVerdict(res.body)
	if err != nil {
		return nil, &Error{Kind: KindProtocol, Message: err.Error(), RequestID: res.requestID}
	}
	if c.checkSQLHash {
		sum := sha256.Sum256([]byte(sqlText))
		want := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(want), []byte(v.SQLSHA256)) != 1 {
			return nil, &Error{Kind: KindProtocol, Message: "sql_sha256 does not match the SQL that was sent", RequestID: res.requestID}
		}
	}
	return v, nil
}

// Health calls GET /healthz and fails unless the answer is 200.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	res, err := c.do(ctx, http.MethodGet, "/healthz", nil, false, true, "")
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, httpError(res)
	}
	var h HealthStatus
	if err := json.Unmarshal(res.body, &h); err != nil || h.Status == "" {
		return nil, &Error{Kind: KindProtocol, Message: "healthz body has no status", RequestID: res.requestID}
	}
	return &h, nil
}

// Ready calls GET /readyz. A 503 not-ready answer is returned as
// Ready == false (and is not retried); other statuses are errors.
func (c *Client) Ready(ctx context.Context) (*ReadyStatus, error) {
	res, err := c.do(ctx, http.MethodGet, "/readyz", nil, false, false, "")
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK && res.status != http.StatusServiceUnavailable {
		return nil, httpError(res)
	}
	var b struct {
		Status   string `json:"status"`
		Policies int    `json:"policies"`
	}
	if err := json.Unmarshal(res.body, &b); err != nil || b.Status == "" {
		return nil, &Error{Kind: KindProtocol, Message: "readyz body has no status", RequestID: res.requestID}
	}
	return &ReadyStatus{Ready: res.status == http.StatusOK && b.Status == "ready", Status: b.Status, Policies: b.Policies}, nil
}

// Policies calls GET /v1/policies: the policies this caller may use.
func (c *Client) Policies(ctx context.Context) ([]PolicySummary, error) {
	res, err := c.do(ctx, http.MethodGet, "/v1/policies", nil, true, true, "")
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, httpError(res)
	}
	var b struct {
		Policies *[]struct {
			Name    *string `json:"name"`
			Version *string `json:"version"`
			Mode    *string `json:"mode"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(res.body, &b); err != nil || b.Policies == nil {
		return nil, &Error{Kind: KindProtocol, Message: "policies must be an array", RequestID: res.requestID}
	}
	out := make([]PolicySummary, 0, len(*b.Policies))
	for i, p := range *b.Policies {
		if p.Name == nil || p.Version == nil || p.Mode == nil {
			return nil, &Error{Kind: KindProtocol, Message: fmt.Sprintf("policies[%d] needs name, version and mode", i), RequestID: res.requestID}
		}
		out = append(out, PolicySummary{Name: *p.Name, Version: *p.Version, Mode: *p.Mode})
	}
	return out, nil
}

type rawResponse struct {
	status     int
	body       []byte
	requestID  string
	retryAfter time.Duration
	hasRetry   bool
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, auth, retry bool, requestID string) (*rawResponse, error) {
	attempts := 1
	if retry {
		attempts += c.maxRetries
	}
	var last error
	var lastRes *rawResponse
	for i := 0; i < attempts; i++ {
		if i > 0 {
			delay := c.backoff(i)
			if lastRes != nil && lastRes.hasRetry {
				delay = min(lastRes.retryAfter, c.maxDelay)
			}
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, &Error{Kind: KindTransport, Message: "canceled: " + ctx.Err().Error(), Err: ctx.Err()}
			case <-t.C:
			}
		}
		res, err := c.once(ctx, method, path, body, auth, requestID)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			if IsKind(err, KindTransport) || IsKind(err, KindTimeout) {
				last, lastRes = err, nil
				continue
			}
			return nil, err
		}
		if res.status == http.StatusServiceUnavailable && i+1 < attempts {
			last, lastRes = httpError(res), res
			continue
		}
		return res, nil
	}
	if last == nil {
		last = &Error{Kind: KindTransport, Message: "no attempt was made"}
	}
	return nil, last
}

func (c *Client) backoff(attempt int) time.Duration {
	capd := c.baseDelay << (attempt - 1)
	if capd > c.maxDelay || capd <= 0 {
		capd = c.maxDelay
	}
	if capd <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(capd) + 1))
}

func (c *Client) once(ctx context.Context, method, path string, body []byte, auth bool, requestID string) (*rawResponse, error) {
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(actx, method, c.baseURL+path, rd)
	if err != nil {
		return nil, usageErr("building request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "haltsql-client-go/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth && c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, c.classify(ctx, actx, err)
	}
	defer resp.Body.Close()
	rid := resp.Header.Get("X-Request-Id")
	if resp.ContentLength > c.maxBody {
		return nil, &Error{Kind: KindProtocol, Message: fmt.Sprintf("response larger than %d bytes", c.maxBody), RequestID: rid}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, c.classify(ctx, actx, err)
	}
	if int64(len(data)) > c.maxBody {
		return nil, &Error{Kind: KindProtocol, Message: fmt.Sprintf("response larger than %d bytes", c.maxBody), RequestID: rid}
	}
	out := &rawResponse{status: resp.StatusCode, body: data, requestID: rid}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if n, err := strconv.Atoi(ra); err == nil && n >= 0 && n < 1_000_000 {
			out.retryAfter, out.hasRetry = time.Duration(n)*time.Second, true
		}
	}
	return out, nil
}

func (c *Client) classify(parent, attempt context.Context, err error) error {
	if parent.Err() != nil {
		return &Error{Kind: KindTransport, Message: "canceled: " + parent.Err().Error(), Err: parent.Err()}
	}
	if errors.Is(attempt.Err(), context.DeadlineExceeded) {
		return &Error{Kind: KindTimeout, Message: fmt.Sprintf("request timed out after %s", c.timeout), Err: err}
	}
	// *url.Error includes the URL (never the token) and the cause.
	return &Error{Kind: KindTransport, Message: err.Error(), Err: err}
}

func httpError(res *rawResponse) *Error {
	e := &Error{Kind: KindHTTP, Status: res.status, Code: fmt.Sprintf("HTTP_%d", res.status), Message: "unexpected status", RequestID: res.requestID}
	var b struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(res.body, &b) == nil {
		if b.Error.Code != "" {
			e.Code = b.Error.Code
		}
		if b.Error.Message != "" {
			m := b.Error.Message
			if len(m) > 500 {
				m = m[:500]
			}
			e.Message = m
		}
	}
	return e
}

func validRequestID(id string) bool {
	if len(id) > 200 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] > 0x7e {
			return false
		}
	}
	return true
}
