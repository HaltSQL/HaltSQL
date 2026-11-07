package haltsql

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorKind classifies an *Error.
type ErrorKind string

const (
	// KindHTTP: the server answered with a non-200 status.
	KindHTTP ErrorKind = "http"
	// KindTransport: the request could not be sent or the connection failed.
	KindTransport ErrorKind = "transport"
	// KindTimeout: an attempt did not finish within the configured timeout.
	KindTimeout ErrorKind = "timeout"
	// KindProtocol: the body is not a valid verdict, or its sql_sha256 does
	// not match the SQL that was sent.
	KindProtocol ErrorKind = "protocol"
	// KindUsage: invalid arguments or options.
	KindUsage ErrorKind = "usage"
)

// Error is returned for every failure except a policy denial. Any Error
// means deny: the SQL must not run.
type Error struct {
	Kind ErrorKind
	// Status is the HTTP status for KindHTTP, else 0.
	Status int
	// Code is error.code from the body (e.g. "UNAUTHORIZED"), or "HTTP_<status>".
	Code string
	// Message is a human-readable description. It never contains the token.
	Message string
	// RequestID is the X-Request-Id of the last attempt, when known.
	RequestID string
	// Err is the underlying cause, if any.
	Err error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("haltsql: ")
	switch e.Kind {
	case KindHTTP:
		fmt.Fprintf(&b, "HTTP %d %s: %s", e.Status, e.Code, e.Message)
	default:
		fmt.Fprintf(&b, "%s error: %s", e.Kind, e.Message)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Allowed always returns false: an error is never an allow.
func (e *Error) Allowed() bool { return false }

// DeniedError is returned by GuardedQuery and GuardedExec when the policy
// denies the SQL. Nothing was sent to the database.
type DeniedError struct {
	Verdict *Verdict
}

func (e *DeniedError) Error() string {
	codes := strings.Join(e.Verdict.Codes(), ", ")
	if codes == "" {
		codes = "no reasons"
	}
	return fmt.Sprintf("haltsql: denied by policy %s: %s", e.Verdict.Policy.Name, codes)
}

// Allowed always returns false.
func (e *DeniedError) Allowed() bool { return false }

// IsDenied reports whether err is (or wraps) a *DeniedError.
func IsDenied(err error) bool {
	var d *DeniedError
	return errors.As(err, &d)
}

// IsKind reports whether err is (or wraps) an *Error of the given kind.
func IsKind(err error, k ErrorKind) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == k
}

func usageErr(format string, a ...any) error {
	return &Error{Kind: KindUsage, Message: fmt.Sprintf(format, a...)}
}
