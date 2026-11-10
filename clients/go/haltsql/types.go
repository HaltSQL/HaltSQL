package haltsql

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Context holds values from the caller's authenticated session (tenant id,
// user id, ...). Values must be strings, integers, or slices of those
// ([]string, []int, []int64, []any of strings/integers). Never take them from
// the prompt or from the SQL.
type Context map[string]any

// Reason is one reason a statement was (or in shadow mode would have been)
// denied. Match on Code, never on Message.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Rule    string `json:"rule"`
	// Loc is the byte offset into the SQL string, or nil when unknown.
	Loc *int `json:"loc,omitempty"`
	// Hint is a short instruction an LLM agent can follow.
	Hint string `json:"hint,omitempty"`
}

// BindParam is a value the caller must bind to placeholder $Param.
// Exactly one of Value (scalar) or Values (set) is meaningful: IsSet tells which.
type BindParam struct {
	Param  int
	Value  string
	Values []string
	IsSet  bool
}

// UnmarshalJSON accepts {"param": n, "value": "s" | ["a", ...]}.
func (b *BindParam) UnmarshalJSON(data []byte) error {
	var raw struct {
		Param *int            `json:"param"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Param == nil || *raw.Param < 1 {
		return errors.New("bind_params[].param must be an integer >= 1")
	}
	b.Param = *raw.Param
	var s string
	if err := json.Unmarshal(raw.Value, &s); err == nil && len(raw.Value) > 0 && raw.Value[0] == '"' {
		b.Value, b.IsSet = s, false
		return nil
	}
	var arr []*string
	if len(raw.Value) > 0 && raw.Value[0] == '[' {
		if err := json.Unmarshal(raw.Value, &arr); err == nil {
			// A JSON null element must not be bound as an empty string.
			if vals, ok := nonNullStrings(arr); ok {
				b.Values, b.IsSet = vals, true
				return nil
			}
		}
	}
	return fmt.Errorf("bind_params[$%d].value must be a string or an array of strings", b.Param)
}

// MarshalJSON writes the wire form.
func (b BindParam) MarshalJSON() ([]byte, error) {
	if b.IsSet {
		return json.Marshal(struct {
			Param int      `json:"param"`
			Value []string `json:"value"`
		}{b.Param, b.Values})
	}
	return json.Marshal(struct {
		Param int    `json:"param"`
		Value string `json:"value"`
	}{b.Param, b.Value})
}

// PolicyRef identifies the policy that produced a verdict.
type PolicyRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// SearchPath lists the schemas unqualified names were resolved against
	// (nil from an engine that does not report it). The verdict holds only if
	// the session that runs the SQL uses this search path.
	SearchPath []string `json:"search_path,omitempty"`
}

// Verdict is the result of verifying one SQL string.
type Verdict struct {
	// Allowed is true only if the caller may run this exact SQL string.
	Allowed bool     `json:"allowed"`
	Reasons []Reason `json:"reasons"`
	// ShadowReasons lists, in shadow mode, why the SQL would have been denied.
	ShadowReasons []Reason  `json:"shadow_reasons"`
	Policy        PolicyRef `json:"policy"`
	// StatementKind is "select", "insert", "update", "delete", or "" (JSON null).
	StatementKind string      `json:"statement_kind"`
	Tables        []string    `json:"tables"`
	Columns       []string    `json:"columns"`
	BindParams    []BindParam `json:"bind_params"`
	// Fingerprint is "" when the SQL did not parse (JSON null).
	Fingerprint string `json:"fingerprint"`
	SQLSHA256   string `json:"sql_sha256"`
	ElapsedUS   int64  `json:"elapsed_us"`
}

// Codes returns the reason codes in server order.
func (v *Verdict) Codes() []string {
	out := make([]string, len(v.Reasons))
	for i, r := range v.Reasons {
		out[i] = r.Code
	}
	return out
}

// PolicySummary is one entry of GET /v1/policies.
type PolicySummary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

// HealthStatus is the body of GET /healthz.
type HealthStatus struct {
	Status string `json:"status"`
}

// ReadyStatus is the result of GET /readyz. Ready is true only on HTTP 200
// with status "ready".
type ReadyStatus struct {
	Ready    bool
	Status   string
	Policies int
}

var (
	reasonCodeRE = regexp.MustCompile(`^E_[A-Z_]+$`)
	hex64RE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// wireVerdict mirrors the JSON with pointers so missing fields are detected.
type wireVerdict struct {
	Allowed       *bool         `json:"allowed"`
	Reasons       *[]wireReason `json:"reasons"`
	ShadowReasons *[]wireReason `json:"shadow_reasons"`
	Policy        *struct {
		Name       *string   `json:"name"`
		Version    *string   `json:"version"`
		SearchPath []*string `json:"search_path"`
	} `json:"policy"`
	StatementKind json.RawMessage `json:"statement_kind"`
	Tables        *[]*string      `json:"tables"`
	Columns       *[]*string      `json:"columns"`
	BindParams    *[]BindParam    `json:"bind_params"`
	Fingerprint   json.RawMessage `json:"fingerprint"`
	SQLSHA256     *string         `json:"sql_sha256"`
	ElapsedUS     *int64          `json:"elapsed_us"`
}

type wireReason struct {
	Code    *string `json:"code"`
	Message *string `json:"message"`
	Rule    *string `json:"rule"`
	Loc     *int    `json:"loc"`
	Hint    *string `json:"hint"`
}

// nonNullStrings converts a decoded JSON array of strings, refusing null
// elements (encoding/json would otherwise turn them into "").
func nonNullStrings(in []*string) ([]string, bool) {
	out := make([]string, len(in))
	for i, p := range in {
		if p == nil {
			return nil, false
		}
		out[i] = *p
	}
	return out, true
}

func nullableString(raw json.RawMessage, field string) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("%s is missing", field)
	}
	if string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%s must be a string or null", field)
	}
	return s, nil
}

func convReasons(in *[]wireReason, field string) ([]Reason, error) {
	if in == nil {
		return nil, fmt.Errorf("%s is missing", field)
	}
	out := make([]Reason, 0, len(*in))
	for i, r := range *in {
		if r.Code == nil || r.Message == nil || r.Rule == nil {
			return nil, fmt.Errorf("%s[%d] needs code, message and rule", field, i)
		}
		if !reasonCodeRE.MatchString(*r.Code) {
			return nil, fmt.Errorf("%s[%d].code is not a reason code", field, i)
		}
		if r.Loc != nil && *r.Loc < 0 {
			return nil, fmt.Errorf("%s[%d].loc must be >= 0", field, i)
		}
		rr := Reason{Code: *r.Code, Message: *r.Message, Rule: *r.Rule, Loc: r.Loc}
		if r.Hint != nil {
			rr.Hint = *r.Hint
		}
		out = append(out, rr)
	}
	return out, nil
}

// ParseVerdict strictly decodes and validates a verdict body. Any missing or
// mistyped field, or an allow that carries reasons, is an error. Unknown
// extra fields are ignored.
func ParseVerdict(body []byte) (*Verdict, error) {
	var w wireVerdict
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("verdict is not valid JSON of the expected shape: %v", err)
	}
	if w.Allowed == nil {
		return nil, errors.New("allowed is missing")
	}
	reasons, err := convReasons(w.Reasons, "reasons")
	if err != nil {
		return nil, err
	}
	shadow, err := convReasons(w.ShadowReasons, "shadow_reasons")
	if err != nil {
		return nil, err
	}
	if w.Policy == nil || w.Policy.Name == nil || w.Policy.Version == nil {
		return nil, errors.New("policy.name and policy.version are required")
	}
	kind, err := nullableString(w.StatementKind, "statement_kind")
	if err != nil {
		return nil, err
	}
	fp, err := nullableString(w.Fingerprint, "fingerprint")
	if err != nil {
		return nil, err
	}
	if w.Tables == nil || w.Columns == nil || w.BindParams == nil {
		return nil, errors.New("tables, columns and bind_params are required")
	}
	tables, ok1 := nonNullStrings(*w.Tables)
	columns, ok2 := nonNullStrings(*w.Columns)
	if !ok1 || !ok2 {
		return nil, errors.New("tables and columns must be arrays of strings")
	}
	var searchPath []string
	if w.Policy.SearchPath != nil {
		sp, ok := nonNullStrings(w.Policy.SearchPath)
		if !ok {
			return nil, errors.New("policy.search_path must be an array of strings")
		}
		searchPath = sp
	}
	if w.SQLSHA256 == nil || !hex64RE.MatchString(*w.SQLSHA256) {
		return nil, errors.New("sql_sha256 must be 64 lower-case hex digits")
	}
	if w.ElapsedUS == nil || *w.ElapsedUS < 0 {
		return nil, errors.New("elapsed_us must be a non-negative integer")
	}
	if *w.Allowed && len(reasons) > 0 {
		return nil, errors.New("allowed is true but reasons is not empty")
	}
	return &Verdict{
		Allowed:       *w.Allowed,
		Reasons:       reasons,
		ShadowReasons: shadow,
		Policy:        PolicyRef{Name: *w.Policy.Name, Version: *w.Policy.Version, SearchPath: searchPath},
		StatementKind: kind,
		Tables:        tables,
		Columns:       columns,
		BindParams:    *w.BindParams,
		Fingerprint:   fp,
		SQLSHA256:     *w.SQLSHA256,
		ElapsedUS:     *w.ElapsedUS,
	}, nil
}
