package haltsql

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

func utf8Valid(s string) bool { return utf8.ValidString(s) }

// maxSafeInt is 2^53-1: larger integers lose precision in JSON consumers.
const maxSafeInt = 1<<53 - 1

func scalarOK(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		return x, utf8.ValidString(x)
	case int:
		return x, x >= -maxSafeInt && x <= maxSafeInt
	case int32:
		return x, true
	case int64:
		return x, x >= -maxSafeInt && x <= maxSafeInt
	case uint32:
		return x, true
	case float64: // only integral values (e.g. from decoded JSON)
		return int64(x), x == math.Trunc(x) && math.Abs(x) <= maxSafeInt
	case json.Number:
		if i, err := x.Int64(); err == nil && i >= -maxSafeInt && i <= maxSafeInt {
			return i, true
		}
	}
	return nil, false
}

// encodeContext validates the context and returns its JSON encoding.
func encodeContext(c Context) (json.RawMessage, error) {
	out := make(map[string]any, len(c))
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := c[k]
		if s, ok := scalarOK(v); ok {
			out[k] = s
			continue
		}
		var items []any
		switch x := v.(type) {
		case []string:
			for _, e := range x {
				items = append(items, e)
			}
		case []int:
			for _, e := range x {
				items = append(items, e)
			}
		case []int64:
			for _, e := range x {
				items = append(items, e)
			}
		case []any:
			items = x
		default:
			return nil, usageErr("context.%s must be a string, an integer, or a slice of those", k)
		}
		arr := make([]any, 0, len(items))
		for _, e := range items {
			s, ok := scalarOK(e)
			if !ok {
				return nil, usageErr("context.%s must be a string, an integer, or a slice of those", k)
			}
			arr = append(arr, s)
		}
		out[k] = arr
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, usageErr("encoding context: %v", err)
	}
	return b, nil
}

func (v *Verdict) positional() ([]BindParam, error) {
	if v == nil || !v.Allowed {
		return nil, usageErr("refusing to build parameters for a denied verdict")
	}
	n := len(v.BindParams)
	slots := make([]*BindParam, n)
	for i := range v.BindParams {
		bp := &v.BindParams[i]
		if bp.Param < 1 || bp.Param > n {
			return nil, usageErr("bind param $%d is outside $1..$%d; placeholders must be contiguous", bp.Param, n)
		}
		if slots[bp.Param-1] != nil {
			return nil, usageErr("bind param $%d appears more than once", bp.Param)
		}
		slots[bp.Param-1] = bp
	}
	out := make([]BindParam, n)
	for i, p := range slots {
		out[i] = *p
	}
	return out, nil
}

// Args turns BindParams into positional driver arguments: element i is the
// value of $(i+1), a string or (for a set) a []string. With pgx's
// database/sql driver a []string is sent as a Postgres text array.
//
// It fails closed: an error if the verdict is not an allow, or if the params
// are not exactly $1..$n with each number present once.
func (v *Verdict) Args() ([]any, error) {
	ps, err := v.positional()
	if err != nil {
		return nil, err
	}
	out := make([]any, len(ps))
	for i, p := range ps {
		if p.IsSet {
			out[i] = append([]string(nil), p.Values...)
		} else {
			out[i] = p.Value
		}
	}
	return out, nil
}

// ArgsArrayLiteral is like Args but encodes sets as Postgres array literals
// ({"a","b"}), for drivers that cannot encode a []string (e.g. lib/pq).
func (v *Verdict) ArgsArrayLiteral() ([]any, error) {
	ps, err := v.positional()
	if err != nil {
		return nil, err
	}
	out := make([]any, len(ps))
	for i, p := range ps {
		if p.IsSet {
			out[i] = PGArrayLiteral(p.Values)
		} else {
			out[i] = p.Value
		}
	}
	return out, nil
}

// PGArrayLiteral encodes a string slice as a Postgres array literal. Every
// element is double-quoted with `"` and `\` escaped, so it is unambiguous.
func PGArrayLiteral(values []string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		for _, r := range v {
			if r == '"' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}
