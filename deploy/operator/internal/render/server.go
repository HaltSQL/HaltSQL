/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	haltsqlv1alpha1 "github.com/HaltSQL/HaltSQL/deploy/operator/api/v1alpha1"
)

// MaxConfigBytes keeps the rendered ConfigMap below the 1 MiB object limit
// with room for metadata.
const MaxConfigBytes = 900 * 1024

// PolicyInput is one referenced HaltSQLPolicy, in spec.policies order.
type PolicyInput struct {
	// Ref is the HaltSQLPolicy name.
	Ref  string
	Spec *haltsqlv1alpha1.HaltSQLPolicySpec
}

// Rendered is everything the server controller writes.
type Rendered struct {
	// Data is the ConfigMap content: config.yaml and one file per inline policy.
	Data map[string]string
	// Secrets are the Secret keys to mount (sorted, unique).
	Secrets []SecretRef
	// TLSSecret is the kubernetes.io/tls Secret to mount, if any.
	TLSSecret string
	// HealthPort is true when probes use the plain-HTTP health listener.
	HealthPort bool
	// Checksum covers Data, Secrets and TLSSecret; it is put on the pod
	// template so any change rolls the pods.
	Checksum string
	// Applied lists the policies and content hashes in Data.
	Applied []haltsqlv1alpha1.AppliedPolicy
}

// PolicyFile is the ConfigMap key holding the inline policy of HaltSQLPolicy ref.
func PolicyFile(ref, ext string) string { return "policy-" + ref + ext }

// Server renders the Config document and policy files for srv. It fails on
// anything that would make haltsql-server refuse to start and that can be
// decided without the referenced Secrets' values.
func Server(srv *haltsqlv1alpha1.HaltSQLServer, policies []PolicyInput) (*Rendered, error) {
	return renderServer(srv, policies, ForServer)
}

// ServerValidationDocument renders the server's Config document with inline
// policies and dummy secret values so `haltsql validate` can check the full
// configuration (including free-form JSON sections) without mounted Secrets.
func ServerValidationDocument(srv *haltsqlv1alpha1.HaltSQLServer, policies []PolicyInput) ([]byte, error) {
	rd, err := renderServer(srv, policies, ForValidation)
	if err != nil {
		return nil, err
	}
	return []byte(rd.Data[ConfigFile]), nil
}

func renderServer(srv *haltsqlv1alpha1.HaltSQLServer, policies []PolicyInput, mode Mode) (*Rendered, error) {
	var secrets []SecretRef
	data := map[string]string{}
	out := &Rendered{}

	// Policies.
	var entries []any
	names := map[string]string{} // policy name -> HaltSQLPolicy
	var prefixes []string
	bundles, unprefixed := 0, 0
	for _, p := range policies {
		hash, err := ContentHash(p.Spec)
		if err != nil {
			return nil, fmt.Errorf("HaltSQLPolicy %s: %w", p.Ref, err)
		}
		switch {
		case p.Spec.Policy != "":
			pc, err := InlinePolicy(p.Spec.Policy)
			if err != nil {
				return nil, fmt.Errorf("HaltSQLPolicy %s: %w", p.Ref, err)
			}
			if other, dup := names[pc.Name]; dup {
				return nil, fmt.Errorf("HaltSQLPolicies %s and %s both define policy %q", other, p.Ref, pc.Name)
			}
			names[pc.Name] = p.Ref
			file := PolicyFile(p.Ref, pc.Ext)
			data[file] = string(pc.Body)
			if mode == ForValidation {
				var inlineDoc map[string]any
				if err := yaml.Unmarshal(pc.Body, &inlineDoc); err != nil {
					return nil, fmt.Errorf("HaltSQLPolicy %s: %w", p.Ref, err)
				}
				entries = append(entries, map[string]any{"inline": inlineDoc})
			} else {
				entries = append(entries, map[string]any{"path": ConfigDir + "/" + file})
			}
		case p.Spec.BundleSource != nil:
			entry, refs, err := BundleEntry(p.Spec.BundleSource, mode)
			if err != nil {
				return nil, fmt.Errorf("HaltSQLPolicy %s: %w", p.Ref, err)
			}
			entry["cache_dir"] = BundleCacheDir + "/" + p.Ref
			secrets = append(secrets, refs...)
			entries = append(entries, entry)
			bundles++
			if p.Spec.BundleSource.NamePrefix == "" {
				unprefixed++
			} else {
				prefixes = append(prefixes, p.Spec.BundleSource.NamePrefix)
			}
		default:
			return nil, fmt.Errorf("HaltSQLPolicy %s: exactly one of spec.policy or spec.bundleSource is required", p.Ref)
		}
		out.Applied = append(out.Applied, haltsqlv1alpha1.AppliedPolicy{Name: p.Ref, ContentHash: hash})
	}
	if len(entries) == 0 {
		return nil, errors.New("spec.policies must reference at least one HaltSQLPolicy")
	}
	// A policy reference must resolve to an inline policy, or (when bundles
	// are loaded) possibly to a bundle policy; with prefixes on every bundle
	// it must carry one of them. haltsql-server re-checks after loading.
	resolves := func(name string) bool {
		if _, ok := names[name]; ok {
			return true
		}
		if bundles == 0 {
			return false
		}
		if unprefixed > 0 {
			return true
		}
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}

	cfg := srv.Spec.Config
	server := map[string]any{"listen": "0.0.0.0:" + strconv.Itoa(ListenPort)}
	auth := map[string]any{"allow_unauthenticated": cfg.AllowUnauthenticated}

	if a := srv.Spec.Auth; a != nil {
		if len(a.Tokens) > 0 {
			tokens := make([]any, 0, len(a.Tokens))
			seen := map[string]bool{}
			for i, t := range a.Tokens {
				if seen[t.Name] {
					return nil, fmt.Errorf("spec.auth.tokens[%d]: duplicate token name %q", i, t.Name)
				}
				seen[t.Name] = true
				if !resolves(t.Policy) {
					return nil, fmt.Errorf("spec.auth.tokens[%d] (%s): policy %q is not defined by any referenced HaltSQLPolicy", i, t.Name, t.Policy)
				}
				r := SecretRef{Name: t.SHA256SecretRef.Name, Key: t.SHA256SecretRef.Key}
				if err := checkSecretRef(r); err != nil {
					return nil, fmt.Errorf("spec.auth.tokens[%d].sha256SecretRef: %w", i, err)
				}
				secrets = append(secrets, r)
				tokenSHA256 := r.Placeholder()
				if mode == ForValidation {
					sum := sha256.Sum256([]byte(fmt.Sprintf("operator-validation-token-%d", i)))
					tokenSHA256 = hex.EncodeToString(sum[:])
				}
				entry := map[string]any{
					"name":         t.Name,
					"token_sha256": tokenSHA256,
					"policy":       t.Policy,
				}
				if len(t.Context) > 0 {
					ctx, err := tokenContext(t.Context)
					if err != nil {
						return nil, fmt.Errorf("spec.auth.tokens[%d].context%w", i, err)
					}
					entry["context"] = ctx
				}
				// An empty list is kept: it binds the token and lets the
				// body add nothing.
				if t.RequestContextFields != nil {
					fields := make([]any, 0, len(t.RequestContextFields))
					for _, f := range t.RequestContextFields {
						if !contextField.MatchString(f) {
							return nil, fmt.Errorf("spec.auth.tokens[%d].requestContextFields: invalid context field %q", i, f)
						}
						if _, fixed := t.Context[f]; fixed {
							return nil, fmt.Errorf("spec.auth.tokens[%d].requestContextFields: %q is already fixed by context", i, f)
						}
						fields = append(fields, f)
					}
					entry["request_context_fields"] = fields
				}
				tokens = append(tokens, entry)
			}
			auth["tokens"] = tokens
		}
		if len(a.OIDC) > 0 {
			list := make([]any, 0, len(a.OIDC))
			for i := range a.OIDC {
				v, refs, err := rawObject(&a.OIDC[i], fmt.Sprintf("spec.auth.oidc[%d]", i), mode)
				if err != nil {
					return nil, err
				}
				secrets = append(secrets, refs...)
				list = append(list, v)
			}
			auth["oidc"] = list
		}
		if a.MTLS != nil && len(a.MTLS.Identities) > 0 {
			list := make([]any, 0, len(a.MTLS.Identities))
			for i := range a.MTLS.Identities {
				v, refs, err := rawObject(&a.MTLS.Identities[i], fmt.Sprintf("spec.auth.mtls.identities[%d]", i), mode)
				if err != nil {
					return nil, err
				}
				secrets = append(secrets, refs...)
				list = append(list, v)
			}
			auth["mtls"] = map[string]any{"identities": list}
		}
	}
	server["auth"] = auth

	if t := srv.Spec.TLS; t != nil {
		if !isDNSSubdomain(t.SecretName) {
			return nil, fmt.Errorf("spec.tls.secretName %q is not a valid Secret name", t.SecretName)
		}
		tls := map[string]any{
			"cert": TLSDir + "/tls.crt",
			"key":  TLSDir + "/tls.key",
		}
		ca := t.ClientAuth
		if ca == "" {
			ca = "none"
		}
		if ca != "none" {
			tls["client_ca"] = TLSDir + "/ca.crt"
		}
		tls["client_auth"] = ca
		if t.MinVersion != "" {
			tls["min_version"] = t.MinVersion
		}
		server["tls"] = tls
		out.TLSSecret = t.SecretName
		out.HealthPort = true
	} else if a := srv.Spec.Auth; a != nil && a.MTLS != nil && len(a.MTLS.Identities) > 0 {
		return nil, errors.New("spec.auth.mtls.identities need spec.tls with clientAuth optional or required")
	}

	if cfg.Admin != nil {
		v, refs, err := rawObject(cfg.Admin, "spec.config.admin", mode)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, refs...)
		server["admin"] = v
	}

	doc := map[string]any{
		"apiVersion": documentVersion,
		"kind":       "Config",
		"server":     server,
		"policies":   entries,
		// The operator rolls pods on every change (checksum annotation), so
		// file watching would only race the rollout.
		"reload": map[string]any{"watch": false},
	}
	if cfg.DefaultPolicy != "" {
		if !resolves(cfg.DefaultPolicy) {
			return nil, fmt.Errorf("spec.config.defaultPolicy %q is not defined by any referenced HaltSQLPolicy", cfg.DefaultPolicy)
		}
		doc["default_policy"] = cfg.DefaultPolicy
	}

	audit := map[string]any{"log_raw_sql": false}
	sinks := []any{map[string]any{"type": "stdout"}}
	if au := srv.Spec.Audit; au != nil {
		audit["log_raw_sql"] = au.LogRawSQL
		if len(au.Sinks) > 0 {
			sinks = sinks[:0]
			for i := range au.Sinks {
				v, refs, err := rawObject(&au.Sinks[i], fmt.Sprintf("spec.audit.sinks[%d]", i), mode)
				if err != nil {
					return nil, err
				}
				if _, ok := v.(map[string]any)["type"].(string); !ok {
					return nil, fmt.Errorf("spec.audit.sinks[%d]: type must be a string", i)
				}
				secrets = append(secrets, refs...)
				sinks = append(sinks, v)
			}
		}
	}
	audit["sinks"] = sinks
	doc["audit"] = audit

	logging := map[string]any{}
	if cfg.LogLevel != "" {
		logging["level"] = cfg.LogLevel
	}
	if cfg.LogFormat != "" {
		logging["format"] = cfg.LogFormat
	}
	if len(logging) > 0 {
		doc["logging"] = logging
	}
	if cfg.MaxRequestBytes != nil {
		doc["limits"] = map[string]any{"max_request_bytes": *cfg.MaxRequestBytes}
	}
	for _, sec := range []struct {
		key string
		raw *apiextensionsv1.JSON
	}{{"telemetry", cfg.Telemetry}, {"opa", cfg.OPA}, {"secrets", cfg.Secrets}} {
		if sec.raw == nil {
			continue
		}
		v, refs, err := rawObject(sec.raw, "spec.config."+sec.key, mode)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, refs...)
		doc[sec.key] = v
	}

	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("rendering config: %w", err)
	}
	header := fmt.Sprintf("# Generated by haltsql-operator for HaltSQLServer %s/%s. Do not edit:\n# changes are overwritten on the next reconcile.\n", srv.Namespace, srv.Name)
	data[ConfigFile] = header + string(body)

	total := 0
	for k, v := range data {
		total += len(k) + len(v)
	}
	if total > MaxConfigBytes {
		return nil, fmt.Errorf("rendered configuration is %d bytes, above the %d byte limit of a ConfigMap; use a bundleSource for large policies", total, MaxConfigBytes)
	}

	out.Data = data
	out.Secrets = dedupeRefs(secrets)
	out.Checksum = checksum(out)
	return out, nil
}

// contextField is a haltsql context field name.
var contextField = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// tokenContext decodes a token's fixed context. haltsql accepts a string, an
// integer or a non-empty list of them per field; anything else is refused
// here so the error names the field. The returned error text starts with
// the path below `context`.
func tokenContext(raw map[string]apiextensionsv1.JSON) (map[string]any, error) {
	scalar := func(v any) bool {
		switch t := v.(type) {
		case string:
			return true
		case json.Number:
			_, err := strconv.ParseInt(t.String(), 10, 64)
			return err == nil
		default:
			return false
		}
	}
	out := make(map[string]any, len(raw))
	for k, r := range raw {
		if !contextField.MatchString(k) {
			return nil, fmt.Errorf(": invalid context field %q", k)
		}
		dec := json.NewDecoder(bytes.NewReader(r.Raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf(".%s: %v", k, err)
		}
		switch t := v.(type) {
		case []any:
			if len(t) == 0 {
				return nil, fmt.Errorf(".%s: must not be empty", k)
			}
			for _, e := range t {
				if !scalar(e) {
					return nil, fmt.Errorf(".%s: list items must be strings or integers", k)
				}
			}
		default:
			if !scalar(v) {
				return nil, fmt.Errorf(".%s: must be a string, an integer or a list of them", k)
			}
		}
		out[k] = v
	}
	return out, nil
}

func checksum(r *Rendered) string {
	h := sha256.New()
	keys := make([]string, 0, len(r.Data))
	for k := range r.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "data\x00%s\x00%d\x00", k, len(r.Data[k]))
		h.Write([]byte(r.Data[k]))
	}
	for _, s := range r.Secrets {
		fmt.Fprintf(h, "secret\x00%s\x00%s\x00", s.Name, s.Key)
	}
	fmt.Fprintf(h, "tls\x00%s\x00%t", r.TLSSecret, r.HealthPort)
	return hex.EncodeToString(h.Sum(nil))
}

// rawObject decodes a free-form section (it must be a JSON object) and
// replaces every {secretKeyRef: {name, key}} object by a ${file:...}
// placeholder for the mounted key (or a dummy string when validating).
func rawObject(raw *apiextensionsv1.JSON, path string, mode Mode) (any, []SecretRef, error) {
	if raw == nil || len(raw.Raw) == 0 {
		return nil, nil, fmt.Errorf("%s: must be an object", path)
	}
	dec := json.NewDecoder(bytes.NewReader(raw.Raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, fmt.Errorf("%s: %v", path, err)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, nil, fmt.Errorf("%s: must be an object", path)
	}
	var refs []SecretRef
	out, err := substitute(v, path, &refs, mode)
	if err != nil {
		return nil, nil, err
	}
	return out, refs, nil
}

func substitute(v any, path string, refs *[]SecretRef, mode Mode) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		if ref, ok := t["secretKeyRef"]; ok {
			if len(t) != 1 {
				return nil, fmt.Errorf("%s: an object with secretKeyRef must have no other keys", path)
			}
			m, ok := ref.(map[string]any)
			if !ok || len(m) != 2 {
				return nil, fmt.Errorf("%s.secretKeyRef: must be {name, key}", path)
			}
			name, ok1 := m["name"].(string)
			key, ok2 := m["key"].(string)
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("%s.secretKeyRef: must be {name, key} with string values", path)
			}
			r := SecretRef{Name: name, Key: key}
			if err := checkSecretRef(r); err != nil {
				return nil, fmt.Errorf("%s.secretKeyRef: %w", path, err)
			}
			*refs = append(*refs, r)
			if mode == ForValidation {
				return dummySecret, nil
			}
			return r.Placeholder(), nil
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			s, err := substitute(e, path+"."+k, refs, mode)
			if err != nil {
				return nil, err
			}
			out[k] = s
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			s, err := substitute(e, fmt.Sprintf("%s[%d]", path, i), refs, mode)
			if err != nil {
				return nil, err
			}
			out[i] = s
		}
		return out, nil
	default:
		return v, nil
	}
}
