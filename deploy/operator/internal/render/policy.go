/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

// Package render turns HaltSQLPolicy and HaltSQLServer objects into the
// HaltSQL documents haltsql-server loads. Everything here is a pure function
// of its inputs, so the same spec always renders the same bytes (and the same
// checksum).
package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	haltsqlv1alpha1 "github.com/HaltSQL/HaltSQL/deploy/operator/api/v1alpha1"
)

// Paths inside haltsql-server pods.
const (
	ConfigDir       = "/etc/haltsql"
	ConfigFile      = "config.yaml"
	SecretsDir      = "/var/run/haltsql/secrets"
	TLSDir          = "/var/run/haltsql/tls"
	BundleCacheDir  = "/var/cache/haltsql/bundles"
	ListenPort      = 8080
	HealthPort      = 8081
	documentVersion = "haltsql.dev/v1"
)

// SecretRef is one Secret key mounted into the pods at
// SecretsDir/<Name>/<Key>.
type SecretRef struct {
	Name string
	Key  string
}

// Path is where the key is mounted.
func (s SecretRef) Path() string { return SecretsDir + "/" + s.Name + "/" + s.Key }

// Placeholder is the ${file:...} placeholder that reads the mounted key.
func (s SecretRef) Placeholder() string { return "${file:" + s.Path() + "}" }

// PolicyContent is the validated form of an inline policy.
type PolicyContent struct {
	// Ext is ".yaml" or ".json".
	Ext string
	// Body is the policy text exactly as written in the spec, so validation
	// errors point at the user's own line numbers.
	Body []byte
	// Name is the document's metadata.name.
	Name string
}

// InlinePolicy checks the shape haltsql cannot check for us (a Policy
// document; no catalog file reference, because the operator and the pods
// have no such file) and returns the content.
func InlinePolicy(text string) (*PolicyContent, error) {
	body := []byte(text)
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("spec.policy is empty")
	}
	ext := ".yaml"
	if trimmed := bytes.TrimSpace(body); trimmed[0] == '{' {
		ext = ".json"
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("spec.policy is not a YAML or JSON mapping: %v", err)
	}
	if doc == nil {
		return nil, errors.New("spec.policy is not a YAML or JSON mapping")
	}
	if kind, _ := doc["kind"].(string); kind != "Policy" {
		return nil, fmt.Errorf("spec.policy must be a document with kind: Policy (got kind %q)", fmt.Sprint(doc["kind"]))
	}
	meta, _ := doc["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	if name == "" {
		return nil, errors.New("spec.policy: metadata.name must be a non-empty string")
	}
	if c, ok := doc["catalog"]; ok {
		if _, isPath := c.(string); isPath {
			return nil, errors.New("spec.policy: catalog file references are not supported by the operator; write the catalog snapshot inline")
		}
	}
	return &PolicyContent{Ext: ext, Body: body, Name: name}, nil
}

// Mode selects how secrets are rendered in a bundle_source entry.
type Mode int

const (
	// ForServer renders ${file:...} placeholders for mounted Secret keys.
	ForServer Mode = iota
	// ForValidation renders fixed dummy literals, so `haltsql validate` can
	// check the shape without access to any Secret.
	ForValidation
)

const dummySecret = "operator-validation-placeholder"

func keyOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// BundleEntry renders a bundle source as a `policies` entry (without
// cache_dir, which depends on the server) and lists the Secret keys it
// needs.
func BundleEntry(bs *haltsqlv1alpha1.BundleSource, mode Mode) (map[string]any, []SecretRef, error) {
	if bs == nil {
		return nil, nil, errors.New("bundleSource is nil")
	}
	var refs []SecretRef
	secret := func(name, key string) (string, error) {
		r := SecretRef{Name: name, Key: key}
		if err := checkSecretRef(r); err != nil {
			return "", err
		}
		refs = append(refs, r)
		if mode == ForValidation {
			return dummySecret, nil
		}
		return r.Placeholder(), nil
	}
	authOf := func(a *haltsqlv1alpha1.BundleAuth) (map[string]any, error) {
		if a == nil {
			return nil, nil
		}
		switch a.Type {
		case "token":
			t, err := secret(a.SecretName, keyOr(a.TokenKey, "token"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"token": t}, nil
		case "basic":
			u, err := secret(a.SecretName, keyOr(a.UsernameKey, "username"))
			if err != nil {
				return nil, err
			}
			p, err := secret(a.SecretName, keyOr(a.PasswordKey, "password"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"username": u, "password": p}, nil
		default:
			return nil, fmt.Errorf("type must be token or basic, got %q", a.Type)
		}
	}

	src := map[string]any{}
	entry := map[string]any{}
	n := 0
	if o := bs.OCI; o != nil {
		n++
		src["oci"] = o.Ref
		if o.PlainHTTP {
			src["plain_http"] = true
		}
		auth, err := authOf(o.Auth)
		if err != nil {
			return nil, nil, fmt.Errorf("bundleSource.oci.auth: %w", err)
		}
		if auth != nil {
			entry["auth"] = auth
		}
	}
	if h := bs.HTTPS; h != nil {
		n++
		src["https"] = h.URL
		auth, err := authOf(h.Auth)
		if err != nil {
			return nil, nil, fmt.Errorf("bundleSource.https.auth: %w", err)
		}
		if auth != nil {
			entry["auth"] = auth
		}
	}
	if s := bs.S3; s != nil {
		n++
		s3 := map[string]any{"bucket": s.Bucket, "key": s.Key, "region": s.Region}
		if s.Endpoint != "" {
			s3["endpoint"] = s.Endpoint
		}
		if c := s.Credentials; c != nil {
			creds := map[string]any{"source": c.Source}
			if c.Source == "static" {
				ak, err := secret(c.SecretName, keyOr(c.AccessKeyIDKey, "access_key_id"))
				if err != nil {
					return nil, nil, fmt.Errorf("bundleSource.s3.credentials: %w", err)
				}
				sk, err := secret(c.SecretName, keyOr(c.SecretAccessKeyKey, "secret_access_key"))
				if err != nil {
					return nil, nil, fmt.Errorf("bundleSource.s3.credentials: %w", err)
				}
				creds["access_key_id"] = ak
				creds["secret_access_key"] = sk
				if c.SessionTokenKey != "" {
					st, err := secret(c.SecretName, c.SessionTokenKey)
					if err != nil {
						return nil, nil, fmt.Errorf("bundleSource.s3.credentials: %w", err)
					}
					creds["session_token"] = st
				}
			}
			s3["credentials"] = creds
		}
		src["s3"] = s3
	}
	if n != 1 {
		return nil, nil, errors.New("bundleSource: exactly one of oci, s3 or https is required")
	}
	if len(bs.PublicKeys) == 0 {
		return nil, nil, errors.New("bundleSource.publicKeys must not be empty (signature verification is mandatory)")
	}
	entry["bundle_source"] = src
	keys := make([]any, len(bs.PublicKeys))
	for i, k := range bs.PublicKeys {
		keys[i] = k
	}
	entry["public_keys"] = keys
	if bs.NamePrefix != "" {
		entry["name_prefix"] = bs.NamePrefix
	}
	if bs.PollIntervalSeconds != nil {
		entry["poll_interval_s"] = int64(*bs.PollIntervalSeconds)
	}
	return entry, dedupeRefs(refs), nil
}

// ValidationDocument returns the file name and content `haltsql validate`
// checks for a policy spec: the inline policy itself, or a minimal Config
// document holding the bundle source (with dummy credentials).
func ValidationDocument(spec *haltsqlv1alpha1.HaltSQLPolicySpec) (string, []byte, *PolicyContent, error) {
	switch {
	case spec.Policy != "" && spec.BundleSource != nil:
		return "", nil, nil, errors.New("exactly one of spec.policy or spec.bundleSource is required")
	case spec.Policy != "":
		pc, err := InlinePolicy(spec.Policy)
		if err != nil {
			return "", nil, nil, err
		}
		return "policy" + pc.Ext, pc.Body, pc, nil
	case spec.BundleSource != nil:
		entry, _, err := BundleEntry(spec.BundleSource, ForValidation)
		if err != nil {
			return "", nil, nil, err
		}
		doc := map[string]any{
			"apiVersion": documentVersion,
			"kind":       "Config",
			"policies":   []any{entry},
		}
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return "", nil, nil, err
		}
		return "bundle-source.json", b, nil, nil
	default:
		return "", nil, nil, errors.New("exactly one of spec.policy or spec.bundleSource is required")
	}
}

// ContentHash identifies the content a policy spec renders to. Both
// controllers compute it from the spec, so a server never runs content that
// was not validated under the same hash.
func ContentHash(spec *haltsqlv1alpha1.HaltSQLPolicySpec) (string, error) {
	h := sha256.New()
	switch {
	case spec.Policy != "" && spec.BundleSource == nil:
		h.Write([]byte("inline\x00"))
		h.Write([]byte(spec.Policy))
	case spec.BundleSource != nil && spec.Policy == "":
		entry, _, err := BundleEntry(spec.BundleSource, ForServer)
		if err != nil {
			return "", err
		}
		b, err := json.Marshal(entry) // map keys are sorted: deterministic
		if err != nil {
			return "", err
		}
		h.Write([]byte("bundle\x00"))
		h.Write(b)
	default:
		return "", errors.New("exactly one of spec.policy or spec.bundleSource is required")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func dedupeRefs(refs []SecretRef) []SecretRef {
	seen := map[SecretRef]bool{}
	out := refs[:0]
	for _, r := range refs {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func isDNSSubdomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if !alnum && !(c == '-' && i > 0 && i < len(label)-1) {
				return false
			}
		}
	}
	return true
}

func isSecretKey(s string) bool {
	if len(s) == 0 || len(s) > 253 || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

func checkSecretRef(r SecretRef) error {
	if !isDNSSubdomain(r.Name) {
		return fmt.Errorf("secret name %q is not a valid Secret name", r.Name)
	}
	if !isSecretKey(r.Key) {
		return fmt.Errorf("secret key %q is not a valid Secret key", r.Key)
	}
	return nil
}
