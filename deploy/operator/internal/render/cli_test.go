/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package render

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	haltsqlv1alpha1 "github.com/HaltSQL/HaltSQL/deploy/operator/api/v1alpha1"
	"github.com/HaltSQL/HaltSQL/deploy/operator/internal/testutil"
	"github.com/HaltSQL/HaltSQL/deploy/operator/internal/validate"
)

// TestRenderedConfigLoadsInHaltSQL writes the rendered ConfigMap and the
// Secret keys it mounts into a directory laid out like the pod, and checks
// that the real haltsql loader accepts the result.
func TestRenderedConfigLoadsInHaltSQL(t *testing.T) {
	bin := testutil.HaltSQLBinary(t)
	srv := server(func(s *haltsqlv1alpha1.HaltSQLServer) {
		s.Spec.Policies = []haltsqlv1alpha1.PolicyReference{{Name: "orders"}, {Name: "prod"}}
		s.Spec.Config = haltsqlv1alpha1.ServerConfig{LogLevel: "warn", LogFormat: "text", DefaultPolicy: "orders-agent"}
		s.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{
			{Name: "agent", Policy: "orders-agent", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tok", Key: "agent.sha256"}},
			{Name: "bundle-agent", Policy: "prod.analytics", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tok", Key: "bundle.sha256"}},
		}}
		s.Spec.Audit = &haltsqlv1alpha1.ServerAudit{Sinks: []apiextensionsv1.JSON{
			raw(t, "{type: stdout}"),
			raw(t, "{type: kafka, brokers: ['kafka:9093'], topic: haltsql.audit, tls: {enabled: true}, sasl: {mechanism: scram-sha-512, username: haltsql, password: {secretKeyRef: {name: kafka, key: password}}}}"),
		}}
	})
	bundle := PolicyInput{Ref: "prod", Spec: &haltsqlv1alpha1.HaltSQLPolicySpec{BundleSource: &haltsqlv1alpha1.BundleSource{
		OCI:        &haltsqlv1alpha1.OCIBundleSource{Ref: "registry.example:5000/corp/policies:prod", Auth: &haltsqlv1alpha1.BundleAuth{SecretName: "reg", Type: "token"}},
		PublicKeys: []string{testKey},
		NamePrefix: "prod.",
	}}}
	r, err := Server(srv, []PolicyInput{inline("orders", ordersPolicy), bundle})
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	rewrite := func(s string) string {
		s = strings.ReplaceAll(s, SecretsDir, filepath.Join(root, "secrets"))
		s = strings.ReplaceAll(s, BundleCacheDir, filepath.Join(root, "cache"))
		return strings.ReplaceAll(s, ConfigDir+"/", filepath.Join(root, "etc")+"/")
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range r.Data {
		if err := os.WriteFile(filepath.Join(root, "etc", k), []byte(rewrite(v)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range r.Secrets {
		val := "secret-value"
		if strings.HasSuffix(s.Key, ".sha256") {
			sum := sha256.Sum256([]byte("token-" + s.Key))
			val = hex.EncodeToString(sum[:]) + "\n" // trailing newline, as `sha256sum` users write it
		}
		p := filepath.Join(root, "secrets", s.Name, s.Key)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(val), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(root, "etc", ConfigFile)
	out, err := exec.Command(bin, "validate", cfg).CombinedOutput()
	if err != nil {
		t.Fatalf("haltsql validate rejected the rendered config: %v\n%s\n--- config ---\n%s", err, out, r.Data[ConfigFile])
	}
	t.Logf("haltsql validate: %s", strings.TrimSpace(string(out)))
}

func TestValidationDocumentsInHaltSQL(t *testing.T) {
	v, err := validate.NewCLI(testutil.HaltSQLBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	valid := []*haltsqlv1alpha1.HaltSQLPolicySpec{
		{Policy: ordersPolicy},
		{BundleSource: &haltsqlv1alpha1.BundleSource{OCI: &haltsqlv1alpha1.OCIBundleSource{Ref: "registry.example/corp/p@sha256:" + strings.Repeat("a", 64), Auth: &haltsqlv1alpha1.BundleAuth{SecretName: "r", Type: "basic"}}, PublicKeys: []string{testKey}}},
		{BundleSource: &haltsqlv1alpha1.BundleSource{S3: &haltsqlv1alpha1.S3BundleSource{Bucket: "corp-bundles", Key: "p.haltsqlbundle", Region: "eu-west-1", Credentials: &haltsqlv1alpha1.S3Credentials{Source: "static", SecretName: "s3"}}, PublicKeys: []string{testKey}}},
		{BundleSource: &haltsqlv1alpha1.BundleSource{HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://bundles.example/p.haltsqlbundle"}, PublicKeys: []string{testKey}}},
	}
	for i, spec := range valid {
		name, doc, _, err := ValidationDocument(spec)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if err := v.Validate(ctx, name, doc); err != nil {
			t.Errorf("%d: expected valid, got %v\n%s", i, err, doc)
		}
	}
	invalid := []*haltsqlv1alpha1.HaltSQLPolicySpec{
		{Policy: ordersPolicy + "unknown_key: 1\n"},
		{BundleSource: &haltsqlv1alpha1.BundleSource{OCI: &haltsqlv1alpha1.OCIBundleSource{Ref: "no-registry-host/p:prod"}, PublicKeys: []string{testKey}}},
		{BundleSource: &haltsqlv1alpha1.BundleSource{HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "http://bundles.example/p"}, PublicKeys: []string{testKey}}},
		{BundleSource: &haltsqlv1alpha1.BundleSource{HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://bundles.example/p?x=1"}, PublicKeys: []string{testKey}}},
	}
	for i, spec := range invalid {
		name, doc, _, err := ValidationDocument(spec)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		err = v.Validate(ctx, name, doc)
		if !validate.IsInvalid(err) {
			t.Errorf("%d: expected an InvalidError, got %v", i, err)
		}
	}
}

func TestServerValidationDocumentInHaltSQL(t *testing.T) {
	v, err := validate.NewCLI(testutil.HaltSQLBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bundle := PolicyInput{Ref: "prod", Spec: &haltsqlv1alpha1.HaltSQLPolicySpec{BundleSource: &haltsqlv1alpha1.BundleSource{
		OCI:        &haltsqlv1alpha1.OCIBundleSource{Ref: "registry.example:5000/corp/policies:prod", Auth: &haltsqlv1alpha1.BundleAuth{SecretName: "reg", Type: "token"}},
		PublicKeys: []string{testKey},
		NamePrefix: "prod.",
	}}}
	policies := []PolicyInput{inline("orders", ordersPolicy), bundle}

	good := server(func(s *haltsqlv1alpha1.HaltSQLServer) {
		s.Spec.Policies = []haltsqlv1alpha1.PolicyReference{{Name: "orders"}, {Name: "prod"}}
		s.Spec.Config = haltsqlv1alpha1.ServerConfig{
			LogLevel:      "warn",
			LogFormat:     "text",
			DefaultPolicy: "orders-agent",
			OPA:           ptrTo(raw(t, `{url: "https://opa.example:8181", decision_path: "haltsql/allow", headers: {Authorization: {secretKeyRef: {name: opa, key: token}}}}`)),
		}
		s.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{
			{Name: "agent", Policy: "orders-agent", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tok", Key: "agent.sha256"}},
			{Name: "bundle-agent", Policy: "prod.analytics", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tok", Key: "bundle.sha256"}},
		}}
	})
	doc, err := ServerValidationDocument(good, policies)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(ctx, ConfigFile, doc); err != nil {
		t.Fatalf("expected valid server config, got %v\n%s", err, doc)
	}

	bad := good.DeepCopy()
	bad.Spec.Config.OPA = ptrTo(raw(t, `{url: "https://opa.example:8181", decision_path: "haltsql/allow", unknown_field: true}`))
	badDoc, err := ServerValidationDocument(bad, policies)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(ctx, ConfigFile, badDoc); !validate.IsInvalid(err) {
		t.Fatalf("expected InvalidError for unknown_field in spec.config.opa, got %v", err)
	}
}

func ptrTo[T any](v T) *T { return &v }
