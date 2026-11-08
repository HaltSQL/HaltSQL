/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package render

import (
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	haltsqlv1alpha1 "github.com/HaltSQL/HaltSQL/deploy/operator/api/v1alpha1"
)

const ordersPolicy = `apiVersion: haltsql.dev/v1
kind: Policy
metadata:
  name: orders-agent
dialect: postgres
search_path: [app]
statements:
  allow: [select]
require_limit:
  max: 100
tables:
  app.orders:
    columns: [id, status, total_cents]
`

const testKey = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n"

func raw(t *testing.T, s string) apiextensionsv1.JSON {
	t.Helper()
	j, err := yaml.YAMLToJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return apiextensionsv1.JSON{Raw: j}
}

func server(mod func(*haltsqlv1alpha1.HaltSQLServer)) *haltsqlv1alpha1.HaltSQLServer {
	s := &haltsqlv1alpha1.HaltSQLServer{
		ObjectMeta: metav1.ObjectMeta{Name: "hs", Namespace: "ns"},
		Spec: haltsqlv1alpha1.HaltSQLServerSpec{
			Image:    "haltsql:test",
			Policies: []haltsqlv1alpha1.PolicyReference{{Name: "orders"}},
		},
	}
	if mod != nil {
		mod(s)
	}
	return s
}

func inline(ref, text string) PolicyInput {
	return PolicyInput{Ref: ref, Spec: &haltsqlv1alpha1.HaltSQLPolicySpec{Policy: text}}
}

func configDoc(t *testing.T, r *Rendered) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(r.Data[ConfigFile]), &doc); err != nil {
		t.Fatalf("config.yaml does not parse: %v", err)
	}
	return doc
}

func TestInlinePolicy(t *testing.T) {
	pc, err := InlinePolicy(ordersPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if pc.Name != "orders-agent" || pc.Ext != ".yaml" || string(pc.Body) != ordersPolicy {
		t.Fatalf("unexpected %+v", pc)
	}
	pc, err = InlinePolicy(`  {"apiVersion":"haltsql.dev/v1","kind":"Policy","metadata":{"name":"j"}}`)
	if err != nil || pc.Ext != ".json" || pc.Name != "j" {
		t.Fatalf("json: %+v %v", pc, err)
	}
	for name, text := range map[string]string{
		"empty":       "  \n",
		"not mapping": "- a\n- b\n",
		"wrong kind":  "apiVersion: haltsql.dev/v1\nkind: Config\n",
		"no name":     "apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: {}\n",
		"catalog":     ordersPolicy + "catalog: /var/run/secrets/kubernetes.io/serviceaccount/token\n",
		"bad yaml":    "kind: [\n",
	} {
		if _, err := InlinePolicy(text); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestBundleEntryPlaceholdersAndDummies(t *testing.T) {
	bs := &haltsqlv1alpha1.BundleSource{
		OCI:                 &haltsqlv1alpha1.OCIBundleSource{Ref: "registry.example:5000/corp/policies:prod", Auth: &haltsqlv1alpha1.BundleAuth{SecretName: "reg", Type: "basic"}},
		PublicKeys:          []string{testKey},
		NamePrefix:          "prod.",
		PollIntervalSeconds: ptr.To[int32](30),
	}
	entry, refs, err := BundleEntry(bs, ForServer)
	if err != nil {
		t.Fatal(err)
	}
	auth := entry["auth"].(map[string]any)
	if auth["username"] != "${file:/var/run/haltsql/secrets/reg/username}" || auth["password"] != "${file:/var/run/haltsql/secrets/reg/password}" {
		t.Fatalf("auth placeholders: %v", auth)
	}
	if len(refs) != 2 || refs[0] != (SecretRef{"reg", "password"}) || refs[1] != (SecretRef{"reg", "username"}) {
		t.Fatalf("refs: %v", refs)
	}
	if entry["poll_interval_s"] != int64(30) || entry["name_prefix"] != "prod." {
		t.Fatalf("entry: %v", entry)
	}
	ventry, _, err := BundleEntry(bs, ForValidation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mustJSON(t, ventry), "${") {
		t.Fatalf("validation entry must not contain placeholders: %v", ventry)
	}

	s3 := &haltsqlv1alpha1.BundleSource{
		S3: &haltsqlv1alpha1.S3BundleSource{Bucket: "bundles", Key: "p.haltsqlbundle", Region: "us-east-1",
			Credentials: &haltsqlv1alpha1.S3Credentials{Source: "static", SecretName: "s3", SessionTokenKey: "st"}},
		PublicKeys: []string{testKey},
	}
	entry, refs, err = BundleEntry(s3, ForServer)
	if err != nil {
		t.Fatal(err)
	}
	creds := entry["bundle_source"].(map[string]any)["s3"].(map[string]any)["credentials"].(map[string]any)
	if creds["source"] != "static" || creds["session_token"] != "${file:/var/run/haltsql/secrets/s3/st}" || len(refs) != 3 {
		t.Fatalf("s3 creds: %v %v", creds, refs)
	}

	for name, bad := range map[string]*haltsqlv1alpha1.BundleSource{
		"none":      {PublicKeys: []string{testKey}},
		"two":       {OCI: &haltsqlv1alpha1.OCIBundleSource{Ref: "a.b/c:d"}, HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://x"}, PublicKeys: []string{testKey}},
		"no keys":   {HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://x"}},
		"bad sname": {HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://x", Auth: &haltsqlv1alpha1.BundleAuth{SecretName: "Bad_Name", Type: "token"}}, PublicKeys: []string{testKey}},
		"bad key":   {HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://x", Auth: &haltsqlv1alpha1.BundleAuth{SecretName: "ok", Type: "token", TokenKey: "../etc"}}, PublicKeys: []string{testKey}},
	} {
		if _, _, err := BundleEntry(bad, ForServer); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestContentHash(t *testing.T) {
	a := &haltsqlv1alpha1.HaltSQLPolicySpec{Policy: ordersPolicy}
	h1, err := ContentHash(a)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := ContentHash(a.DeepCopy())
	if h1 != h2 || !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("hash not stable: %s %s", h1, h2)
	}
	b := &haltsqlv1alpha1.HaltSQLPolicySpec{Policy: ordersPolicy + "\n"}
	if h3, _ := ContentHash(b); h3 == h1 {
		t.Fatal("hash must change with content")
	}
	if _, err := ContentHash(&haltsqlv1alpha1.HaltSQLPolicySpec{}); err == nil {
		t.Fatal("empty spec must fail")
	}
}

func TestServerRendersTokensAndSecrets(t *testing.T) {
	srv := server(func(s *haltsqlv1alpha1.HaltSQLServer) {
		s.Spec.Config = haltsqlv1alpha1.ServerConfig{LogLevel: "debug", DefaultPolicy: "orders-agent", MaxRequestBytes: ptr.To[int64](4096)}
		s.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{
			{Name: "agent", Policy: "orders-agent", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tok", Key: "agent.sha256"}},
		}}
		s.Spec.Audit = &haltsqlv1alpha1.ServerAudit{Sinks: []apiextensionsv1.JSON{
			raw(t, "{type: stdout}"),
			raw(t, "{type: elasticsearch, url: 'https://es:9200', index: audit, auth: {api_key: {secretKeyRef: {name: es, key: api-key}}}}"),
		}}
	})
	r, err := Server(srv, []PolicyInput{inline("orders", ordersPolicy)})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Data["policy-orders.yaml"]; got != ordersPolicy {
		t.Fatalf("policy file: %q", got)
	}
	doc := configDoc(t, r)
	if doc["kind"] != "Config" || doc["default_policy"] != "orders-agent" {
		t.Fatalf("doc: %v", doc)
	}
	tok := doc["server"].(map[string]any)["auth"].(map[string]any)["tokens"].([]any)[0].(map[string]any)
	if tok["token_sha256"] != "${file:/var/run/haltsql/secrets/tok/agent.sha256}" || tok["policy"] != "orders-agent" {
		t.Fatalf("token: %v", tok)
	}
	sink := doc["audit"].(map[string]any)["sinks"].([]any)[1].(map[string]any)
	if sink["auth"].(map[string]any)["api_key"] != "${file:/var/run/haltsql/secrets/es/api-key}" {
		t.Fatalf("sink: %v", sink)
	}
	if doc["reload"].(map[string]any)["watch"] != false {
		t.Fatal("reload.watch must be false")
	}
	if got := doc["limits"].(map[string]any)["max_request_bytes"]; got != float64(4096) {
		t.Fatalf("limits: %v", got)
	}
	if len(r.Secrets) != 2 || r.Secrets[0] != (SecretRef{"es", "api-key"}) || r.Secrets[1] != (SecretRef{"tok", "agent.sha256"}) {
		t.Fatalf("secrets: %v", r.Secrets)
	}
	if len(r.Applied) != 1 || r.Applied[0].Name != "orders" {
		t.Fatalf("applied: %v", r.Applied)
	}
}

func TestServerChecksum(t *testing.T) {
	srv := server(nil)
	r1, err := Server(srv, []PolicyInput{inline("orders", ordersPolicy)})
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := Server(srv.DeepCopy(), []PolicyInput{inline("orders", ordersPolicy)})
	if r1.Checksum != r2.Checksum || r1.Data[ConfigFile] != r2.Data[ConfigFile] {
		t.Fatal("rendering must be deterministic")
	}
	changed := strings.Replace(ordersPolicy, "max: 100", "max: 50", 1)
	r3, _ := Server(srv, []PolicyInput{inline("orders", changed)})
	if r3.Checksum == r1.Checksum {
		t.Fatal("checksum must change with the policy")
	}
	r4, _ := Server(server(func(s *haltsqlv1alpha1.HaltSQLServer) { s.Spec.Config.LogLevel = "warn" }), []PolicyInput{inline("orders", ordersPolicy)})
	if r4.Checksum == r1.Checksum {
		t.Fatal("checksum must change with the config")
	}
	r5, _ := Server(server(func(s *haltsqlv1alpha1.HaltSQLServer) { s.Spec.TLS = &haltsqlv1alpha1.ServerTLS{SecretName: "tls"} }), []PolicyInput{inline("orders", ordersPolicy)})
	if r5.Checksum == r1.Checksum || !r5.HealthPort || r5.TLSSecret != "tls" {
		t.Fatal("checksum must change with TLS")
	}
}

func TestServerRejects(t *testing.T) {
	ok := []PolicyInput{inline("orders", ordersPolicy)}
	cases := map[string]struct {
		srv      *haltsqlv1alpha1.HaltSQLServer
		policies []PolicyInput
		want     string
	}{
		"no policies":     {server(nil), nil, "at least one"},
		"duplicate names": {server(nil), []PolicyInput{inline("a", ordersPolicy), inline("b", ordersPolicy)}, "both define policy"},
		"unknown token policy": {server(func(s *haltsqlv1alpha1.HaltSQLServer) {
			s.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{{Name: "t", Policy: "nope", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "s", Key: "k"}}}}
		}), ok, `policy "nope"`},
		"unknown default": {server(func(s *haltsqlv1alpha1.HaltSQLServer) { s.Spec.Config.DefaultPolicy = "nope" }), ok, "defaultPolicy"},
		"secretKeyRef extra keys": {server(func(s *haltsqlv1alpha1.HaltSQLServer) {
			s.Spec.Audit = &haltsqlv1alpha1.ServerAudit{Sinks: []apiextensionsv1.JSON{raw(t, "{type: kafka, sasl: {password: {secretKeyRef: {name: a, key: b}, x: 1}}}")}}
		}), ok, "no other keys"},
		"secretKeyRef bad name": {server(func(s *haltsqlv1alpha1.HaltSQLServer) {
			s.Spec.Audit = &haltsqlv1alpha1.ServerAudit{Sinks: []apiextensionsv1.JSON{raw(t, "{type: kafka, sasl: {password: {secretKeyRef: {name: ../x, key: b}}}}")}}
		}), ok, "spec.audit.sinks[0].sasl.password.secretKeyRef"},
		"sink not object": {server(func(s *haltsqlv1alpha1.HaltSQLServer) {
			s.Spec.Audit = &haltsqlv1alpha1.ServerAudit{Sinks: []apiextensionsv1.JSON{raw(t, "[1]")}}
		}), ok, "must be an object"},
		"sink without type": {server(func(s *haltsqlv1alpha1.HaltSQLServer) {
			s.Spec.Audit = &haltsqlv1alpha1.ServerAudit{Sinks: []apiextensionsv1.JSON{raw(t, "{path: x}")}}
		}), ok, "type must be a string"},
		"mtls without tls": {server(func(s *haltsqlv1alpha1.HaltSQLServer) {
			s.Spec.Auth = &haltsqlv1alpha1.ServerAuth{MTLS: &haltsqlv1alpha1.MTLSSpec{Identities: []apiextensionsv1.JSON{raw(t, "{subject_cn: a, policy: orders-agent}")}}}
		}), ok, "need spec.tls"},
		"too large": {server(nil), []PolicyInput{inline("orders", ordersPolicy+"# "+strings.Repeat("x", MaxConfigBytes)+"\n")}, "byte limit"},
	}
	for name, c := range cases {
		_, err := Server(c.srv, c.policies)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
}

func TestBundleReferencesWithPrefix(t *testing.T) {
	bundle := PolicyInput{Ref: "prod", Spec: &haltsqlv1alpha1.HaltSQLPolicySpec{BundleSource: &haltsqlv1alpha1.BundleSource{
		HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://bundles.example/p.haltsqlbundle"}, PublicKeys: []string{testKey}, NamePrefix: "prod.",
	}}}
	tokenFor := func(policy string) *haltsqlv1alpha1.HaltSQLServer {
		return server(func(s *haltsqlv1alpha1.HaltSQLServer) {
			s.Spec.Policies = []haltsqlv1alpha1.PolicyReference{{Name: "prod"}}
			s.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{{Name: "t", Policy: policy, SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "s", Key: "k"}}}}
		})
	}
	r, err := Server(tokenFor("prod.analytics"), []PolicyInput{bundle})
	if err != nil {
		t.Fatal(err)
	}
	entry := configDoc(t, r)["policies"].([]any)[0].(map[string]any)
	if entry["cache_dir"] != "/var/cache/haltsql/bundles/prod" {
		t.Fatalf("cache_dir: %v", entry)
	}
	if _, err := Server(tokenFor("other"), []PolicyInput{bundle}); err == nil {
		t.Fatal("a name without a bundle prefix must be rejected")
	}
}

func TestDeploymentSpec(t *testing.T) {
	srv := server(func(s *haltsqlv1alpha1.HaltSQLServer) {
		s.Spec.Replicas = ptr.To[int32](3)
		s.Spec.PodAnnotations = map[string]string{"a": "b", AnnotationConfigChecksum: "spoofed"}
		s.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{
			{Name: "t1", Policy: "orders-agent", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tok", Key: "a"}},
			{Name: "t2", Policy: "orders-agent", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tok", Key: "b"}},
		}}
	})
	r, err := Server(srv, []PolicyInput{inline("orders", ordersPolicy)})
	if err != nil {
		t.Fatal(err)
	}
	d := DeploymentSpec(srv, r)
	if *d.Replicas != 3 || d.Template.Annotations[AnnotationConfigChecksum] != r.Checksum || d.Template.Annotations["a"] != "b" {
		t.Fatalf("template: %+v", d.Template.ObjectMeta)
	}
	if d.Strategy.RollingUpdate.MaxUnavailable.IntValue() != 0 {
		t.Fatal("maxUnavailable must be 0")
	}
	c := d.Template.Spec.Containers[0]
	if c.Image != "haltsql:test" || strings.Join(c.Args, " ") != "--config /etc/haltsql/config.yaml" {
		t.Fatalf("container: %v %v", c.Image, c.Args)
	}
	if !*c.SecurityContext.ReadOnlyRootFilesystem || *c.SecurityContext.AllowPrivilegeEscalation || *d.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("security context too loose")
	}
	var projected int
	for _, v := range d.Template.Spec.Volumes {
		if v.Projected != nil {
			projected++
			if len(v.Projected.Sources) != 1 || len(v.Projected.Sources[0].Secret.Items) != 2 || v.Projected.Sources[0].Secret.Items[1].Path != "tok/b" {
				t.Fatalf("projection: %+v", v.Projected.Sources)
			}
		}
	}
	if projected != 1 {
		t.Fatal("expected one projected secrets volume")
	}
	if got := SpecHash(d); got != SpecHash(DeploymentSpec(srv, r)) {
		t.Fatal("spec hash not deterministic")
	}
	if PDBSpec(srv) != nil || NetworkPolicySpec(srv, r) != nil {
		t.Fatal("PDB and NetworkPolicy are off by default")
	}
	srv.Spec.PodDisruptionBudget = &haltsqlv1alpha1.PodDisruptionBudgetSpec{Enabled: true}
	srv.Spec.NetworkPolicy = &haltsqlv1alpha1.NetworkPolicySpec{Enabled: true}
	if p := PDBSpec(srv); p == nil || p.MinAvailable.IntValue() != 1 {
		t.Fatal("default PDB minAvailable 1")
	}
	if np := NetworkPolicySpec(srv, r); np == nil || len(np.Ingress) != 1 || np.Ingress[0].From[0].PodSelector == nil {
		t.Fatal("default NetworkPolicy allows the namespace")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
