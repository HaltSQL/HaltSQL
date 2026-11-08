//go:build e2e

/*
Copyright The HaltSQL Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package e2e runs the operator on a real kind cluster: it builds the
// haltsql and operator images, installs the CRDs and the operator with
// kustomize, creates a HaltSQLPolicy and a HaltSQLServer, calls /v1/verify
// through a port-forward, updates the policy and watches the rollout, and
// deletes the server to see garbage collection.
//
//	HALTSQL_E2E=1 go test -tags e2e -v -timeout 30m ./test/e2e/
//
// Environment:
//
//	HALTSQL_E2E=1               required (the test is skipped otherwise)
//	HALTSQL_IMAGE               haltsql image (default haltsql-operator-e2e/haltsql:dev;
//	                            built from the repository Dockerfile when missing)
//	KIND_NODE_IMAGE             kind node image (default: kind's default)
//	HALTSQL_E2E_KEEP_CLUSTER=1  keep the kind cluster after the test
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	clusterName      = "haltsql-operator"
	defaultHaltSQL   = "haltsql-operator-e2e/haltsql:dev"
	operatorImage    = "haltsql-operator-e2e/operator:dev"
	operatorNS       = "haltsql-system"
	operatorDeploy   = "haltsql-operator-controller-manager"
	defaultOperImage = "ghcr.io/ardada2468/haltsql-operator:latest"
	testNS           = "haltsql-e2e"
)

const policyV1 = `apiVersion: haltsql.dev/v1
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

var policyV2 = strings.Replace(policyV1, "[id, status, total_cents]", "[id, status, total_cents, created_at]", 1)

type env struct {
	t          *testing.T
	kubeconfig string
	opDir      string
	repoDir    string
}

func (e *env) run(stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+e.kubeconfig)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func (e *env) must(stdin string, name string, args ...string) string {
	e.t.Helper()
	out, err := e.run(stdin, name, args...)
	if err != nil {
		e.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func (e *env) kubectl(args ...string) string {
	e.t.Helper()
	return e.must("", "kubectl", args...)
}

func (e *env) apply(manifest string) {
	e.t.Helper()
	e.must(manifest, "kubectl", "apply", "--server-side", "--force-conflicts", "-f", "-")
}

// eventually polls cond every second.
func (e *env) eventually(timeout time.Duration, what string, cond func() (bool, string)) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ok, msg := cond()
		if ok {
			e.t.Logf("ok: %s", what)
			return
		}
		last = msg
		if time.Now().After(deadline) {
			e.dumpState()
			e.t.Fatalf("timed out after %s waiting for %s; last state: %s", timeout, what, last)
		}
		time.Sleep(time.Second)
	}
}

func (e *env) dumpState() {
	for _, args := range [][]string{
		{"get", "haltsqlpolicies,haltsqlservers,deploy,rs,pods,svc,cm,pdb,netpol", "-n", testNS, "-o", "wide"},
		{"get", "haltsqlpolicies,haltsqlservers", "-n", testNS, "-o", "yaml"},
		{"logs", "-n", operatorNS, "deploy/" + operatorDeploy, "--tail", "80"},
		{"logs", "-n", testNS, "-l", "app.kubernetes.io/instance=hs", "--tail", "40", "--prefix"},
	} {
		out, _ := e.run("", "kubectl", args...)
		e.t.Logf("$ kubectl %s\n%s", strings.Join(args, " "), out)
	}
}

type condition struct {
	Type, Status, Reason, Message string
}

type object struct {
	Metadata struct {
		Generation  int64             `json:"generation"`
		UID         string            `json:"uid"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64       `json:"observedGeneration"`
		ContentHash        string      `json:"contentHash"`
		PolicyName         string      `json:"policyName"`
		ReadyReplicas      int32       `json:"readyReplicas"`
		ConfigChecksum     string      `json:"configChecksum"`
		Conditions         []condition `json:"conditions"`
		AppliedPolicies    []struct {
			Name, ContentHash string
		} `json:"appliedPolicies"`
	} `json:"status"`
}

func (e *env) get(kind, name string) (*object, error) {
	out, err := e.run("", "kubectl", "get", kind, name, "-n", testNS, "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, out)
	}
	var o object
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		return nil, err
	}
	return &o, nil
}

func cond(o *object, typ string) *condition {
	for i := range o.Status.Conditions {
		if o.Status.Conditions[i].Type == typ {
			return &o.Status.Conditions[i]
		}
	}
	return nil
}

func (e *env) waitCondition(kind, name, typ, status, reason string, timeout time.Duration) *object {
	e.t.Helper()
	var o *object
	e.eventually(timeout, fmt.Sprintf("%s/%s %s=%s %s", kind, name, typ, status, reason), func() (bool, string) {
		var err error
		o, err = e.get(kind, name)
		if err != nil {
			return false, err.Error()
		}
		c := cond(o, typ)
		if c == nil {
			return false, "no condition"
		}
		ok := c.Status == status && (reason == "" || c.Reason == reason) && o.Status.ObservedGeneration == o.Metadata.Generation
		return ok, fmt.Sprintf("%s=%s %s: %s", c.Type, c.Status, c.Reason, c.Message)
	})
	return o
}

// portForward forwards a random local port to svc/hs:8080 and returns the
// base URL and a stop function.
func (e *env) portForward() (string, func()) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "port-forward", "-n", testNS, "svc/hs", ":8080")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+e.kubeconfig)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	stop := func() { cancel(); _ = cmd.Wait() }
	re := regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+) ->`)
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				select {
				case found <- m[1]:
				default:
				}
			}
		}
	}()
	select {
	case port := <-found:
		return "http://127.0.0.1:" + port, stop
	case <-time.After(30 * time.Second):
		stop()
		e.t.Fatal("kubectl port-forward did not start")
		return "", nil
	}
}

type verdict struct {
	Allowed bool `json:"allowed"`
	Reasons []struct {
		Code string `json:"code"`
	} `json:"reasons"`
	Policy struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"policy"`
}

func verify(base, token, sql string) (int, *verdict, error) {
	body, _ := json.Marshal(map[string]any{"sql": sql})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/verify", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var v verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, &v, nil
}

// expectVerdict calls /v1/verify through a fresh port-forward (pods change
// across rollouts), retrying transient connection errors.
func (e *env) expectVerdict(token, sql string, allowed bool, code string) {
	e.t.Helper()
	e.eventually(60*time.Second, fmt.Sprintf("verify %q -> allowed=%t %s", sql, allowed, code), func() (bool, string) {
		base, stop := e.portForward()
		defer stop()
		_, v, err := verify(base, token, sql)
		if err != nil {
			return false, err.Error()
		}
		if v.Allowed != allowed {
			return false, fmt.Sprintf("allowed=%t reasons=%v", v.Allowed, v.Reasons)
		}
		if code != "" && (len(v.Reasons) == 0 || v.Reasons[0].Code != code) {
			return false, fmt.Sprintf("reasons=%v", v.Reasons)
		}
		return true, ""
	})
}

func haveTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func TestOperatorOnKind(t *testing.T) {
	if os.Getenv("HALTSQL_E2E") != "1" {
		t.Skip("set HALTSQL_E2E=1 to run the kind end-to-end test")
	}
	for _, tool := range []string{"docker", "kind", "kubectl"} {
		if !haveTool(tool) {
			t.Skipf("%s not found on PATH", tool)
		}
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker is not available: %v: %s", err, bytes.TrimSpace(out))
	}
	opDir, _ := filepath.Abs(filepath.Join("..", ".."))
	e := &env{t: t, opDir: opDir, repoDir: filepath.Join(opDir, "..", ".."), kubeconfig: filepath.Join(t.TempDir(), "kubeconfig")}

	// Images.
	haltsqlImage := os.Getenv("HALTSQL_IMAGE")
	if haltsqlImage == "" {
		haltsqlImage = defaultHaltSQL
	}
	if _, err := e.run("", "docker", "image", "inspect", haltsqlImage); err != nil {
		t.Logf("building %s from the repository Dockerfile", haltsqlImage)
		e.must("", "docker", "build", "-t", haltsqlImage, e.repoDir)
	}
	t.Logf("building %s", operatorImage)
	e.must("", "docker", "build", "-t", operatorImage, "--build-arg", "HALTSQL_IMAGE="+haltsqlImage, opDir)

	// Cluster.
	_, _ = e.run("", "kind", "delete", "cluster", "--name", clusterName)
	createArgs := []string{"create", "cluster", "--name", clusterName, "--kubeconfig", e.kubeconfig, "--wait", "180s"}
	if img := os.Getenv("KIND_NODE_IMAGE"); img != "" {
		createArgs = append(createArgs, "--image", img)
	}
	e.must("", "kind", createArgs...)
	t.Cleanup(func() {
		if t.Failed() {
			e.dumpState()
		}
		if os.Getenv("HALTSQL_E2E_KEEP_CLUSTER") == "1" {
			t.Logf("keeping kind cluster %s (kubeconfig %s)", clusterName, e.kubeconfig)
			return
		}
		if out, err := e.run("", "kind", "delete", "cluster", "--name", clusterName); err != nil {
			t.Errorf("deleting kind cluster: %v: %s", err, out)
		}
	})
	e.must("", "kind", "load", "docker-image", "--name", clusterName, haltsqlImage, operatorImage)

	// Install the CRDs, RBAC and operator from the kustomize tree.
	manifests := e.must("", "kubectl", "kustomize", filepath.Join(opDir, "config", "default"))
	if !strings.Contains(manifests, defaultOperImage) {
		t.Fatalf("kustomize output does not reference %s", defaultOperImage)
	}
	e.apply(strings.ReplaceAll(manifests, defaultOperImage, operatorImage))
	e.kubectl("wait", "--for=condition=Established", "crd/haltsqlpolicies.haltsql.dev", "crd/haltsqlservers.haltsql.dev", "--timeout=60s")
	e.kubectl("-n", operatorNS, "rollout", "status", "deploy/"+operatorDeploy, "--timeout=180s")

	// The operator's ServiceAccount must not be able to read Secrets.
	for _, verb := range []string{"get", "list", "watch"} {
		// kubectl auth can-i exits 1 when the answer is "no".
		out, _ := e.run("", "kubectl", "auth", "can-i", verb, "secrets", "-A",
			"--as=system:serviceaccount:"+operatorNS+":"+operatorDeploy)
		if strings.TrimSpace(out) != "no" {
			t.Fatalf("operator ServiceAccount: can-i %s secrets = %q, want no", verb, strings.TrimSpace(out))
		}
	}

	// Token for the agent: only its SHA-256 goes into a Secret.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	e.kubectl("create", "namespace", testNS)
	e.kubectl("-n", testNS, "create", "secret", "generic", "haltsql-tokens",
		"--from-literal=orders-agent.sha256="+hex.EncodeToString(sum[:])+"\n")

	e.apply(policyManifest(policyV1))
	e.apply(fmt.Sprintf(`apiVersion: haltsql.dev/v1alpha1
kind: HaltSQLServer
metadata:
  name: hs
  namespace: %s
spec:
  replicas: 2
  image: %s
  imagePullPolicy: IfNotPresent
  policies:
    - name: orders
  config:
    logLevel: info
  auth:
    tokens:
      - name: orders-agent
        policy: orders-agent
        sha256SecretRef: { name: haltsql-tokens, key: orders-agent.sha256 }
  podDisruptionBudget:
    enabled: true
  networkPolicy:
    enabled: true
`, testNS, haltsqlImage))

	pol := e.waitCondition("haltsqlpolicy", "orders", "Valid", "True", "Validated", 2*time.Minute)
	if pol.Status.PolicyName != "orders-agent" {
		t.Fatalf("policyName = %q", pol.Status.PolicyName)
	}
	srv := e.waitCondition("haltsqlserver", "hs", "Ready", "True", "Ready", 4*time.Minute)
	if srv.Status.ReadyReplicas != 2 {
		t.Fatalf("readyReplicas = %d", srv.Status.ReadyReplicas)
	}
	pol = e.waitCondition("haltsqlpolicy", "orders", "Synced", "True", "Synced", time.Minute)
	hashV1 := pol.Status.ContentHash

	// The pods run haltsql-server from the haltsql image.
	images := e.kubectl("get", "pods", "-n", testNS, "-l", "app.kubernetes.io/instance=hs",
		"-o", `jsonpath={range .items[*]}{.spec.containers[0].image} {.status.phase} {.status.containerStatuses[0].ready}{"\n"}{end}`)
	lines := strings.Split(strings.TrimSpace(images), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 pods, got:\n%s", images)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, haltsqlImage+" Running true") && !strings.HasPrefix(l, "docker.io/"+haltsqlImage+" Running true") {
			t.Fatalf("unexpected pod: %q", l)
		}
	}
	for _, kind := range []string{"configmap/hs-haltsql-config", "service/hs", "poddisruptionbudget/hs", "networkpolicy/hs"} {
		e.kubectl("get", "-n", testNS, kind)
	}

	// Allow and deny through the Service.
	e.expectVerdict(token, "SELECT id, status FROM orders LIMIT 10", true, "")
	e.expectVerdict(token, "SELECT created_at FROM orders LIMIT 5", false, "E_COLUMN_DENIED")
	e.expectVerdict(token, "DELETE FROM orders", false, "")
	func() {
		base, stop := e.portForward()
		defer stop()
		if code, _, _ := verify(base, "", "SELECT id FROM orders LIMIT 1"); code != http.StatusUnauthorized {
			t.Fatalf("request without a token: HTTP %d, want 401", code)
		}
		if code, _, _ := verify(base, "wrong-token", "SELECT id FROM orders LIMIT 1"); code != http.StatusUnauthorized {
			t.Fatalf("request with a wrong token: HTTP %d, want 401", code)
		}
	}()

	// Update the policy: new checksum, rolling update, new behaviour.
	dep, err := e.get("deployment", "hs")
	if err != nil {
		t.Fatal(err)
	}
	sumV1 := dep.Spec.Template.Metadata.Annotations["haltsql.dev/config-checksum"]
	rsBefore := strings.Fields(e.kubectl("get", "rs", "-n", testNS, "-l", "app.kubernetes.io/instance=hs", "-o", "jsonpath={.items[*].metadata.name}"))
	e.apply(policyManifest(policyV2))
	e.eventually(time.Minute, "new config checksum on the pod template", func() (bool, string) {
		d, err := e.get("deployment", "hs")
		if err != nil {
			return false, err.Error()
		}
		s := d.Spec.Template.Metadata.Annotations["haltsql.dev/config-checksum"]
		return s != "" && s != sumV1, s
	})
	e.kubectl("-n", testNS, "rollout", "status", "deploy/hs", "--timeout=180s")
	pol = e.waitCondition("haltsqlpolicy", "orders", "Synced", "True", "Synced", 2*time.Minute)
	if pol.Status.ContentHash == hashV1 {
		t.Fatal("content hash did not change")
	}
	e.waitCondition("haltsqlserver", "hs", "Ready", "True", "Ready", 2*time.Minute)
	rsAfter := strings.Fields(e.kubectl("get", "rs", "-n", testNS, "-l", "app.kubernetes.io/instance=hs", "-o", "jsonpath={.items[*].metadata.name}"))
	if len(rsAfter) <= len(rsBefore) {
		t.Fatalf("expected a new ReplicaSet: before %v, after %v", rsBefore, rsAfter)
	}
	e.expectVerdict(token, "SELECT created_at FROM orders LIMIT 5", true, "")

	// An invalid policy is refused before it reaches the pods; they keep
	// serving the last valid version.
	d2, _ := e.get("deployment", "hs")
	sumV2 := d2.Spec.Template.Metadata.Annotations["haltsql.dev/config-checksum"]
	e.apply(policyManifest(policyV2 + "require_limt: {max: 5}\n"))
	e.waitCondition("haltsqlpolicy", "orders", "Valid", "False", "ValidationFailed", time.Minute)
	e.waitCondition("haltsqlserver", "hs", "PoliciesReady", "False", "PolicyNotValid", time.Minute)
	time.Sleep(3 * time.Second)
	if d3, _ := e.get("deployment", "hs"); d3.Spec.Template.Metadata.Annotations["haltsql.dev/config-checksum"] != sumV2 {
		t.Fatal("an invalid policy changed the pod template")
	}
	e.expectVerdict(token, "SELECT created_at FROM orders LIMIT 5", true, "")

	// Delete the server: its Deployment, pods, ConfigMap, Service, PDB and
	// NetworkPolicy are garbage-collected through owner references.
	e.kubectl("delete", "haltsqlserver", "hs", "-n", testNS, "--wait=true", "--timeout=60s")
	e.eventually(2*time.Minute, "garbage collection of owned objects", func() (bool, string) {
		out, err := e.run("", "kubectl", "get", "deploy,rs,pods,cm,svc,pdb,netpol", "-n", testNS,
			"-l", "app.kubernetes.io/instance=hs", "-o", "name")
		if err != nil {
			return false, out
		}
		return strings.TrimSpace(out) == "", out
	})
	e.waitCondition("haltsqlpolicy", "orders", "Synced", "False", "", time.Minute)
	e.kubectl("delete", "haltsqlpolicy", "orders", "-n", testNS)
}

func policyManifest(policy string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: haltsql.dev/v1alpha1\nkind: HaltSQLPolicy\nmetadata:\n  name: orders\n  namespace: %s\nspec:\n  policy: |\n", testNS)
	for _, l := range strings.Split(strings.TrimRight(policy, "\n"), "\n") {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}
