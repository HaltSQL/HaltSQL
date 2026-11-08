/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	haltsqlv1alpha1 "github.com/ardada2468/HaltSQL/deploy/operator/api/v1alpha1"
	"github.com/ardada2468/HaltSQL/deploy/operator/internal/render"
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

const timeout = 20 * time.Second

var ctx = context.Background()

func getPolicy(t *testing.T, ns, name string) *haltsqlv1alpha1.HaltSQLPolicy {
	t.Helper()
	var p haltsqlv1alpha1.HaltSQLPolicy
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func getServer(t *testing.T, ns, name string) *haltsqlv1alpha1.HaltSQLServer {
	t.Helper()
	var s haltsqlv1alpha1.HaltSQLServer
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func condString(conds []metav1.Condition) string {
	var b strings.Builder
	for _, c := range conds {
		fmt.Fprintf(&b, "[%s=%s %s: %s] ", c.Type, c.Status, c.Reason, c.Message)
	}
	return b.String()
}

func hasCondition(conds []metav1.Condition, typ string, status metav1.ConditionStatus, reason string) bool {
	c := meta.FindStatusCondition(conds, typ)
	return c != nil && c.Status == status && (reason == "" || c.Reason == reason)
}

func waitPolicy(t *testing.T, ns, name, typ string, status metav1.ConditionStatus, reason string) *haltsqlv1alpha1.HaltSQLPolicy {
	t.Helper()
	var p *haltsqlv1alpha1.HaltSQLPolicy
	eventually(t, timeout, fmt.Sprintf("policy %s %s=%s %s", name, typ, status, reason), func() (bool, string) {
		p = getPolicy(t, ns, name)
		ok := hasCondition(p.Status.Conditions, typ, status, reason) && p.Status.ObservedGeneration == p.Generation
		return ok, condString(p.Status.Conditions)
	})
	return p
}

func waitServer(t *testing.T, ns, name, typ string, status metav1.ConditionStatus, reason string) *haltsqlv1alpha1.HaltSQLServer {
	t.Helper()
	var s *haltsqlv1alpha1.HaltSQLServer
	eventually(t, timeout, fmt.Sprintf("server %s %s=%s %s", name, typ, status, reason), func() (bool, string) {
		s = getServer(t, ns, name)
		ok := hasCondition(s.Status.Conditions, typ, status, reason) && s.Status.ObservedGeneration == s.Generation
		return ok, condString(s.Status.Conditions)
	})
	return s
}

func newPolicy(ns, name, text string) *haltsqlv1alpha1.HaltSQLPolicy {
	return &haltsqlv1alpha1.HaltSQLPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       haltsqlv1alpha1.HaltSQLPolicySpec{Policy: text},
	}
}

func newServer(ns, name string, policies ...string) *haltsqlv1alpha1.HaltSQLServer {
	s := &haltsqlv1alpha1.HaltSQLServer{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: haltsqlv1alpha1.HaltSQLServerSpec{
			Replicas: ptr.To[int32](2),
			Image:    "ghcr.io/ardada2468/haltsql:test",
		},
	}
	for _, p := range policies {
		s.Spec.Policies = append(s.Spec.Policies, haltsqlv1alpha1.PolicyReference{Name: p})
	}
	return s
}

func create(t *testing.T, obj client.Object) {
	t.Helper()
	if err := k8sClient.Create(ctx, obj); err != nil {
		t.Fatalf("creating %T %s: %v", obj, obj.GetName(), err)
	}
}

// updatePolicyText changes spec.policy with conflict retries.
func updatePolicyText(t *testing.T, ns, name, text string) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		p := getPolicy(t, ns, name)
		p.Spec.Policy = text
		return k8sClient.Update(ctx, p)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func updateServer(t *testing.T, ns, name string, mutate func(*haltsqlv1alpha1.HaltSQLServer)) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		s := getServer(t, ns, name)
		mutate(s)
		return k8sClient.Update(ctx, s)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// markRolledOut plays the Deployment controller: it reports every replica of
// the current generation as updated, ready and available.
func markRolledOut(t *testing.T, ns, name string) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var d appsv1.Deployment
		if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &d); err != nil {
			return err
		}
		n := *d.Spec.Replicas
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation,
			Replicas:           n, UpdatedReplicas: n, ReadyReplicas: n, AvailableReplicas: n,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, Reason: "MinimumReplicasAvailable", LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now()},
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable", LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now()},
			},
		}
		return k8sClient.Status().Update(ctx, &d)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func deployment(t *testing.T, ns, name string) *appsv1.Deployment {
	t.Helper()
	var d appsv1.Deployment
	eventually(t, timeout, "deployment "+name, func() (bool, string) {
		err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &d)
		return err == nil, fmt.Sprint(err)
	})
	return &d
}

func configMap(t *testing.T, ns, name string) *corev1.ConfigMap {
	t.Helper()
	var c corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name + "-haltsql-config"}, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestPolicyValidation(t *testing.T) {
	ns := newNamespace(t)
	create(t, newPolicy(ns, "good", ordersPolicy))
	p := waitPolicy(t, ns, "good", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionTrue, ReasonValidated)
	if p.Status.PolicyName != "orders-agent" || !strings.HasPrefix(p.Status.ContentHash, "sha256:") {
		t.Fatalf("status: %+v", p.Status)
	}
	waitPolicy(t, ns, "good", haltsqlv1alpha1.PolicyConditionSynced, metav1.ConditionFalse, ReasonNotReferenced)

	create(t, newPolicy(ns, "bad", ordersPolicy+"unknown_key: 1\n"))
	p = waitPolicy(t, ns, "bad", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionFalse, ReasonValidationFailed)
	msg := meta.FindStatusCondition(p.Status.Conditions, haltsqlv1alpha1.PolicyConditionValid).Message
	if !strings.Contains(msg, "policy.yaml:14") || !strings.Contains(msg, "unknown_key") {
		t.Fatalf("message must locate the error: %q", msg)
	}
	waitPolicy(t, ns, "bad", haltsqlv1alpha1.PolicyConditionSynced, metav1.ConditionFalse, ReasonNotValid)

	create(t, newPolicy(ns, "catalog", ordersPolicy+"catalog: /var/run/secrets/kubernetes.io/serviceaccount/token\n"))
	waitPolicy(t, ns, "catalog", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionFalse, ReasonInvalidSpec)

	create(t, newPolicy(ns, "config-kind", "apiVersion: haltsql.dev/v1\nkind: Config\n"))
	waitPolicy(t, ns, "config-kind", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionFalse, ReasonInvalidSpec)

	// Fixing the policy flips it to Valid.
	updatePolicyText(t, ns, "bad", ordersPolicy)
	waitPolicy(t, ns, "bad", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionTrue, ReasonValidated)

	// Bundle sources are validated as a Config document by the same CLI.
	bundle := &haltsqlv1alpha1.HaltSQLPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "bundle"},
		Spec: haltsqlv1alpha1.HaltSQLPolicySpec{BundleSource: &haltsqlv1alpha1.BundleSource{
			OCI:        &haltsqlv1alpha1.OCIBundleSource{Ref: "registry.example:5000/corp/policies:prod", Auth: &haltsqlv1alpha1.BundleAuth{SecretName: "reg", Type: "basic"}},
			PublicKeys: []string{testKey},
			NamePrefix: "prod.",
		}},
	}
	create(t, bundle)
	waitPolicy(t, ns, "bundle", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionTrue, ReasonValidated)
	badBundle := bundle.DeepCopy()
	badBundle.ObjectMeta = metav1.ObjectMeta{Namespace: ns, Name: "bad-bundle"}
	badBundle.Spec.BundleSource.OCI.Ref = "no-registry/policies:prod"
	create(t, badBundle)
	waitPolicy(t, ns, "bad-bundle", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionFalse, ReasonValidationFailed)
}

func TestCRDValidation(t *testing.T) {
	ns := newNamespace(t)
	reject := func(what string, obj client.Object, want string) {
		t.Helper()
		err := k8sClient.Create(ctx, obj)
		if err == nil || !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an Invalid error containing %q, got %v", what, want, err)
		}
	}
	both := newPolicy(ns, "both", ordersPolicy)
	both.Spec.BundleSource = &haltsqlv1alpha1.BundleSource{HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://x"}, PublicKeys: []string{testKey}}
	reject("policy and bundleSource", both, "exactly one of spec.policy or spec.bundleSource")
	reject("neither", newPolicy(ns, "neither", ""), "exactly one of spec.policy or spec.bundleSource")
	noKeys := newPolicy(ns, "nokeys", "")
	noKeys.Spec.BundleSource = &haltsqlv1alpha1.BundleSource{HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://x"}}
	reject("no public keys", noKeys, "publicKeys")
	twoSources := newPolicy(ns, "two", "")
	twoSources.Spec.BundleSource = &haltsqlv1alpha1.BundleSource{
		HTTPS: &haltsqlv1alpha1.HTTPSBundleSource{URL: "https://x"}, OCI: &haltsqlv1alpha1.OCIBundleSource{Ref: "a.b/c:d"}, PublicKeys: []string{testKey},
	}
	reject("two sources", twoSources, "exactly one of oci, s3 or https")
	staticNoSecret := newPolicy(ns, "s3", "")
	staticNoSecret.Spec.BundleSource = &haltsqlv1alpha1.BundleSource{
		S3: &haltsqlv1alpha1.S3BundleSource{Bucket: "abc", Key: "k", Region: "r", Credentials: &haltsqlv1alpha1.S3Credentials{Source: "static"}}, PublicKeys: []string{testKey},
	}
	reject("static s3 without secret", staticNoSecret, "secretName is required")

	noPolicies := newServer(ns, "nopol")
	reject("server without policies", noPolicies, "spec.policies")
	mtls := newServer(ns, "mtls", "p")
	mtls.Spec.Auth = &haltsqlv1alpha1.ServerAuth{MTLS: &haltsqlv1alpha1.MTLSSpec{Identities: []apiextensionsv1.JSON{{Raw: []byte(`{"subject_cn":"a","policy":"p"}`)}}}}
	reject("mtls without tls", mtls, "auth.mtls.identities need tls")
	badSecret := newServer(ns, "badsecret", "p")
	badSecret.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{{Name: "t", Policy: "p", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "Bad_Name", Key: "k"}}}}
	reject("bad secret name", badSecret, "sha256SecretRef.name")
}

func TestServerLifecycle(t *testing.T) {
	ns := newNamespace(t)
	create(t, newPolicy(ns, "orders", ordersPolicy))
	srv := newServer(ns, "hs", "orders")
	srv.Spec.Config.DefaultPolicy = "orders-agent"
	srv.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{
		{Name: "agent", Policy: "orders-agent", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tokens", Key: "agent.sha256"}},
	}}
	srv.Spec.PodDisruptionBudget = &haltsqlv1alpha1.PodDisruptionBudgetSpec{Enabled: true}
	srv.Spec.NetworkPolicy = &haltsqlv1alpha1.NetworkPolicySpec{Enabled: true}
	create(t, srv)

	s := waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionConfigRendered, metav1.ConditionTrue, ReasonRendered)
	if !hasCondition(s.Status.Conditions, haltsqlv1alpha1.ServerConditionPoliciesReady, metav1.ConditionTrue, "") {
		t.Fatalf("policies not ready: %s", condString(s.Status.Conditions))
	}
	if !hasCondition(s.Status.Conditions, haltsqlv1alpha1.ServerConditionReady, metav1.ConditionFalse, "") {
		t.Fatalf("must not be Ready before the rollout: %s", condString(s.Status.Conditions))
	}
	if s.Status.Selector != "app.kubernetes.io/instance=hs,app.kubernetes.io/name=haltsql" {
		t.Fatalf("selector: %q", s.Status.Selector)
	}

	// Owned objects, all controlled by the server (garbage collection
	// follows these references).
	d := deployment(t, ns, "hs")
	cm := configMap(t, ns, "hs")
	var svc corev1.Service
	var pdb policyv1.PodDisruptionBudget
	var np networkingv1.NetworkPolicy
	for _, o := range []client.Object{d, cm, &svc, &pdb, &np} {
		name := "hs"
		if o == client.Object(cm) {
			name = cm.Name
		}
		if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, o); err != nil {
			t.Fatalf("%T: %v", o, err)
		}
		ref := metav1.GetControllerOf(o)
		if ref == nil || ref.UID != s.UID || ref.Kind != "HaltSQLServer" || !ptr.Deref(ref.BlockOwnerDeletion, false) {
			t.Fatalf("%T %s: bad controller reference %+v", o, o.GetName(), ref)
		}
		if o.GetLabels()[render.LabelManagedBy] != render.ManagedBy {
			t.Fatalf("%T: missing managed-by label", o)
		}
	}
	if !strings.Contains(cm.Data["config.yaml"], "token_sha256: ${file:/var/run/haltsql/secrets/tokens/agent.sha256}") {
		t.Fatalf("config.yaml:\n%s", cm.Data["config.yaml"])
	}
	if cm.Data["policy-orders.yaml"] != ordersPolicy {
		t.Fatalf("policy file: %q", cm.Data["policy-orders.yaml"])
	}
	sum1 := d.Spec.Template.Annotations[render.AnnotationConfigChecksum]
	if sum1 == "" || sum1 != s.Status.ConfigChecksum {
		t.Fatalf("checksum annotation %q, status %q", sum1, s.Status.ConfigChecksum)
	}
	if *d.Spec.Replicas != 2 || d.Spec.Template.Spec.Containers[0].Image != "ghcr.io/ardada2468/haltsql:test" {
		t.Fatalf("deployment spec: %+v", d.Spec)
	}
	if svc.Spec.Ports[0].Port != 8080 || svc.Spec.Selector["app.kubernetes.io/instance"] != "hs" {
		t.Fatalf("service: %+v", svc.Spec)
	}

	// Roll out: the server becomes Ready and the policy Synced.
	markRolledOut(t, ns, "hs")
	s = waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionReady, metav1.ConditionTrue, ReasonReady)
	if s.Status.ReadyReplicas != 2 || len(s.Status.AppliedPolicies) != 1 {
		t.Fatalf("status: %+v", s.Status)
	}
	p := waitPolicy(t, ns, "orders", haltsqlv1alpha1.PolicyConditionSynced, metav1.ConditionTrue, ReasonSynced)
	if s.Status.AppliedPolicies[0].ContentHash != p.Status.ContentHash {
		t.Fatalf("applied hash %s != policy hash %s", s.Status.AppliedPolicies[0].ContentHash, p.Status.ContentHash)
	}

	// A policy change re-renders the ConfigMap, changes the checksum (new
	// pods) and the policy waits for the rollout.
	changed := strings.Replace(ordersPolicy, "[id, status, total_cents]", "[id, status, total_cents, created_at]", 1)
	updatePolicyText(t, ns, "orders", changed)
	eventually(t, timeout, "new checksum", func() (bool, string) {
		d = deployment(t, ns, "hs")
		sum := d.Spec.Template.Annotations[render.AnnotationConfigChecksum]
		return sum != sum1, sum
	})
	if configMap(t, ns, "hs").Data["policy-orders.yaml"] != changed {
		t.Fatal("ConfigMap not updated")
	}
	waitPolicy(t, ns, "orders", haltsqlv1alpha1.PolicyConditionSynced, metav1.ConditionFalse, ReasonRollingOut)
	waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionProgressing, metav1.ConditionTrue, ReasonRollingOut)
	markRolledOut(t, ns, "hs")
	waitPolicy(t, ns, "orders", haltsqlv1alpha1.PolicyConditionSynced, metav1.ConditionTrue, ReasonSynced)
	waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionReady, metav1.ConditionTrue, ReasonReady)
	sum2 := deployment(t, ns, "hs").Spec.Template.Annotations[render.AnnotationConfigChecksum]

	// An invalid policy never reaches the pods: the last good configuration
	// stays in place and the server reports why.
	updatePolicyText(t, ns, "orders", changed+"bogus: true\n")
	waitPolicy(t, ns, "orders", haltsqlv1alpha1.PolicyConditionValid, metav1.ConditionFalse, ReasonValidationFailed)
	waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionPoliciesReady, metav1.ConditionFalse, ReasonPolicyNotValid)
	consistently(t, 2*time.Second, "last good config", func() (bool, string) {
		sum := deployment(t, ns, "hs").Spec.Template.Annotations[render.AnnotationConfigChecksum]
		data := configMap(t, ns, "hs").Data["policy-orders.yaml"]
		return sum == sum2 && data == changed, sum
	})
	updatePolicyText(t, ns, "orders", changed)
	waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionPoliciesReady, metav1.ConditionTrue, ReasonPoliciesReady)

	// Server spec changes: scale, and turn the PDB and NetworkPolicy off.
	updateServer(t, ns, "hs", func(s *haltsqlv1alpha1.HaltSQLServer) {
		s.Spec.Replicas = ptr.To[int32](3)
		s.Spec.PodDisruptionBudget.Enabled = false
		s.Spec.NetworkPolicy = nil
	})
	eventually(t, timeout, "scale to 3 and drop PDB/NetworkPolicy", func() (bool, string) {
		d = deployment(t, ns, "hs")
		pdbErr := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "hs"}, &policyv1.PodDisruptionBudget{})
		npErr := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "hs"}, &networkingv1.NetworkPolicy{})
		return *d.Spec.Replicas == 3 && apierrors.IsNotFound(pdbErr) && apierrors.IsNotFound(npErr),
			fmt.Sprintf("replicas=%d pdb=%v np=%v", *d.Spec.Replicas, pdbErr, npErr)
	})
	if d.Spec.Template.Annotations[render.AnnotationConfigChecksum] != sum2 {
		t.Fatal("scaling must not change the config checksum")
	}

	// Drift on an owned object is not corrected unless the desired spec
	// changes, but a deleted object is recreated.
	if err := k8sClient.Delete(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "hs"}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, timeout, "service recreated", func() (bool, string) {
		err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "hs"}, &corev1.Service{})
		return err == nil, fmt.Sprint(err)
	})

	// Deleting the server removes the policy's reference.
	if err := k8sClient.Delete(ctx, getServer(t, ns, "hs")); err != nil {
		t.Fatal(err)
	}
	waitPolicy(t, ns, "orders", haltsqlv1alpha1.PolicyConditionSynced, metav1.ConditionFalse, ReasonNotReferenced)
}

func TestServerWaitsForPolicies(t *testing.T) {
	ns := newNamespace(t)
	create(t, newServer(ns, "hs", "later"))
	s := waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionPoliciesReady, metav1.ConditionFalse, ReasonPolicyNotFound)
	if !hasCondition(s.Status.Conditions, haltsqlv1alpha1.ServerConditionReady, metav1.ConditionFalse, ReasonPolicyNotFound) {
		t.Fatalf("ready: %s", condString(s.Status.Conditions))
	}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "hs"}, &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("no Deployment may exist without valid policies, got %v", err)
	}
	create(t, newPolicy(ns, "later", ordersPolicy))
	waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionConfigRendered, metav1.ConditionTrue, ReasonRendered)
	deployment(t, ns, "hs")
}

func TestServerInvalidConfig(t *testing.T) {
	ns := newNamespace(t)
	create(t, newPolicy(ns, "orders", ordersPolicy))
	srv := newServer(ns, "hs", "orders")
	srv.Spec.Auth = &haltsqlv1alpha1.ServerAuth{Tokens: []haltsqlv1alpha1.TokenSpec{
		{Name: "agent", Policy: "not-loaded", SHA256SecretRef: haltsqlv1alpha1.SecretKeyRef{Name: "tokens", Key: "k"}},
	}}
	create(t, srv)
	s := waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionConfigRendered, metav1.ConditionFalse, ReasonInvalidConfig)
	if c := meta.FindStatusCondition(s.Status.Conditions, haltsqlv1alpha1.ServerConditionConfigRendered); !strings.Contains(c.Message, `policy "not-loaded"`) {
		t.Fatalf("message: %q", c.Message)
	}
	updateServer(t, ns, "hs", func(s *haltsqlv1alpha1.HaltSQLServer) { s.Spec.Auth.Tokens[0].Policy = "orders-agent" })
	waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionConfigRendered, metav1.ConditionTrue, ReasonRendered)
}

func TestServerNeverAdoptsForeignObjects(t *testing.T) {
	ns := newNamespace(t)
	foreign := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "hs-haltsql-config"},
		Data:       map[string]string{"owner": "someone else"},
	}
	create(t, foreign)
	create(t, newPolicy(ns, "orders", ordersPolicy))
	create(t, newServer(ns, "hs", "orders"))
	waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionConfigRendered, metav1.ConditionFalse, ReasonNameConflict)
	var cm corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: foreign.Name}, &cm); err != nil {
		t.Fatal(err)
	}
	if cm.Data["owner"] != "someone else" || len(cm.OwnerReferences) != 0 {
		t.Fatalf("foreign ConfigMap was modified: %+v", cm)
	}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "hs"}, &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("no Deployment may be created after a conflict, got %v", err)
	}
}

func TestDuplicatePolicyNames(t *testing.T) {
	ns := newNamespace(t)
	create(t, newPolicy(ns, "a", ordersPolicy))
	create(t, newPolicy(ns, "b", ordersPolicy))
	create(t, newServer(ns, "hs", "a", "b"))
	s := waitServer(t, ns, "hs", haltsqlv1alpha1.ServerConditionConfigRendered, metav1.ConditionFalse, ReasonInvalidConfig)
	if c := meta.FindStatusCondition(s.Status.Conditions, haltsqlv1alpha1.ServerConditionConfigRendered); !strings.Contains(c.Message, "both define policy") {
		t.Fatalf("message: %q", c.Message)
	}
}
