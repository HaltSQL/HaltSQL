/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package controller

// The reconcile tests run both controllers against a real kube-apiserver and
// etcd started by envtest (no fake client), with the real haltsql CLI as the
// validator. envtest has no kube-controller-manager, so the tests play the
// Deployment controller's part by writing Deployment status, and check owner
// references instead of garbage collection (the kind e2e test covers that).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	haltsqlv1alpha1 "github.com/HaltSQL/HaltSQL/deploy/operator/api/v1alpha1"
	"github.com/HaltSQL/HaltSQL/deploy/operator/internal/validate"
)

var (
	k8sClient client.Client
	scheme    = k8sruntime.NewScheme()
	nsCounter int
)

const envtestVersion = "1.35.0"

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(haltsqlv1alpha1.AddToScheme(scheme))
}

// skipOrFail ends the run before any test when a prerequisite is missing:
// a clean skip by default, a failure when HALTSQL_REQUIRE_ENVTEST=1.
func skipOrFail(msg string) {
	if os.Getenv("HALTSQL_REQUIRE_ENVTEST") == "1" {
		fmt.Fprintln(os.Stderr, "FAIL: "+msg)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "SKIP: "+msg)
	os.Exit(0)
}

func envtestAssets() string {
	if a := os.Getenv("KUBEBUILDER_ASSETS"); a != "" {
		return a
	}
	dir := filepath.Join("..", "..", "bin", "k8s", "k8s", envtestVersion+"-"+runtime.GOOS+"-"+runtime.GOARCH)
	if _, err := os.Stat(filepath.Join(dir, "kube-apiserver")); err == nil {
		abs, _ := filepath.Abs(dir)
		return abs
	}
	return ""
}

func haltsqlBinary() string {
	if p := os.Getenv("HALTSQL_BIN"); p != "" {
		return p
	}
	if p, err := exec.LookPath("haltsql"); err == nil {
		return p
	}
	return ""
}

func TestMain(m *testing.M) {
	assets := envtestAssets()
	if assets == "" {
		skipOrFail("envtest binaries not found: run `make envtest` (setup-envtest) or set KUBEBUILDER_ASSETS")
	}
	bin := haltsqlBinary()
	if bin == "" {
		skipOrFail("haltsql CLI not found: set HALTSQL_BIN or put haltsql on PATH")
	}
	v, err := validate.NewCLI(bin)
	if err != nil {
		skipOrFail(err.Error())
	}
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(os.Stderr), zap.Level(zapLevel())))

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		BinaryAssetsDirectory: assets,
	}
	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "starting envtest:", err)
		os.Exit(1)
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Cache:                  CacheOptions(),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "creating manager:", err)
		_ = testEnv.Stop()
		os.Exit(1)
	}
	if err := Setup(mgr, v); err != nil {
		fmt.Fprintln(os.Stderr, "setting up controllers:", err)
		_ = testEnv.Stop()
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()

	// Tests use an uncached client so they see the API server directly.
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, "creating client:", err)
		os.Exit(1)
	}
	code := m.Run()
	cancel()
	<-done
	if err := testEnv.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stopping envtest:", err)
	}
	os.Exit(code)
}

func zapLevel() zapcore.Level {
	if os.Getenv("HALTSQL_TEST_VERBOSE") == "1" {
		return -1
	}
	return 2 // errors only
}

// newNamespace creates a namespace for one test.
func newNamespace(t *testing.T) string {
	t.Helper()
	nsCounter++
	name := fmt.Sprintf("t%d-%d", nsCounter, time.Now().UnixNano()%100000)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8sClient.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	return name
}

// eventually polls cond until it returns true or the timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ok, msg := cond()
		if ok {
			return
		}
		last = msg
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s; last state: %s", timeout, what, last)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// consistently checks that cond stays true for d.
func consistently(t *testing.T, d time.Duration, what string, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok, msg := cond(); !ok {
			t.Fatalf("%s stopped holding: %s", what, msg)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
