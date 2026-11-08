/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

// Command manager runs the HaltSQL Kubernetes operator.
package main

import (
	"flag"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	haltsqlv1alpha1 "github.com/ardada2468/HaltSQL/deploy/operator/api/v1alpha1"
	"github.com/ardada2468/HaltSQL/deploy/operator/internal/controller"
	"github.com/ardada2468/HaltSQL/deploy/operator/internal/validate"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(haltsqlv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr    string
		probeAddr      string
		leaderElect    bool
		haltsqlBin     string
		watchNamespace string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", `Address of the Prometheus metrics endpoint ("0" disables it).`)
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address of the /healthz and /readyz endpoints.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election (needed when running more than one replica).")
	flag.StringVar(&haltsqlBin, "haltsql-binary", "/usr/local/bin/haltsql", "Path to the haltsql CLI used to validate policies.")
	flag.StringVar(&watchNamespace, "watch-namespaces", "", "Comma-separated namespaces to watch (default: all namespaces).")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	v, err := validate.NewCLI(haltsqlBin)
	if err != nil {
		log.Error(err, "the haltsql CLI is required to validate policies")
		os.Exit(1)
	}

	cacheOpts := controller.CacheOptions()
	if watchNamespace != "" {
		cacheOpts.DefaultNamespaces = map[string]cache.Config{}
		for _, ns := range strings.Split(watchNamespace, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				cacheOpts.DefaultNamespaces[ns] = cache.Config{}
			}
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Cache:                  cacheOpts,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "haltsql-operator.haltsql.dev",
	})
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}
	if err := controller.Setup(mgr, v); err != nil {
		log.Error(err, "unable to set up controllers")
		os.Exit(1)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	log.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited")
		os.Exit(1)
	}
}
