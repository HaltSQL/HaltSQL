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

// Package controller holds the HaltSQLPolicy and HaltSQLServer reconcilers.
package controller

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	haltsqlv1alpha1 "github.com/ardada2468/HaltSQL/deploy/operator/api/v1alpha1"
	"github.com/ardada2468/HaltSQL/deploy/operator/internal/render"
	"github.com/ardada2468/HaltSQL/deploy/operator/internal/validate"
)

// policyRefIndex indexes HaltSQLServers by the HaltSQLPolicy names they reference.
const policyRefIndex = "spec.policies.name"

// CacheOptions restricts the informers for the object kinds the operator
// creates to objects carrying its managed-by label, so the operator neither
// caches nor ever adopts other ConfigMaps, Deployments or Services.
func CacheOptions() cache.Options {
	managed := labels.SelectorFromSet(labels.Set{render.LabelManagedBy: render.ManagedBy})
	return cache.Options{ByObject: map[client.Object]cache.ByObject{
		&corev1.ConfigMap{}:             {Label: managed},
		&corev1.Service{}:               {Label: managed},
		&appsv1.Deployment{}:            {Label: managed},
		&policyv1.PodDisruptionBudget{}: {Label: managed},
		&networkingv1.NetworkPolicy{}:   {Label: managed},
	}}
}

// Setup registers the field index and both reconcilers with mgr.
func Setup(mgr ctrl.Manager, v validate.Validator) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &haltsqlv1alpha1.HaltSQLServer{}, policyRefIndex,
		func(o client.Object) []string {
			srv := o.(*haltsqlv1alpha1.HaltSQLServer)
			names := make([]string, 0, len(srv.Spec.Policies))
			for _, p := range srv.Spec.Policies {
				names = append(names, p.Name)
			}
			return names
		}); err != nil {
		return err
	}
	if err := (&PolicyReconciler{Client: mgr.GetClient(), Validator: v}).SetupWithManager(mgr); err != nil {
		return err
	}
	return (&ServerReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr)
}
