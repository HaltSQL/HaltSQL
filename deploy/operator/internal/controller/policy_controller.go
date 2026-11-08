/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	haltsqlv1alpha1 "github.com/ardada2468/HaltSQL/deploy/operator/api/v1alpha1"
	"github.com/ardada2468/HaltSQL/deploy/operator/internal/render"
	"github.com/ardada2468/HaltSQL/deploy/operator/internal/validate"
)

// Condition reasons on HaltSQLPolicy.
const (
	ReasonValidated        = "Validated"
	ReasonValidationFailed = "ValidationFailed"
	ReasonInvalidSpec      = "InvalidSpec"
	ReasonValidatorError   = "ValidatorError"
	ReasonSynced           = "Synced"
	ReasonRollingOut       = "RollingOut"
	ReasonNotReferenced    = "NotReferenced"
	ReasonNotValid         = "NotValid"
)

// PolicyReconciler validates HaltSQLPolicies with `haltsql validate` and
// reports whether the servers that reference them run the current content.
type PolicyReconciler struct {
	client.Client
	Validator validate.Validator
}

// +kubebuilder:rbac:groups=haltsql.dev,resources=haltsqlpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=haltsql.dev,resources=haltsqlpolicies/status,verbs=update

// Reconcile implements reconcile.Reconciler.
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	var pol haltsqlv1alpha1.HaltSQLPolicy
	if err := r.Get(ctx, req.NamespacedName, &pol); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	status := pol.Status.DeepCopy()
	var requeueErr error

	hash, hashErr := render.ContentHash(&pol.Spec)
	prev := meta.FindStatusCondition(status.Conditions, haltsqlv1alpha1.PolicyConditionValid)
	upToDate := prev != nil && prev.Status != metav1.ConditionUnknown &&
		status.ObservedGeneration == pol.Generation && status.ContentHash == hash && hashErr == nil
	if !upToDate {
		cond := metav1.Condition{Type: haltsqlv1alpha1.PolicyConditionValid, ObservedGeneration: pol.Generation}
		status.PolicyName = ""
		name, doc, pc, err := render.ValidationDocument(&pol.Spec)
		switch {
		case hashErr != nil:
			cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, ReasonInvalidSpec, hashErr.Error()
		case err != nil:
			cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, ReasonInvalidSpec, err.Error()
		default:
			verr := r.Validator.Validate(ctx, name, doc)
			switch {
			case verr == nil:
				cond.Status, cond.Reason = metav1.ConditionTrue, ReasonValidated
				cond.Message = "haltsql validate accepted the policy"
				if pc != nil {
					status.PolicyName = pc.Name
				} else {
					cond.Message = "haltsql validate accepted the bundle source; haltsql-server fetches and verifies the bundle"
				}
			case validate.IsInvalid(verr):
				cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, ReasonValidationFailed, verr.Error()
			default:
				// The check itself could not run: unknown, retried with backoff.
				cond.Status, cond.Reason, cond.Message = metav1.ConditionUnknown, ReasonValidatorError, verr.Error()
				requeueErr = fmt.Errorf("validating HaltSQLPolicy %s: %w", req.NamespacedName, verr)
			}
		}
		if hashErr == nil {
			status.ContentHash = hash
		} else {
			status.ContentHash = ""
		}
		status.ObservedGeneration = pol.Generation
		meta.SetStatusCondition(&status.Conditions, cond)
		log.Info("validated policy", "valid", cond.Status, "reason", cond.Reason)
	}

	synced, err := r.syncedCondition(ctx, &pol, status)
	if err != nil {
		return ctrl.Result{}, err
	}
	meta.SetStatusCondition(&status.Conditions, synced)

	if !equality.Semantic.DeepEqual(&pol.Status, status) {
		pol.Status = *status
		if err := r.Status().Update(ctx, &pol); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}
	if requeueErr != nil {
		return ctrl.Result{}, requeueErr
	}
	return ctrl.Result{}, nil
}

func (r *PolicyReconciler) syncedCondition(ctx context.Context, pol *haltsqlv1alpha1.HaltSQLPolicy, status *haltsqlv1alpha1.HaltSQLPolicyStatus) (metav1.Condition, error) {
	cond := metav1.Condition{Type: haltsqlv1alpha1.PolicyConditionSynced, ObservedGeneration: pol.Generation}
	var servers haltsqlv1alpha1.HaltSQLServerList
	if err := r.List(ctx, &servers, client.InNamespace(pol.Namespace), client.MatchingFields{policyRefIndex: pol.Name}); err != nil {
		return cond, err
	}
	if !meta.IsStatusConditionTrue(status.Conditions, haltsqlv1alpha1.PolicyConditionValid) {
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonNotValid
		cond.Message = "the current spec is not valid; servers keep running the last valid content"
		return cond, nil
	}
	if len(servers.Items) == 0 {
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonNotReferenced
		cond.Message = "no HaltSQLServer references this policy"
		return cond, nil
	}
	var pending []string
	for _, s := range servers.Items {
		ok := false
		for _, a := range s.Status.AppliedPolicies {
			if a.Name == pol.Name && a.ContentHash == status.ContentHash {
				ok = true
				break
			}
		}
		if !ok {
			pending = append(pending, s.Name)
		}
	}
	if len(pending) > 0 {
		sort.Strings(pending)
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonRollingOut
		cond.Message = fmt.Sprintf("waiting for %d of %d HaltSQLServer(s) to roll out the current content: %s",
			len(pending), len(servers.Items), strings.Join(pending, ", "))
		return cond, nil
	}
	cond.Status, cond.Reason = metav1.ConditionTrue, ReasonSynced
	cond.Message = fmt.Sprintf("running on %d HaltSQLServer(s)", len(servers.Items))
	return cond, nil
}

// SetupWithManager registers the reconciler.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&haltsqlv1alpha1.HaltSQLPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&haltsqlv1alpha1.HaltSQLServer{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, o client.Object) []reconcile.Request {
				srv := o.(*haltsqlv1alpha1.HaltSQLServer)
				reqs := make([]reconcile.Request, 0, len(srv.Spec.Policies))
				for _, p := range srv.Spec.Policies {
					reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: srv.Namespace, Name: p.Name}})
				}
				return reqs
			})).
		Named("haltsqlpolicy").
		WithOptions(controllerOptions(30 * time.Second)).
		Complete(r)
}
