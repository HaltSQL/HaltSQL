/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	haltsqlv1alpha1 "github.com/HaltSQL/HaltSQL/deploy/operator/api/v1alpha1"
	"github.com/HaltSQL/HaltSQL/deploy/operator/internal/render"
	"github.com/HaltSQL/HaltSQL/deploy/operator/internal/validate"
)

// Condition reasons on HaltSQLServer.
const (
	ReasonPoliciesReady     = "PoliciesReady"
	ReasonPolicyNotFound    = "PolicyNotFound"
	ReasonPolicyNotValid    = "PolicyNotValid"
	ReasonPolicyPending     = "PolicyPendingValidation"
	ReasonRendered          = "Rendered"
	ReasonInvalidConfig     = "InvalidConfig"
	ReasonNotRendered       = "NotRendered"
	ReasonNameConflict      = "NameConflict"
	ReasonRolloutComplete   = "RolloutComplete"
	ReasonRolloutFailed     = "RolloutFailed"
	ReasonDeploymentMissing = "DeploymentMissing"
	ReasonReady             = "Ready"
	ReasonUnavailable       = "Unavailable"
	ReasonScaledToZero      = "ScaledToZero"
)

// annotationAppliedPolicies on the Deployment records the policies and
// content hashes of the configuration in its pod template.
const annotationAppliedPolicies = "haltsql.dev/applied-policies"

// ServerReconciler renders a HaltSQLServer into a ConfigMap, Deployment,
// Service and optional PodDisruptionBudget and NetworkPolicy.
type ServerReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Validator validate.Validator
}

// +kubebuilder:rbac:groups=haltsql.dev,resources=haltsqlservers,verbs=get;list;watch
// +kubebuilder:rbac:groups=haltsql.dev,resources=haltsqlservers/status,verbs=update
// +kubebuilder:rbac:groups=haltsql.dev,resources=haltsqlservers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps;services,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;delete

// errConflict marks an object name already used by something the operator
// does not own.
var errConflict = errors.New("name conflict")

// Reconcile implements reconcile.Reconciler.
func (r *ServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	var srv haltsqlv1alpha1.HaltSQLServer
	if err := r.Get(ctx, req.NamespacedName, &srv); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !srv.DeletionTimestamp.IsZero() {
		// Owned objects are garbage-collected through owner references.
		return ctrl.Result{}, nil
	}
	status := srv.Status.DeepCopy()
	status.ObservedGeneration = srv.Generation
	status.Selector = labels.SelectorFromSet(render.SelectorLabels(&srv)).String()

	policies, polCond := r.loadPolicies(ctx, &srv)
	meta.SetStatusCondition(&status.Conditions, polCond)

	var applyErr error
	renderCond := metav1.Condition{Type: haltsqlv1alpha1.ServerConditionConfigRendered, ObservedGeneration: srv.Generation}
	if polCond.Status != metav1.ConditionTrue {
		renderCond.Status, renderCond.Reason = metav1.ConditionFalse, ReasonNotRendered
		renderCond.Message = "waiting for valid policies; running pods keep the last rendered configuration"
	} else if rd, err := render.Server(&srv, policies); err != nil {
		renderCond.Status, renderCond.Reason = metav1.ConditionFalse, ReasonInvalidConfig
		renderCond.Message = err.Error() + "; running pods keep the last rendered configuration"
	} else {
		var verr error
		if r.Validator != nil {
			vdoc, err := render.ServerValidationDocument(&srv, policies)
			if err != nil {
				verr = &validate.InvalidError{Message: err.Error()}
			} else {
				verr = r.Validator.Validate(ctx, render.ConfigFile, vdoc)
			}
		}
		switch {
		case validate.IsInvalid(verr):
			renderCond.Status, renderCond.Reason = metav1.ConditionFalse, ReasonInvalidConfig
			renderCond.Message = verr.Error() + "; running pods keep the last rendered configuration"
		case verr != nil:
			applyErr = fmt.Errorf("validating HaltSQLServer %s: %w", req.NamespacedName, verr)
			renderCond.Status, renderCond.Reason, renderCond.Message = metav1.ConditionFalse, ReasonValidatorError, verr.Error()
		default:
			if err := r.apply(ctx, &srv, rd); err != nil {
				if errors.Is(err, errConflict) {
					renderCond.Status, renderCond.Reason, renderCond.Message = metav1.ConditionFalse, ReasonNameConflict, err.Error()
				} else {
					applyErr = err
					renderCond.Status, renderCond.Reason, renderCond.Message = metav1.ConditionFalse, ReasonNotRendered, err.Error()
				}
			} else {
				renderCond.Status, renderCond.Reason = metav1.ConditionTrue, ReasonRendered
				renderCond.Message = "ConfigMap and Deployment hold the configuration for the current spec"
				status.ConfigChecksum = rd.Checksum
			}
		}
	}
	meta.SetStatusCondition(&status.Conditions, renderCond)

	if err := r.workloadStatus(ctx, &srv, status); err != nil {
		return ctrl.Result{}, err
	}
	if !equality.Semantic.DeepEqual(&srv.Status, status) {
		srv.Status = *status
		if err := r.Status().Update(ctx, &srv); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}
	if applyErr != nil {
		log.Error(applyErr, "applying owned objects")
		return ctrl.Result{}, applyErr
	}
	return ctrl.Result{}, nil
}

// loadPolicies fetches the referenced policies and checks that each one was
// validated for its current generation and content.
func (r *ServerReconciler) loadPolicies(ctx context.Context, srv *haltsqlv1alpha1.HaltSQLServer) ([]render.PolicyInput, metav1.Condition) {
	cond := metav1.Condition{Type: haltsqlv1alpha1.ServerConditionPoliciesReady, ObservedGeneration: srv.Generation}
	var inputs []render.PolicyInput
	var missing, invalid, pending []string
	for _, ref := range srv.Spec.Policies {
		var pol haltsqlv1alpha1.HaltSQLPolicy
		if err := r.Get(ctx, types.NamespacedName{Namespace: srv.Namespace, Name: ref.Name}, &pol); err != nil {
			if apierrors.IsNotFound(err) {
				missing = append(missing, ref.Name)
				continue
			}
			pending = append(pending, ref.Name+" ("+err.Error()+")")
			continue
		}
		hash, err := render.ContentHash(&pol.Spec)
		valid := meta.FindStatusCondition(pol.Status.Conditions, haltsqlv1alpha1.PolicyConditionValid)
		switch {
		case err != nil:
			invalid = append(invalid, ref.Name)
		case valid == nil || pol.Status.ObservedGeneration != pol.Generation || pol.Status.ContentHash != hash || valid.Status == metav1.ConditionUnknown:
			pending = append(pending, ref.Name)
		case valid.Status != metav1.ConditionTrue:
			invalid = append(invalid, ref.Name)
		default:
			inputs = append(inputs, render.PolicyInput{Ref: pol.Name, Spec: pol.Spec.DeepCopy()})
		}
	}
	switch {
	case len(missing) > 0:
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonPolicyNotFound
		cond.Message = "HaltSQLPolicy not found: " + strings.Join(missing, ", ")
	case len(invalid) > 0:
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonPolicyNotValid
		cond.Message = "HaltSQLPolicy not valid: " + strings.Join(invalid, ", ")
	case len(pending) > 0:
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonPolicyPending
		cond.Message = "HaltSQLPolicy not validated yet: " + strings.Join(pending, ", ")
	default:
		cond.Status, cond.Reason = metav1.ConditionTrue, ReasonPoliciesReady
		cond.Message = fmt.Sprintf("%d policies valid", len(inputs))
	}
	return inputs, cond
}

// apply creates or updates every owned object.
func (r *ServerReconciler) apply(ctx context.Context, srv *haltsqlv1alpha1.HaltSQLServer, rd *render.Rendered) error {
	cm := render.ConfigMap(srv, rd)
	if err := r.upsert(ctx, srv, &corev1.ConfigMap{}, cm.Name, func(obj client.Object) {
		c := obj.(*corev1.ConfigMap)
		c.Data = cm.Data
		c.BinaryData = nil
	}, render.SpecHash(cm.Data)); err != nil {
		return err
	}

	applied, err := json.Marshal(rd.Applied)
	if err != nil {
		return err
	}
	depSpec := render.DeploymentSpec(srv, rd)
	if err := r.upsert(ctx, srv, &appsv1.Deployment{}, srv.Name, func(obj client.Object) {
		d := obj.(*appsv1.Deployment)
		if d.CreationTimestamp.IsZero() {
			d.Spec = depSpec
		} else {
			// The selector is immutable; it never changes for a server.
			sel := d.Spec.Selector
			d.Spec = depSpec
			if sel != nil {
				d.Spec.Selector = sel
			}
		}
		setAnnotation(d, annotationAppliedPolicies, string(applied))
	}, render.SpecHash(struct {
		S appsv1.DeploymentSpec
		A string
	}{depSpec, string(applied)})); err != nil {
		return err
	}

	svcSpec := render.ServiceSpec(srv)
	if err := r.upsert(ctx, srv, &corev1.Service{}, srv.Name, func(obj client.Object) {
		s := obj.(*corev1.Service)
		// Keep what the API server allocated (cluster IPs, node ports).
		old := map[string]int32{}
		for _, p := range s.Spec.Ports {
			old[p.Name] = p.NodePort
		}
		s.Spec.Type = svcSpec.Type
		s.Spec.Selector = svcSpec.Selector
		ports := svcSpec.Ports
		for i := range ports {
			if svcSpec.Type != corev1.ServiceTypeClusterIP {
				ports[i].NodePort = old[ports[i].Name]
			}
		}
		s.Spec.Ports = ports
		s.Annotations = mergeAnnotations(s.Annotations, srv.Spec.Service.Annotations)
	}, render.SpecHash(struct {
		S corev1.ServiceSpec
		A map[string]string
	}{svcSpec, srv.Spec.Service.Annotations})); err != nil {
		return err
	}

	if pdb := render.PDBSpec(srv); pdb != nil {
		if err := r.upsert(ctx, srv, &policyv1.PodDisruptionBudget{}, srv.Name, func(obj client.Object) {
			obj.(*policyv1.PodDisruptionBudget).Spec = *pdb
		}, render.SpecHash(pdb)); err != nil {
			return err
		}
	} else if err := r.deleteOwned(ctx, srv, &policyv1.PodDisruptionBudget{}, srv.Name); err != nil {
		return err
	}

	if np := render.NetworkPolicySpec(srv, rd); np != nil {
		if err := r.upsert(ctx, srv, &networkingv1.NetworkPolicy{}, srv.Name, func(obj client.Object) {
			obj.(*networkingv1.NetworkPolicy).Spec = *np
		}, render.SpecHash(np)); err != nil {
			return err
		}
	} else if err := r.deleteOwned(ctx, srv, &networkingv1.NetworkPolicy{}, srv.Name); err != nil {
		return err
	}
	return nil
}

// upsert creates obj (named name) or updates it when the desired spec hash
// changed. It refuses to touch an object the server does not control.
func (r *ServerReconciler) upsert(ctx context.Context, srv *haltsqlv1alpha1.HaltSQLServer, obj client.Object, name string, mutate func(client.Object), hash string) error {
	key := types.NamespacedName{Namespace: srv.Namespace, Name: name}
	err := r.Get(ctx, key, obj)
	switch {
	case apierrors.IsNotFound(err):
		obj.SetName(name)
		obj.SetNamespace(srv.Namespace)
		obj.SetLabels(render.Labels(srv))
		mutate(obj)
		setAnnotation(obj, render.AnnotationSpecHash, hash)
		if err := controllerutil.SetControllerReference(srv, obj, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, obj); err != nil {
			if apierrors.IsAlreadyExists(err) {
				// The cache only sees objects with our label: this name is
				// taken by an object the operator does not manage.
				return fmt.Errorf("%w: %T %s already exists and is not managed by haltsql-operator", errConflict, obj, name)
			}
			return err
		}
		return nil
	case err != nil:
		return err
	}
	if !metav1.IsControlledBy(obj, srv) {
		return fmt.Errorf("%w: %T %s is not controlled by HaltSQLServer %s", errConflict, obj, name, srv.Name)
	}
	before := obj.DeepCopyObject().(client.Object)
	if obj.GetAnnotations()[render.AnnotationSpecHash] != hash {
		mutate(obj)
		setAnnotation(obj, render.AnnotationSpecHash, hash)
	}
	l := obj.GetLabels()
	if l == nil {
		l = map[string]string{}
	}
	for k, v := range render.Labels(srv) {
		l[k] = v
	}
	obj.SetLabels(l)
	if equality.Semantic.DeepEqual(before, obj) {
		return nil
	}
	return r.Update(ctx, obj)
}

func (r *ServerReconciler) deleteOwned(ctx context.Context, srv *haltsqlv1alpha1.HaltSQLServer, obj client.Object, name string) error {
	if err := r.Get(ctx, types.NamespacedName{Namespace: srv.Namespace, Name: name}, obj); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(obj, srv) {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, obj))
}

// workloadStatus fills replica counts, AppliedPolicies and the Available,
// Progressing and Ready conditions from the Deployment.
func (r *ServerReconciler) workloadStatus(ctx context.Context, srv *haltsqlv1alpha1.HaltSQLServer, status *haltsqlv1alpha1.HaltSQLServerStatus) error {
	gen := srv.Generation
	var dep appsv1.Deployment
	err := r.Get(ctx, types.NamespacedName{Namespace: srv.Namespace, Name: srv.Name}, &dep)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if apierrors.IsNotFound(err) || !metav1.IsControlledBy(&dep, srv) {
		status.Replicas, status.ReadyReplicas, status.UpdatedReplicas = 0, 0, 0
		status.AppliedPolicies = nil
		msg := "the Deployment has not been created"
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: haltsqlv1alpha1.ServerConditionAvailable, Status: metav1.ConditionFalse, Reason: ReasonDeploymentMissing, Message: msg, ObservedGeneration: gen})
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: haltsqlv1alpha1.ServerConditionProgressing, Status: metav1.ConditionFalse, Reason: ReasonDeploymentMissing, Message: msg, ObservedGeneration: gen})
		r.readyCondition(status, gen, false, false)
		return nil
	}
	status.Replicas = dep.Status.Replicas
	status.ReadyReplicas = dep.Status.ReadyReplicas
	status.UpdatedReplicas = dep.Status.UpdatedReplicas

	want := int32(1)
	if dep.Spec.Replicas != nil {
		want = *dep.Spec.Replicas
	}
	rendered := meta.IsStatusConditionTrue(status.Conditions, haltsqlv1alpha1.ServerConditionConfigRendered)
	depComplete := dep.Status.ObservedGeneration >= dep.Generation &&
		dep.Status.UpdatedReplicas == want &&
		dep.Status.Replicas == want &&
		dep.Status.AvailableReplicas == want
	complete := rendered &&
		depComplete &&
		dep.Spec.Template.Annotations[render.AnnotationConfigChecksum] == status.ConfigChecksum
	failed := false
	for _, c := range dep.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse && c.Reason == "ProgressDeadlineExceeded" {
			failed = true
		}
	}
	available := want == 0
	for _, c := range dep.Status.Conditions {
		if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionTrue && dep.Status.AvailableReplicas > 0 {
			available = true
		}
	}

	if depComplete {
		var applied []haltsqlv1alpha1.AppliedPolicy
		if a := dep.Annotations[annotationAppliedPolicies]; a != "" {
			if err := json.Unmarshal([]byte(a), &applied); err != nil {
				applied = nil
			}
		}
		sort.Slice(applied, func(i, j int) bool { return applied[i].Name < applied[j].Name })
		status.AppliedPolicies = applied
	}

	avail := metav1.Condition{Type: haltsqlv1alpha1.ServerConditionAvailable, ObservedGeneration: gen}
	switch {
	case want == 0:
		avail.Status, avail.Reason, avail.Message = metav1.ConditionTrue, ReasonScaledToZero, "replicas is 0"
	case available:
		avail.Status, avail.Reason = metav1.ConditionTrue, ReasonReady
		avail.Message = fmt.Sprintf("%d of %d replicas ready", dep.Status.ReadyReplicas, want)
	default:
		avail.Status, avail.Reason = metav1.ConditionFalse, ReasonUnavailable
		avail.Message = fmt.Sprintf("%d of %d replicas ready", dep.Status.ReadyReplicas, want)
	}
	meta.SetStatusCondition(&status.Conditions, avail)

	prog := metav1.Condition{Type: haltsqlv1alpha1.ServerConditionProgressing, ObservedGeneration: gen}
	switch {
	case complete:
		prog.Status, prog.Reason, prog.Message = metav1.ConditionFalse, ReasonRolloutComplete, "all replicas run the current configuration"
	case !rendered && depComplete:
		prog.Status, prog.Reason, prog.Message = metav1.ConditionFalse, ReasonNotRendered, "waiting for a valid configuration; all replicas run the last rendered configuration"
	case failed:
		prog.Status, prog.Reason = metav1.ConditionFalse, ReasonRolloutFailed
		prog.Message = "new pods did not become ready before the progress deadline; ready pods with the previous configuration keep serving (check the pod logs for the haltsql-server load error)"
	default:
		prog.Status, prog.Reason = metav1.ConditionTrue, ReasonRollingOut
		prog.Message = fmt.Sprintf("%d of %d replicas updated, %d available", dep.Status.UpdatedReplicas, want, dep.Status.AvailableReplicas)
	}
	meta.SetStatusCondition(&status.Conditions, prog)
	r.readyCondition(status, gen, complete, available)
	return nil
}

func (r *ServerReconciler) readyCondition(status *haltsqlv1alpha1.HaltSQLServerStatus, gen int64, complete, available bool) {
	ready := metav1.Condition{Type: haltsqlv1alpha1.ServerConditionReady, ObservedGeneration: gen}
	for _, t := range []string{haltsqlv1alpha1.ServerConditionPoliciesReady, haltsqlv1alpha1.ServerConditionConfigRendered} {
		if c := meta.FindStatusCondition(status.Conditions, t); c == nil || c.Status != metav1.ConditionTrue {
			ready.Status = metav1.ConditionFalse
			if c != nil {
				ready.Reason, ready.Message = c.Reason, c.Message
			} else {
				ready.Reason, ready.Message = ReasonNotRendered, t+" is unknown"
			}
			meta.SetStatusCondition(&status.Conditions, ready)
			return
		}
	}
	prog := meta.FindStatusCondition(status.Conditions, haltsqlv1alpha1.ServerConditionProgressing)
	switch {
	case !available:
		ready.Status, ready.Reason, ready.Message = metav1.ConditionFalse, ReasonUnavailable, "no ready replica"
	case !complete:
		ready.Status, ready.Reason = metav1.ConditionFalse, prog.Reason
		ready.Message = prog.Message
	default:
		ready.Status, ready.Reason, ready.Message = metav1.ConditionTrue, ReasonReady, "the current configuration runs on every replica"
	}
	meta.SetStatusCondition(&status.Conditions, ready)
}

func setAnnotation(obj client.Object, k, v string) {
	a := obj.GetAnnotations()
	if a == nil {
		a = map[string]string{}
	}
	a[k] = v
	obj.SetAnnotations(a)
}

func mergeAnnotations(existing, desired map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range existing {
		if strings.HasPrefix(k, "haltsql.dev/") {
			out[k] = v
		}
	}
	for k, v := range desired {
		out[k] = v
	}
	return out
}

func controllerOptions(maxDelay time.Duration) controller.Options {
	return controller.Options{
		RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](500*time.Millisecond, maxDelay),
	}
}

func policyRelevantPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPol, ok1 := e.ObjectOld.(*haltsqlv1alpha1.HaltSQLPolicy)
			newPol, ok2 := e.ObjectNew.(*haltsqlv1alpha1.HaltSQLPolicy)
			if !ok1 || !ok2 {
				return true
			}
			if oldPol.Generation != newPol.Generation ||
				oldPol.Status.ObservedGeneration != newPol.Status.ObservedGeneration ||
				oldPol.Status.ContentHash != newPol.Status.ContentHash ||
				oldPol.Status.PolicyName != newPol.Status.PolicyName {
				return true
			}
			oldValid := meta.FindStatusCondition(oldPol.Status.Conditions, haltsqlv1alpha1.PolicyConditionValid)
			newValid := meta.FindStatusCondition(newPol.Status.Conditions, haltsqlv1alpha1.PolicyConditionValid)
			if (oldValid == nil) != (newValid == nil) {
				return true
			}
			if oldValid != nil && (oldValid.Status != newValid.Status || oldValid.Reason != newValid.Reason || oldValid.Message != newValid.Message || oldValid.ObservedGeneration != newValid.ObservedGeneration) {
				return true
			}
			return false
		},
	}
}

// SetupWithManager registers the reconciler.
func (r *ServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&haltsqlv1alpha1.HaltSQLServer{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Watches(&haltsqlv1alpha1.HaltSQLPolicy{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				var servers haltsqlv1alpha1.HaltSQLServerList
				if err := mgr.GetClient().List(ctx, &servers, client.InNamespace(o.GetNamespace()),
					client.MatchingFields{policyRefIndex: o.GetName()}); err != nil {
					logf.FromContext(ctx).Error(err, "listing HaltSQLServers for policy", "policy", o.GetName())
					return nil
				}
				reqs := make([]reconcile.Request, 0, len(servers.Items))
				for _, s := range servers.Items {
					reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: s.Namespace, Name: s.Name}})
				}
				return reqs
			}), builder.WithPredicates(policyRelevantPredicate())).
		Named("haltsqlserver").
		WithOptions(controllerOptions(60 * time.Second)).
		Complete(r)
}
