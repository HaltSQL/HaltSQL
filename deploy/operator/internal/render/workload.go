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

package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	haltsqlv1alpha1 "github.com/ardada2468/HaltSQL/deploy/operator/api/v1alpha1"
)

// Labels and annotations set by the operator.
const (
	LabelName      = "app.kubernetes.io/name"
	LabelInstance  = "app.kubernetes.io/instance"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelComponent = "app.kubernetes.io/component"
	ManagedBy      = "haltsql-operator"

	// AnnotationConfigChecksum on the pod template rolls the pods when the
	// rendered configuration changes.
	AnnotationConfigChecksum = "haltsql.dev/config-checksum"
	// AnnotationSpecHash on owned objects records the desired spec the
	// operator last applied, so unchanged objects are not rewritten.
	AnnotationSpecHash = "haltsql.dev/spec-hash"
)

// ConfigMapName is the name of the server's ConfigMap.
func ConfigMapName(srv *haltsqlv1alpha1.HaltSQLServer) string { return srv.Name + "-haltsql-config" }

// SelectorLabels select the pods of srv. They never change for a server.
func SelectorLabels(srv *haltsqlv1alpha1.HaltSQLServer) map[string]string {
	return map[string]string{LabelName: "haltsql", LabelInstance: srv.Name}
}

// Labels are put on every object the operator creates for srv.
func Labels(srv *haltsqlv1alpha1.HaltSQLServer) map[string]string {
	l := SelectorLabels(srv)
	l[LabelManagedBy] = ManagedBy
	l[LabelComponent] = "server"
	return l
}

// SpecHash hashes any JSON-serialisable desired spec.
func SpecHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Only unserialisable values (channels, funcs) fail; the specs here
		// are plain API structs.
		panic(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:16])
}

// ConfigMap returns the desired ConfigMap.
func ConfigMap(srv *haltsqlv1alpha1.HaltSQLServer, r *Rendered) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ConfigMapName(srv), Namespace: srv.Namespace, Labels: Labels(srv)},
		Data:       r.Data,
	}
}

// DeploymentSpec returns the desired Deployment spec.
func DeploymentSpec(srv *haltsqlv1alpha1.HaltSQLServer, r *Rendered) appsv1.DeploymentSpec {
	s := srv.Spec
	podLabels := map[string]string{}
	for k, v := range s.PodLabels {
		podLabels[k] = v
	}
	for k, v := range Labels(srv) {
		podLabels[k] = v
	}
	podAnnotations := map[string]string{}
	for k, v := range s.PodAnnotations {
		podAnnotations[k] = v
	}
	podAnnotations[AnnotationConfigChecksum] = r.Checksum

	volumes := []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: ConfigMapName(srv)},
			DefaultMode:          ptr.To[int32](0o444),
		}}},
		{Name: "audit-log", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("256Mi"))}}},
		{Name: "bundle-cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("128Mi"))}}},
	}
	mounts := []corev1.VolumeMount{
		{Name: "config", MountPath: ConfigDir, ReadOnly: true},
		{Name: "audit-log", MountPath: "/var/log/haltsql"},
		{Name: "bundle-cache", MountPath: "/var/cache/haltsql"},
	}
	if len(r.Secrets) > 0 {
		// One projected volume; each key lands at <secret>/<key>. Grouping by
		// Secret keeps one source per Secret.
		var sources []corev1.VolumeProjection
		idx := map[string]int{}
		for _, ref := range r.Secrets {
			i, ok := idx[ref.Name]
			if !ok {
				i = len(sources)
				idx[ref.Name] = i
				sources = append(sources, corev1.VolumeProjection{Secret: &corev1.SecretProjection{
					LocalObjectReference: corev1.LocalObjectReference{Name: ref.Name},
				}})
			}
			sources[i].Secret.Items = append(sources[i].Secret.Items, corev1.KeyToPath{Key: ref.Key, Path: ref.Name + "/" + ref.Key})
		}
		volumes = append(volumes, corev1.Volume{Name: "secrets", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources:     sources,
			DefaultMode: ptr.To[int32](0o440),
		}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "secrets", MountPath: SecretsDir, ReadOnly: true})
	}
	if r.TLSSecret != "" {
		volumes = append(volumes, corev1.Volume{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  r.TLSSecret,
			DefaultMode: ptr.To[int32](0o440),
		}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "tls", MountPath: TLSDir, ReadOnly: true})
	}

	args := []string{"--config", ConfigDir + "/" + ConfigFile}
	ports := []corev1.ContainerPort{{Name: "http", ContainerPort: ListenPort, Protocol: corev1.ProtocolTCP}}
	probePort := intstr.FromString("http")
	if r.HealthPort {
		args = append(args, "--health-listen", "0.0.0.0:"+strconv.Itoa(HealthPort))
		ports = append(ports, corev1.ContainerPort{Name: "health", ContainerPort: HealthPort, Protocol: corev1.ProtocolTCP})
		probePort = intstr.FromString("health")
	}
	env := append([]corev1.EnvVar{{Name: "HALTSQL_LISTEN", Value: "0.0.0.0:" + strconv.Itoa(ListenPort)}}, s.Env...)

	resources := s.Resources
	if resources.Requests == nil && resources.Limits == nil {
		resources = corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
		}
	}

	container := corev1.Container{
		Name:            "haltsql",
		Image:           s.Image,
		ImagePullPolicy: s.ImagePullPolicy,
		Args:            args,
		Env:             env,
		Ports:           ports,
		VolumeMounts:    mounts,
		Resources:       resources,
		LivenessProbe: &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: probePort}},
			InitialDelaySeconds: 2, PeriodSeconds: 10, TimeoutSeconds: 2, FailureThreshold: 3,
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: probePort}},
			InitialDelaySeconds: 1, PeriodSeconds: 5, TimeoutSeconds: 2, FailureThreshold: 2,
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
			RunAsNonRoot:             ptr.To(true),
			Privileged:               ptr.To(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}
	automount := false
	if s.AutomountServiceAccountToken != nil {
		automount = *s.AutomountServiceAccountToken
	}
	replicas := int32(2)
	if s.Replicas != nil {
		replicas = *s.Replicas
	}
	return appsv1.DeploymentSpec{
		Replicas:                &replicas,
		Selector:                &metav1.LabelSelector{MatchLabels: SelectorLabels(srv)},
		RevisionHistoryLimit:    ptr.To[int32](5),
		ProgressDeadlineSeconds: ptr.To[int32](180),
		// Never take a ready pod away before its replacement is ready: a
		// configuration that does not start leaves the old pods serving.
		Strategy: appsv1.DeploymentStrategy{
			Type: appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{
				MaxUnavailable: ptr.To(intstr.FromInt32(0)),
				MaxSurge:       ptr.To(intstr.FromInt32(1)),
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
			Spec: corev1.PodSpec{
				ServiceAccountName:            s.ServiceAccountName,
				AutomountServiceAccountToken:  ptr.To(automount),
				ImagePullSecrets:              s.ImagePullSecrets,
				TerminationGracePeriodSeconds: ptr.To[int64](20),
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot:   ptr.To(true),
					RunAsUser:      ptr.To[int64](65532),
					RunAsGroup:     ptr.To[int64](65532),
					FSGroup:        ptr.To[int64](65532),
					SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
				Containers:                []corev1.Container{container},
				Volumes:                   volumes,
				NodeSelector:              s.NodeSelector,
				Tolerations:               s.Tolerations,
				Affinity:                  s.Affinity,
				TopologySpreadConstraints: s.TopologySpreadConstraints,
			},
		},
	}
}

// ServicePort is the Service port (default 8080).
func ServicePort(srv *haltsqlv1alpha1.HaltSQLServer) int32 {
	if srv.Spec.Service.Port != 0 {
		return srv.Spec.Service.Port
	}
	return ListenPort
}

// ServiceSpec returns the desired Service spec (ClusterIP is left to the
// API server).
func ServiceSpec(srv *haltsqlv1alpha1.HaltSQLServer) corev1.ServiceSpec {
	t := srv.Spec.Service.Type
	if t == "" {
		t = corev1.ServiceTypeClusterIP
	}
	return corev1.ServiceSpec{
		Type:     t,
		Selector: SelectorLabels(srv),
		Ports: []corev1.ServicePort{{
			Name: "http", Port: ServicePort(srv), TargetPort: intstr.FromString("http"), Protocol: corev1.ProtocolTCP,
		}},
	}
}

// PDBSpec returns the desired PodDisruptionBudget spec, or nil when disabled.
func PDBSpec(srv *haltsqlv1alpha1.HaltSQLServer) *policyv1.PodDisruptionBudgetSpec {
	p := srv.Spec.PodDisruptionBudget
	if p == nil || !p.Enabled {
		return nil
	}
	spec := &policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: SelectorLabels(srv)}}
	switch {
	case p.MaxUnavailable != nil:
		spec.MaxUnavailable = p.MaxUnavailable
	case p.MinAvailable != nil:
		spec.MinAvailable = p.MinAvailable
	default:
		spec.MinAvailable = ptr.To(intstr.FromInt32(1))
	}
	return spec
}

// NetworkPolicySpec returns the desired NetworkPolicy spec, or nil when
// disabled. The API port accepts the listed peers (no peers: pods in the
// same namespace); the health port, when used, accepts any source so kubelet
// probes keep working.
func NetworkPolicySpec(srv *haltsqlv1alpha1.HaltSQLServer, r *Rendered) *networkingv1.NetworkPolicySpec {
	n := srv.Spec.NetworkPolicy
	if n == nil || !n.Enabled {
		return nil
	}
	from := n.IngressFrom
	if len(from) == 0 {
		from = []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}
	}
	tcp := corev1.ProtocolTCP
	rules := []networkingv1.NetworkPolicyIngressRule{{
		From:  from,
		Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: ptr.To(intstr.FromInt32(ListenPort))}},
	}}
	if r.HealthPort {
		rules = append(rules, networkingv1.NetworkPolicyIngressRule{
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: ptr.To(intstr.FromInt32(HealthPort))}},
		})
	}
	return &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: SelectorLabels(srv)},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     rules,
	}
}
