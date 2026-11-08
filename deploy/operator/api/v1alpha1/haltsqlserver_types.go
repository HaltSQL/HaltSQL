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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Condition types used on HaltSQLServer.
const (
	// ServerConditionPoliciesReady is True when every referenced policy exists,
	// is Valid for its current generation and the rendered config is consistent.
	ServerConditionPoliciesReady = "PoliciesReady"
	// ServerConditionConfigRendered is True when the ConfigMap holds the
	// configuration for the current spec and policies.
	ServerConditionConfigRendered = "ConfigRendered"
	// ServerConditionAvailable mirrors the Deployment's Available condition.
	ServerConditionAvailable = "Available"
	// ServerConditionProgressing is True while a rollout is in progress.
	ServerConditionProgressing = "Progressing"
	// ServerConditionReady is True when the current configuration is rolled
	// out to every replica.
	ServerConditionReady = "Ready"
)

// HaltSQLServerSpec defines a haltsql-server Deployment.
// +kubebuilder:validation:XValidation:rule="!has(self.auth) || !has(self.auth.mtls) || !has(self.auth.mtls.identities) || size(self.auth.mtls.identities) == 0 || (has(self.tls) && has(self.tls.clientAuth) && self.tls.clientAuth != 'none')",message="auth.mtls.identities need tls with clientAuth optional or required"
type HaltSQLServerSpec struct {
	// Replicas is the number of haltsql-server pods (default 2).
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	Replicas *int32 `json:"replicas,omitempty"`

	// Image is the haltsql container image. Pin a digest in production.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Image string `json:"image"`
	// +optional
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Policies are the HaltSQLPolicies (in this namespace) the server loads.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=name
	Policies []PolicyReference `json:"policies"`

	// Config holds the non-policy server settings.
	// +optional
	Config ServerConfig `json:"config,omitempty"`

	// Auth configures who may call the server.
	// +optional
	Auth *ServerAuth `json:"auth,omitempty"`

	// TLS enables haltsql-server's built-in TLS from a kubernetes.io/tls Secret.
	// +optional
	TLS *ServerTLS `json:"tls,omitempty"`

	// Audit configures audit sinks.
	// +optional
	Audit *ServerAudit `json:"audit,omitempty"`

	// Env adds environment variables to the haltsql container, for example
	// AWS_* variables from a Secret for `credentials: {source: env}`, used by
	// ${env:NAME} placeholders in the raw config sections.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// ServiceAccountName runs the pods as this ServiceAccount (default: the
	// namespace's default ServiceAccount).
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// AutomountServiceAccountToken mounts the ServiceAccount token (default
	// false; Vault Kubernetes auth needs true).
	// +optional
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Service configures the Service in front of the pods.
	// +optional
	Service ServiceSpec `json:"service,omitempty"`
	// PodDisruptionBudget is created when enabled.
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`
	// NetworkPolicy is created when enabled.
	// +optional
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`
}

// PolicyReference names a HaltSQLPolicy in the same namespace.
type PolicyReference struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// ServerConfig holds the non-policy settings rendered into the Config document.
type ServerConfig struct {
	// DefaultPolicy is the policy used for requests that name none.
	// +optional
	DefaultPolicy string `json:"defaultPolicy,omitempty"`
	// AllowUnauthenticated accepts requests without credentials. For
	// development only.
	// +optional
	AllowUnauthenticated bool `json:"allowUnauthenticated,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=debug;info;warn;error
	LogLevel string `json:"logLevel,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=json;text
	LogFormat string `json:"logFormat,omitempty"`
	// MaxRequestBytes is the largest accepted request body (1024-67108864).
	// +optional
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=67108864
	MaxRequestBytes *int64 `json:"maxRequestBytes,omitempty"`
	// Telemetry is rendered verbatim as the config's `telemetry` section.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	Telemetry *apiextensionsv1.JSON `json:"telemetry,omitempty"`
	// OPA is rendered verbatim as the config's `opa` section.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	OPA *apiextensionsv1.JSON `json:"opa,omitempty"`
	// Admin is rendered verbatim as `server.admin`.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	Admin *apiextensionsv1.JSON `json:"admin,omitempty"`
	// Secrets is rendered verbatim as the config's `secrets` section
	// (Vault, AWS or GCP secret providers).
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	Secrets *apiextensionsv1.JSON `json:"secrets,omitempty"`
}

// ServerAuth configures caller authentication.
type ServerAuth struct {
	// Tokens are static bearer tokens; only their SHA-256 hashes are stored,
	// in Secrets.
	// +optional
	// +kubebuilder:validation:MaxItems=1024
	// +listType=map
	// +listMapKey=name
	Tokens []TokenSpec `json:"tokens,omitempty"`
	// OIDC providers, each rendered verbatim as a `server.auth.oidc` entry.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:Type=object
	OIDC []apiextensionsv1.JSON `json:"oidc,omitempty"`
	// MTLS identities (need tls with clientAuth optional or required and a
	// ca.crt in the TLS Secret).
	// +optional
	MTLS *MTLSSpec `json:"mtls,omitempty"`
}

// TokenSpec is one static token.
type TokenSpec struct {
	// Name labels the token in logs and audit records.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Name string `json:"name"`
	// Policy is the policy name (metadata.name of the policy document) the
	// token is pinned to.
	// +kubebuilder:validation:MinLength=1
	Policy string `json:"policy"`
	// SHA256SecretRef selects a Secret key holding the lower-case hex
	// SHA-256 of the token (a trailing newline is ignored).
	SHA256SecretRef SecretKeyRef `json:"sha256SecretRef"`
}

// SecretKeyRef selects one key of a Secret in the same namespace.
type SecretKeyRef struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key"`
}

// MTLSSpec lists client-certificate identities.
type MTLSSpec struct {
	// Identities, each rendered verbatim as a `server.auth.mtls.identities` entry.
	// +optional
	// +kubebuilder:validation:MaxItems=1024
	// +kubebuilder:validation:items:Type=object
	Identities []apiextensionsv1.JSON `json:"identities,omitempty"`
}

// ServerTLS configures built-in TLS.
type ServerTLS struct {
	// SecretName is a kubernetes.io/tls Secret with tls.crt, tls.key and, for
	// client certificates, ca.crt.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	SecretName string `json:"secretName"`
	// ClientAuth is none, optional or required (default none).
	// +optional
	// +kubebuilder:default=none
	// +kubebuilder:validation:Enum=none;optional;required
	ClientAuth string `json:"clientAuth,omitempty"`
	// MinVersion is "1.2" or "1.3" (default "1.2").
	// +optional
	// +kubebuilder:validation:Enum="1.2";"1.3"
	MinVersion string `json:"minVersion,omitempty"`
}

// ServerAudit configures audit logging.
type ServerAudit struct {
	// LogRawSQL includes raw SQL in audit records (off by default).
	// +optional
	LogRawSQL bool `json:"logRawSQL,omitempty"`
	// Sinks, each rendered verbatim as an `audit.sinks` entry (default
	// [{type: stdout}]). Anywhere in a sink, an object of the exact form
	// {secretKeyRef: {name, key}} is replaced by the Secret value (mounted
	// into the pods, never read by the operator).
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:Type=object
	Sinks []apiextensionsv1.JSON `json:"sinks,omitempty"`
}

// ServiceSpec configures the Service.
type ServiceSpec struct {
	// +optional
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	Type corev1.ServiceType `json:"type,omitempty"`
	// Port is the Service port (default 8080).
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PodDisruptionBudgetSpec configures the optional PodDisruptionBudget.
// +kubebuilder:validation:XValidation:rule="!(has(self.minAvailable) && has(self.maxUnavailable))",message="set at most one of minAvailable and maxUnavailable"
type PodDisruptionBudgetSpec struct {
	Enabled bool `json:"enabled"`
	// MinAvailable defaults to 1 when neither field is set.
	// +optional
	MinAvailable *intstr.IntOrString `json:"minAvailable,omitempty"`
	// +optional
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`
}

// NetworkPolicySpec configures the optional NetworkPolicy. When enabled, only
// the listed peers reach the API port (no peers: any pod in the namespace).
type NetworkPolicySpec struct {
	Enabled bool `json:"enabled"`
	// IngressFrom are the peers allowed to call the API port.
	// +optional
	IngressFrom []networkingv1.NetworkPolicyPeer `json:"ingressFrom,omitempty"`
}

// AppliedPolicy records the content of one policy a server runs.
type AppliedPolicy struct {
	// Name of the HaltSQLPolicy.
	Name string `json:"name"`
	// ContentHash of the policy content in the rolled-out configuration.
	ContentHash string `json:"contentHash"`
}

// HaltSQLServerStatus is the observed state of a HaltSQLServer.
type HaltSQLServerStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Replicas int32 `json:"replicas,omitempty"`
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`
	// +optional
	UpdatedReplicas int32 `json:"updatedReplicas,omitempty"`
	// ConfigChecksum is the checksum of the rendered configuration.
	// +optional
	ConfigChecksum string `json:"configChecksum,omitempty"`
	// AppliedPolicies are the policies (and their content hashes) of the
	// configuration that is fully rolled out.
	// +optional
	// +listType=map
	// +listMapKey=name
	AppliedPolicies []AppliedPolicy `json:"appliedPolicies,omitempty"`
	// Selector is the label selector of the pods (for the scale subresource).
	// +optional
	Selector string `json:"selector,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:scale:specpath=.spec.replicas,statuspath=.status.replicas,selectorpath=.status.selector
// +kubebuilder:resource:shortName=hsqlserver;hsqls,categories=haltsql
// +kubebuilder:printcolumn:name="Replicas",type=integer,JSONPath=`.spec.replicas`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HaltSQLServer runs haltsql-server with a set of HaltSQLPolicies.
type HaltSQLServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HaltSQLServerSpec   `json:"spec,omitempty"`
	Status HaltSQLServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HaltSQLServerList contains a list of HaltSQLServer.
type HaltSQLServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HaltSQLServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HaltSQLServer{}, &HaltSQLServerList{})
}
