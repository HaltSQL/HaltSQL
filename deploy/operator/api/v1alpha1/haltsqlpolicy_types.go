/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition types and reasons used on HaltSQLPolicy.
const (
	// PolicyConditionValid is True when the current spec passed `haltsql validate`.
	PolicyConditionValid = "Valid"
	// PolicyConditionSynced is True when every HaltSQLServer that references
	// this policy runs its current content.
	PolicyConditionSynced = "Synced"
)

// HaltSQLPolicySpec defines one HaltSQL policy: either an inline policy
// document or a signed bundle fetched by haltsql-server.
// +kubebuilder:validation:XValidation:rule="has(self.policy) != has(self.bundleSource)",message="exactly one of spec.policy or spec.bundleSource is required"
type HaltSQLPolicySpec struct {
	// Policy is a complete HaltSQL policy document (kind: Policy) as a YAML
	// or JSON string. It must not reference a catalog file (`catalog: <path>`);
	// write the catalog snapshot inline instead.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=262144
	Policy string `json:"policy,omitempty"`

	// BundleSource is a signed policy bundle that haltsql-server fetches from
	// an OCI registry, S3 (or an S3-compatible store) or HTTPS and polls for
	// updates. Signature verification is mandatory.
	// +optional
	BundleSource *BundleSource `json:"bundleSource,omitempty"`
}

// BundleSource is rendered as a `bundle_source` entry in the server config.
// +kubebuilder:validation:XValidation:rule="(has(self.oci) ? 1 : 0) + (has(self.s3) ? 1 : 0) + (has(self.https) ? 1 : 0) == 1",message="exactly one of oci, s3 or https is required"
type BundleSource struct {
	// OCI fetches the bundle from an OCI registry.
	// +optional
	OCI *OCIBundleSource `json:"oci,omitempty"`
	// S3 fetches the bundle from an S3 object.
	// +optional
	S3 *S3BundleSource `json:"s3,omitempty"`
	// HTTPS fetches the bundle from an HTTPS URL.
	// +optional
	HTTPS *HTTPSBundleSource `json:"https,omitempty"`

	// PublicKeys are the trusted ed25519 public keys: inline PEM
	// (-----BEGIN PUBLIC KEY-----) or the base64 of the 32 raw key bytes.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=4096
	PublicKeys []string `json:"publicKeys"`

	// NamePrefix is prepended to the names of the bundle's policies.
	// +optional
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`
	NamePrefix string `json:"namePrefix,omitempty"`

	// PollIntervalSeconds is the time between update checks (10-86400, default 60).
	// +optional
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=86400
	PollIntervalSeconds *int32 `json:"pollIntervalSeconds,omitempty"`
}

// OCIBundleSource is an OCI artifact reference.
type OCIBundleSource struct {
	// Ref is `registry[:port]/repository:tag`, `...@sha256:<digest>` or both.
	// The registry host is mandatory. Pin a digest for immutable deployments.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Ref string `json:"ref"`
	// PlainHTTP talks plain HTTP to the registry. haltsql only accepts it for
	// loopback registries (local tests).
	// +optional
	PlainHTTP bool `json:"plainHTTP,omitempty"`
	// Auth reads registry credentials from a Secret.
	// +optional
	Auth *BundleAuth `json:"auth,omitempty"`
}

// HTTPSBundleSource is an HTTPS URL.
type HTTPSBundleSource struct {
	// URL is an https URL without credentials, query or fragment.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	URL string `json:"url"`
	// Auth reads credentials from a Secret.
	// +optional
	Auth *BundleAuth `json:"auth,omitempty"`
}

// BundleAuth reads bundle-source credentials from a Secret in the same
// namespace. The operator never reads the Secret: it is mounted into the
// haltsql-server pods and referenced with ${file:...} placeholders.
// +kubebuilder:validation:XValidation:rule="self.type == 'token' ? !has(self.usernameKey) && !has(self.passwordKey) : !has(self.tokenKey)",message="tokenKey is only allowed with type token; usernameKey and passwordKey only with type basic"
type BundleAuth struct {
	// SecretName is the name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	SecretName string `json:"secretName"`
	// Type is `token` (bearer token) or `basic` (username and password).
	// +kubebuilder:validation:Enum=token;basic
	Type string `json:"type"`
	// TokenKey is the Secret key holding the token (default `token`).
	// +optional
	TokenKey string `json:"tokenKey,omitempty"`
	// UsernameKey is the Secret key holding the user name (default `username`).
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`
	// PasswordKey is the Secret key holding the password (default `password`).
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`
}

// S3BundleSource is an S3 object.
type S3BundleSource struct {
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=63
	Bucket string `json:"bucket"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Key string `json:"key"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Region string `json:"region"`
	// Endpoint is an S3-compatible URL (for example MinIO).
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	Endpoint string `json:"endpoint,omitempty"`
	// Credentials selects how haltsql-server authenticates to S3.
	// +optional
	Credentials *S3Credentials `json:"credentials,omitempty"`
}

// S3Credentials mirrors the haltsql `credentials` shape.
// +kubebuilder:validation:XValidation:rule="self.source == 'static' ? has(self.secretName) : !has(self.secretName) && !has(self.accessKeyIDKey) && !has(self.secretAccessKeyKey) && !has(self.sessionTokenKey)",message="secretName is required with source static and only allowed with it"
type S3Credentials struct {
	// Source is `env` (AWS_* variables, set them with HaltSQLServer
	// spec.env), `static` (keys from a Secret), `web_identity` (IRSA) or
	// `instance`.
	// +kubebuilder:validation:Enum=env;static;web_identity;instance
	Source string `json:"source"`
	// SecretName holds the static keys.
	// +optional
	SecretName string `json:"secretName,omitempty"`
	// AccessKeyIDKey defaults to `access_key_id`.
	// +optional
	AccessKeyIDKey string `json:"accessKeyIDKey,omitempty"`
	// SecretAccessKeyKey defaults to `secret_access_key`.
	// +optional
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`
	// SessionTokenKey is optional; without it no session token is used.
	// +optional
	SessionTokenKey string `json:"sessionTokenKey,omitempty"`
}

// HaltSQLPolicyStatus is the observed state of a HaltSQLPolicy.
type HaltSQLPolicyStatus struct {
	// ObservedGeneration is the generation the Valid condition refers to.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// PolicyName is the policy document's metadata.name (inline policies only).
	// Tokens, OIDC providers and defaultPolicy refer to this name.
	// +optional
	PolicyName string `json:"policyName,omitempty"`
	// ContentHash is the sha256 of the validated content. HaltSQLServers
	// report the hash they run, which drives the Synced condition.
	// +optional
	ContentHash string `json:"contentHash,omitempty"`
	// Conditions: Valid and Synced.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=hsqlpolicy;hsqlp,categories=haltsql
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.status.policyName`
// +kubebuilder:printcolumn:name="Valid",type=string,JSONPath=`.status.conditions[?(@.type=="Valid")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HaltSQLPolicy is a HaltSQL policy that HaltSQLServers in the same
// namespace can load.
type HaltSQLPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HaltSQLPolicySpec   `json:"spec,omitempty"`
	Status HaltSQLPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HaltSQLPolicyList contains a list of HaltSQLPolicy.
type HaltSQLPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HaltSQLPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HaltSQLPolicy{}, &HaltSQLPolicyList{})
}
