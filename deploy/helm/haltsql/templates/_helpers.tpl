{{/* Chart name. */}}
{{- define "haltsql.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "haltsql.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "haltsql.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "haltsql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "haltsql.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "haltsql.labels" -}}
helm.sh/chart: {{ include "haltsql.chart" . }}
{{ include "haltsql.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: policy-firewall
{{- end -}}

{{- define "haltsql.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "haltsql.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "haltsql.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "haltsql.tokenSecretName" -}}
{{- default (printf "%s-tokens" (include "haltsql.fullname" .)) .Values.existingTokenSecret -}}
{{- end -}}

{{- define "haltsql.policyConfigMapName" -}}
{{- default (printf "%s-policies" (include "haltsql.fullname" .)) .Values.existingPolicyConfigMap -}}
{{- end -}}

{{/* Directory the bundle-source caches go to (on the cache volume). */}}
{{- define "haltsql.bundleCacheDir" -}}
{{- printf "%s/bundles" (trimSuffix "/" (required "cache.mountPath is required" .Values.cache.mountPath)) -}}
{{- end -}}

{{/*
extraPolicies, validated. Each entry must be a map (a Config policies[]
entry). A bundle_source entry without cache_dir gets the chart's cache
directory, so a restart can start from the last verified bundle.
*/}}
{{- define "haltsql.extraPolicies" -}}
{{- $out := list -}}
{{- range $i, $p := .Values.extraPolicies -}}
{{- if not (kindIs "map" $p) -}}
{{- fail (printf "extraPolicies[%d] must be a map (a Config policies[] entry), got %s" $i (kindOf $p)) -}}
{{- end -}}
{{- $e := deepCopy $p -}}
{{- if and (hasKey $e "bundle_source") (not (hasKey $e "cache_dir")) -}}
{{- $_ := set $e "cache_dir" (include "haltsql.bundleCacheDir" $) -}}
{{- end -}}
{{- $out = append $out $e -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/*
The haltsql Config document (kind: Config): the chart-rendered base, with
extraPolicies appended to policies, then server.extraConfig and then
extraConfig deep-merged on top (maps merge recursively, the later one wins;
lists and scalars are replaced). `policies` is refused in both: a replaced
list would silently drop the chart's policies, so use extraPolicies.
*/}}
{{- define "haltsql.config" -}}
{{- if not (kindIs "map" (default dict .Values.server.extraConfig)) -}}
{{- fail "server.extraConfig must be a map" -}}
{{- end -}}
{{- if not (kindIs "map" (default dict .Values.extraConfig)) -}}
{{- fail "extraConfig must be a map" -}}
{{- end -}}
{{- if not (kindIs "slice" (default list .Values.extraPolicies)) -}}
{{- fail "extraPolicies must be a list" -}}
{{- end -}}
{{- $serverExtra := deepCopy (default dict .Values.server.extraConfig) -}}
{{- if hasKey $serverExtra "policies" -}}
{{- fail "server.extraConfig.policies is not allowed: add policy entries with extraPolicies (they are appended to the rendered policies)" -}}
{{- end -}}
{{- $extra := deepCopy (default dict .Values.extraConfig) -}}
{{- if hasKey $extra "policies" -}}
{{- fail "extraConfig.policies is not allowed: add policy entries with extraPolicies (they are appended to the rendered policies)" -}}
{{- end -}}
{{- $base := include "haltsql.baseConfig" . | fromYaml -}}
{{- if hasKey $base "Error" -}}
{{- fail (printf "internal error rendering the base config: %s" (get $base "Error")) -}}
{{- end -}}
{{- $policies := list -}}
{{- range (default list (get $base "policies")) -}}
{{- $policies = append $policies . -}}
{{- end -}}
{{- range (include "haltsql.extraPolicies" . | fromJsonArray) -}}
{{- $policies = append $policies . -}}
{{- end -}}
{{- $_ := set $base "policies" $policies -}}
{{- $merged := mergeOverwrite $base $serverExtra $extra -}}
{{- toYaml $merged -}}
{{- end -}}

{{/* The chart-rendered part of the Config document. Token hashes come from env. */}}
{{- define "haltsql.baseConfig" -}}
apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: "0.0.0.0:{{ .Values.server.port }}"
  {{- if .Values.tls.enabled }}
  tls:
    cert: /etc/haltsql/tls/tls.crt
    key: /etc/haltsql/tls/tls.key
    {{- if ne .Values.tls.clientAuth "none" }}
    client_ca: /etc/haltsql/tls/ca.crt
    {{- end }}
    client_auth: {{ .Values.tls.clientAuth }}
    min_version: {{ .Values.tls.minVersion | quote }}
  {{- end }}
  auth:
    allow_unauthenticated: {{ .Values.server.allowUnauthenticated }}
    {{- with .Values.oidc }}
    oidc: {{ toJson . }}
    {{- end }}
    {{- with .Values.mtlsIdentities }}
    mtls:
      identities: {{ toJson . }}
    {{- end }}
    tokens:
    {{- range $i, $t := .Values.tokens }}
      - name: {{ $t.name | quote }}
        token_sha256: "${env:HALTSQL_TOKEN_{{ $i }}_SHA256}"
        policy: {{ $t.policy | quote }}
    {{- else }} []
    {{- end }}
policies:
{{- range $file, $_ := .Values.policies }}
  - path: /etc/haltsql/policies/{{ $file }}
{{- else }}
{{- if not .Values.existingPolicyConfigMap }} []{{ end }}
{{- end }}
{{- with .Values.existingPolicyConfigMap }}
{{- range $.Values.existingPolicyFiles }}
  - path: /etc/haltsql/policies/{{ . }}
{{- end }}
{{- end }}
limits:
  max_request_bytes: {{ .Values.server.maxRequestBytes | int }}
{{- with .Values.server.defaultPolicy }}
default_policy: {{ . | quote }}
{{- end }}
reload:
  watch: {{ .Values.server.reloadWatch }}
audit:
  sinks: {{ toJson .Values.server.audit.sinks }}
  log_raw_sql: {{ .Values.server.audit.logRawSql }}
telemetry:
  metrics:
    prometheus: {{ .Values.server.metrics }}
logging:
  level: {{ .Values.server.logLevel | quote }}
  format: {{ .Values.server.logFormat | quote }}
{{- end -}}


{{/* Number of replicas the workload runs with (HPA minimum when autoscaling). */}}
{{- define "haltsql.minReplicas" -}}
{{- if .Values.autoscaling.enabled -}}
{{- .Values.autoscaling.minReplicas | int -}}
{{- else -}}
{{- .Values.replicaCount | int -}}
{{- end -}}
{{- end -}}

{{/*
Render a probe from values: drops the chart-only `enabled` key and, with TLS
enabled, moves httpGet probes to the plain-HTTP health port.
Usage: include "haltsql.probe" (dict "probe" .Values.livenessProbe "root" $)
*/}}
{{- define "haltsql.probe" -}}
{{- $p := omit (deepCopy .probe) "enabled" -}}
{{- if and .root.Values.tls.enabled (hasKey $p "httpGet") -}}
{{- $_ := set $p.httpGet "port" "health" -}}
{{- end -}}
{{- toYaml $p -}}
{{- end -}}

{{/*
Whether the NetworkPolicy opens TCP 443 egress (map form of
networkPolicy.egress only; the list form is rendered verbatim).
*/}}
{{- define "haltsql.egressHTTPS" -}}
{{- $eg := .Values.networkPolicy.egress -}}
{{- if kindIs "map" $eg -}}
{{- $v := $eg.allowHTTPS -}}
{{- if eq (toString $v) "auto" -}}
{{- if .Values.oidc }}true{{ end -}}
{{- else if $v -}}
true
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Whether the NetworkPolicy allows any egress besides DNS: HTTPS or extraRules
in the map form of networkPolicy.egress, or a non-empty list form.
*/}}
{{- define "haltsql.egressConfigured" -}}
{{- $eg := .Values.networkPolicy.egress -}}
{{- if kindIs "map" $eg -}}
{{- if or (include "haltsql.egressHTTPS" . | eq "true") $eg.extraRules }}true{{ end -}}
{{- else if $eg -}}
true
{{- end -}}
{{- end -}}
