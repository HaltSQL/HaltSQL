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

{{/*
The haltsql Config document (kind: Config). Token hashes come from env.
server.extraConfig, when set, is deep-merged over the rendered document.
*/}}
{{- define "haltsql.config" -}}
{{- if .Values.server.extraConfig -}}
{{- $base := include "haltsql.baseConfig" . | fromYaml -}}
{{- if hasKey $base "Error" -}}
{{- fail (printf "internal error rendering the haltsql Config: %s" (get $base "Error")) -}}
{{- end -}}
{{- mustMergeOverwrite $base (deepCopy .Values.server.extraConfig) | toYaml -}}
{{- else -}}
{{- include "haltsql.baseConfig" . -}}
{{- end -}}
{{- end -}}

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

{{/* Whether the NetworkPolicy opens TCP 443 egress. */}}
{{- define "haltsql.egressHTTPS" -}}
{{- $v := .Values.networkPolicy.egress.allowHTTPS -}}
{{- if eq (toString $v) "auto" -}}
{{- if .Values.oidc }}true{{ end -}}
{{- else if $v -}}
true
{{- end -}}
{{- end -}}
