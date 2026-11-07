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

{{/* The haltsql Config document (kind: Config). Token hashes come from env. */}}
{{- define "haltsql.config" -}}
apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: "0.0.0.0:{{ .Values.server.port }}"
  auth:
    allow_unauthenticated: {{ .Values.server.allowUnauthenticated }}
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
