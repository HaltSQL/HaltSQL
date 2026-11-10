{{/* Chart name. */}}
{{- define "console.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "console.fullname" -}}
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

{{- define "console.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "console.selectorLabels" -}}
app.kubernetes.io/name: {{ include "console.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "console.labels" -}}
helm.sh/chart: {{ include "console.chart" . }}
{{ include "console.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: control-plane
app.kubernetes.io/part-of: haltsql
{{- end -}}

{{- define "console.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "console.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "console.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "console.oauth2ProxyImage" -}}
{{- $i := .Values.oauth2Proxy.image -}}
{{- if $i.digest -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- else -}}
{{- printf "%s:%s" $i.repository $i.tag -}}
{{- end -}}
{{- end -}}

{{- define "console.pvcName" -}}
{{- default (printf "%s-state" (include "console.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}

{{- define "console.configMapName" -}}
{{- default (printf "%s-config" (include "console.fullname" .)) .Values.console.existingConfigMap -}}
{{- end -}}

{{/* Namespace of the verifiers the Role grants restarts in. */}}
{{- define "console.rbacNamespace" -}}
{{- default .Release.Namespace .Values.rbac.namespace -}}
{{- end -}}

{{/* Address the console listens on: loopback behind the oauth2-proxy sidecar. */}}
{{- define "console.listen" -}}
{{- if .Values.oauth2Proxy.enabled -}}
{{- printf "127.0.0.1:%d" (int .Values.console.port) -}}
{{- else -}}
{{- printf "0.0.0.0:%d" (int .Values.console.port) -}}
{{- end -}}
{{- end -}}

{{/* Whether the service account token is mounted (into the console container
only, through a projected volume; never at pod level). */}}
{{- define "console.automountToken" -}}
{{- if or .Values.rbac.create .Values.serviceAccount.automountServiceAccountToken -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
The console config document: console.config with the chart-owned keys set.
`listen` and `state_dir` are refused in console.config (the chart passes
--listen, and state_dir must be the mounted volume).
*/}}
{{- define "console.config" -}}
{{- if not (kindIs "map" (default dict .Values.console.config)) -}}
{{- fail "console.config must be a map (the console configuration, docs/console/config.md)" -}}
{{- end -}}
{{- $cfg := deepCopy (default dict .Values.console.config) -}}
{{- range list "listen" "state_dir" -}}
{{- if hasKey $cfg . -}}
{{- fail (printf "console.config.%s is set by the chart; remove it (use console.port / persistence.mountPath)" .) -}}
{{- end -}}
{{- end -}}
{{- $_ := set $cfg "listen" (include "console.listen" .) -}}
{{- $_ := set $cfg "state_dir" .Values.persistence.mountPath -}}
{{- with .Values.console.frontendDir -}}
{{- $_ := set $cfg "frontend_dir" . -}}
{{- end -}}
{{- $auth := default dict (get $cfg "auth") -}}
{{- if not (kindIs "map" $auth) -}}
{{- fail "console.config.auth must be a map" -}}
{{- end -}}
{{- if .Values.oauth2Proxy.enabled -}}
{{- /* The sidecar reaches the console over loopback, so identity headers are
       accepted only from 127.0.0.1 / ::1 (the console refuses an auth.proxy
       without trusted_proxies or a shared secret). The chart owns every key:
       oauth2-proxy overwrites exactly these headers on each request. */ -}}
{{- $_ := set $auth "proxy" (dict "user_header" "X-Forwarded-Email" "name_header" "X-Forwarded-Preferred-Username" "groups_header" "X-Forwarded-Groups" "label" "oauth2-proxy" "trusted_proxies" (list "127.0.0.1/32" "::1/128")) -}}
{{- $_ := set $cfg "auth" $auth -}}
{{- else if get $auth "proxy" -}}
{{- $p := get $auth "proxy" -}}
{{- if not (kindIs "map" $p) -}}
{{- fail "console.config.auth.proxy must be a map" -}}
{{- end -}}
{{- if not (or (get $p "trusted_proxies") (get $p "secret_header")) -}}
{{- fail "console.config.auth.proxy needs trusted_proxies and/or secret_header + secret_sha256 (the console refuses to start without them); or enable oauth2Proxy" -}}
{{- end -}}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.ingressFrom) (not (get $p "secret_header")) -}}
{{- fail "console.config.auth.proxy without the oauth2-proxy sidecar: set networkPolicy.ingressFrom to your proxy (an empty list admits every pod in the namespace), or add auth.proxy.secret_header + secret_sha256" -}}
{{- end -}}
{{- end -}}
{{- if .Values.rbac.create -}}
{{- $fleet := default dict (get $cfg "fleet") -}}
{{- $k8s := default dict (get $fleet "kubernetes") -}}
{{- $_ := set $k8s "namespace" (include "console.rbacNamespace" .) -}}
{{- $_ := set $fleet "kubernetes" $k8s -}}
{{- $_ := set $cfg "fleet" $fleet -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}

{{/*
Render a probe from values: drops the chart-only `enabled` key. With the
oauth2-proxy sidecar the console listens on loopback (unreachable for
kubelet) and the named port "http" belongs to the sidecar container (named
ports resolve per container), so httpGet probes on "http" use the sidecar's
port number; it forwards /healthz and /readyz without a session.
Usage: include "console.probe" (dict "probe" .Values.livenessProbe "root" $)
*/}}
{{- define "console.probe" -}}
{{- $p := omit (deepCopy .probe) "enabled" -}}
{{- if and .root.Values.oauth2Proxy.enabled (hasKey $p "httpGet") (eq (toString $p.httpGet.port) "http") -}}
{{- $_ := set $p.httpGet "port" (int .root.Values.oauth2Proxy.port) -}}
{{- end -}}
{{- toYaml $p -}}
{{- end -}}

{{/* Validate a single pod volume source. Usage: include "console.volumeSource" (dict "v" $vol "key" "auditVolume.volume") */}}
{{- define "console.volumeSource" -}}
{{- if not (kindIs "map" .v) -}}
{{- fail (printf "%s must be a pod volume source" .key) -}}
{{- end -}}
{{- if ne (len .v) 1 -}}
{{- fail (printf "%s must have exactly one volume source" .key) -}}
{{- end -}}
{{- if hasKey .v "name" -}}
{{- fail (printf "%s must not set name" .key) -}}
{{- end -}}
{{- toYaml .v -}}
{{- end -}}
