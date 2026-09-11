{{/* Expand the name of the chart. */}}
{{- define "ac.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "ac.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Selector labels. */}}
{{- define "ac.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ac.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Common labels. */}}
{{- define "ac.labels" -}}
helm.sh/chart: {{ include "ac.chart" . }}
{{ include "ac.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Use the Gateway API hostname when enabled, otherwise the first Ingress hostname. */}}
{{- define "ac.hostname" -}}
{{- if .Values.httpRoute.enabled -}}
{{- $hostnames := .Values.httpRoute.hostnames | default (list) -}}
{{- if eq (len $hostnames) 0 -}}
{{- fail "httpRoute.hostnames must contain at least one hostname when httpRoute.enabled is true" -}}
{{- end -}}
{{- index $hostnames 0 -}}
{{- else -}}
{{- $hosts := .Values.ingress.hosts | default (list) -}}
{{- if eq (len $hosts) 0 -}}
{{- fail "ingress.hosts must contain at least one hostname when httpRoute is disabled" -}}
{{- end -}}
{{- index (index $hosts 0) "host" -}}
{{- end -}}
{{- end }}

{{/* Create the name of the service account to use. */}}
{{- define "ac.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (printf "%s-service-account" .Release.Name) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Runtime configuration Secret name. */}}
{{- define "ac.runtimeConfigSecretName" -}}
{{- required "application.runtimeConfig.existingSecret is required" .Values.application.runtimeConfig.existingSecret -}}
{{- end -}}
