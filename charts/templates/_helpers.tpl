{{/*
Expand the name of the chart.
*/}}
{{- define "picante.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "salsa-storage.name" -}}
{{- default "salsa-storage" }}
{{- end }}

{{/*
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "picante.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "picante.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "picante.labels" -}}
helm.sh/chart: {{ include "picante.chart" . }}
{{ include "picante.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "salsa-storage.selectorLabels" -}}
app.kubernetes.io/name: {{ include "salsa-storage.name" . }}
app.kubernetes.io/instance: {{ include "salsa-storage.name" . }}-backend
{{- end }}

{{/*
Selector labels
*/}}
{{- define "picante.selectorLabels" -}}
app.kubernetes.io/name: {{ include "picante.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
