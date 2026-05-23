{{- define "evydence.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "evydence.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "evydence.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
