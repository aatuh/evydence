{{- define "evydence.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "evydence.terminationGrace" -}}
{{- $minimum := add (int64 .process.shutdownTimeoutSeconds) (int64 .cleanup) 5 -}}
{{- $grace := int64 .process.terminationGracePeriodSeconds -}}
{{- if lt $grace $minimum -}}
{{- fail (printf "%s.terminationGracePeriodSeconds must be at least %d (drain + cleanup + 5)" .name $minimum) -}}
{{- end -}}
{{- $grace -}}
{{- end -}}

{{- define "evydence.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "evydence.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
