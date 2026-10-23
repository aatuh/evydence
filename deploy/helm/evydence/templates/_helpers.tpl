{{- define "evydence.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{/* Non-secret process configuration; one input to both revision and data. */}}
{{- define "evydence.configData" -}}
ENV: {{ ternary "production" "development" .Values.env.production | quote }}
EVYDENCE_RUNTIME_PROFILE: "postgres"
EVYDENCE_ADDR: {{ .Values.api.addr | quote }}
EVYDENCE_API_WRITER_MODE: {{ .Values.api.writerMode | quote }}
EVYDENCE_API_WRITER_REPLICAS: {{ .Values.api.replicas | quote }}
EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS: {{ .Values.api.readHeaderTimeoutSeconds | quote }}
EVYDENCE_HTTP_READ_TIMEOUT_SECONDS: {{ .Values.api.readTimeoutSeconds | quote }}
EVYDENCE_HTTP_WRITE_TIMEOUT_SECONDS: {{ .Values.api.writeTimeoutSeconds | quote }}
EVYDENCE_HTTP_IDLE_TIMEOUT_SECONDS: {{ .Values.api.idleTimeoutSeconds | quote }}
EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS: {{ .Values.api.shutdownTimeoutSeconds | quote }}
EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS: {{ .Values.cleanupTimeoutSeconds | quote }}
EVYDENCE_HTTP_MAX_HEADER_BYTES: {{ .Values.api.maxHeaderBytes | quote }}
EVYDENCE_HTTP_MAX_URL_BYTES: {{ .Values.api.maxURLBytes | quote }}
EVYDENCE_HTTP_MAX_IN_FLIGHT_REQUESTS: {{ .Values.api.maxInFlightRequests | quote }}
EVYDENCE_HTTP_MAX_CONCURRENT_UPLOADS: {{ .Values.api.maxConcurrentUploads | quote }}
EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE: {{ .Values.api.rateLimitRequestsPerMinute | quote }}
EVYDENCE_AUTH_FAILURES_PER_MINUTE: {{ .Values.api.authenticationFailuresPerMinute | quote }}
EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE: {{ .Values.api.expensiveTenantRequestsPerMinute | quote }}
EVYDENCE_RATE_LIMIT_BUCKET_CAPACITY: {{ .Values.api.rateLimitBucketCapacity | quote }}
EVYDENCE_TRUSTED_PROXY_CIDRS: {{ .Values.api.trustedProxyCIDRs | quote }}
EVYDENCE_OBJECT_STORE: {{ .Values.env.objectStore | quote }}
EVYDENCE_S3_ENDPOINT: {{ .Values.env.s3Endpoint | quote }}
EVYDENCE_S3_BUCKET: {{ .Values.env.s3Bucket | quote }}
EVYDENCE_S3_REGION: {{ .Values.env.s3Region | quote }}
EVYDENCE_S3_USE_SSL: {{ .Values.env.s3UseSSL | quote }}
EVYDENCE_SIGNING_KEY_MODE: {{ .Values.env.signingKeyMode | quote }}
EVYDENCE_WORKER_POLL_INTERVAL: {{ .Values.worker.pollInterval | quote }}
EVYDENCE_WORKER_HEALTH_ADDR: {{ printf "127.0.0.1:%v" .Values.worker.healthPort | quote }}
EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS: {{ .Values.worker.shutdownTimeoutSeconds | quote }}
{{- end -}}

{{- define "evydence.runtimeSecret" -}}
{{- default .fallback .process.existingSecret -}}
{{- end -}}

{{/* Schema-supported file options only; no secret values enter templates. */}}
{{- define "evydence.secretFiles" -}}
{{- $files := dict "EVYDENCE_DATABASE_URL_FILE" .root.Values.env.databaseURLSecretKey -}}
{{- if eq .name "api" -}}
{{- $_ := set $files "EVYDENCE_API_KEY_PEPPER_FILE" .root.Values.env.apiKeyPepperSecretKey -}}
{{- end -}}
{{- range $option, $key := .process.secretFiles -}}
{{- $_ := set $files $option $key -}}
{{- end -}}
{{- toYaml $files -}}
{{- end -}}

{{- define "evydence.validateSecretFiles" -}}
{{- $pod := default dict .root.Values.podSecurityContext -}}
{{- if not (gt (int64 (default 0 $pod.fsGroup)) 0) -}}
{{- fail "file secretSource requires a positive podSecurityContext.fsGroup" -}}
{{- end -}}
{{- $selected := include "evydence.runtimeSecret" (dict "process" .process "fallback" .root.Values.existingSecret) -}}
{{- if eq .process.environmentSecret $selected -}}
{{- fail "file secretSource requires environmentSecret to differ from the projected Secret" -}}
{{- end -}}
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
