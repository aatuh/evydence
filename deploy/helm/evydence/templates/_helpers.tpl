{{- define "evydence.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{/* One image selection for the hook and both daemons; no independent fallback. */}}
{{- define "evydence.image" -}}
{{- $repository := required "image.repository is required" .Values.image.repository -}}
{{- if contains ":" (last (splitList "/" $repository)) -}}
{{- fail "image.repository must not include an image tag" -}}
{{- end -}}
{{- $tag := .Values.image.tag -}}
{{- $digest := .Values.image.digest -}}
{{- if contains "@" $tag -}}
{{- $parts := splitList "@" $tag -}}
{{- if ne (len $parts) 2 -}}{{- fail "image.tag must use tag@sha256:digest format" -}}{{- end -}}
{{- if and $digest (ne $digest (last $parts)) -}}
{{- fail "image.tag and image.digest select conflicting digests" -}}
{{- end -}}
{{- $digest = last $parts -}}
{{- $tag = first $parts -}}
{{- end -}}
{{- if and .Values.env.production (not $digest) -}}
{{- fail "production image.tag/image.digest must select a sha256 digest" -}}
{{- end -}}
{{- if $digest -}}
{{- if $tag -}}{{ printf "%s:%s@%s" $repository $tag $digest }}{{- else -}}{{ printf "%s@%s" $repository $digest }}{{- end -}}
{{- else -}}
{{- $tag = required "image.tag is required without image.digest" $tag -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "evydence.runtimeServiceAccountName" -}}
{{- printf "%s-%s" (include "evydence.fullname" .root | trunc 55 | trimSuffix "-") .component -}}
{{- end -}}

{{/* Non-secret process configuration; one input to both revision and data. */}}
{{- define "evydence.configData" -}}
ENV: {{ ternary "production" "development" .Values.env.production | quote }}
EVYDENCE_RUNTIME_PROFILE: "postgres"
EVYDENCE_SKIP_MIGRATIONS: "true"
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

{{/* Compare references only; chart templates never inspect credential bytes. */}}
{{- define "evydence.validateSecretSeparation" -}}
{{- if .Values.env.production -}}
{{- $api := include "evydence.runtimeSecret" (dict "process" .Values.api "fallback" .Values.existingSecret) -}}
{{- $worker := include "evydence.runtimeSecret" (dict "process" .Values.worker "fallback" .Values.existingSecret) -}}
{{- $migrate := .Values.migration.existingSecret -}}
{{- if or (eq $api $worker) (eq $api $migrate) (eq $worker $migrate) -}}
{{- fail "production requires distinct API, worker and migration Secret references" -}}
{{- end -}}
{{- if or (and .Values.api.environmentSecret (or (eq .Values.api.environmentSecret $worker) (eq .Values.api.environmentSecret $migrate))) (and .Values.worker.environmentSecret (or (eq .Values.worker.environmentSecret $api) (eq .Values.worker.environmentSecret $migrate))) (and .Values.api.environmentSecret (eq .Values.api.environmentSecret .Values.worker.environmentSecret)) -}}
{{- fail "production environmentSecret must not import another process's Secret authority" -}}
{{- end -}}
{{- end -}}
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

{{/* Jobs must leave room for the controller's generated pod-name suffix. */}}
{{- define "evydence.migrationName" -}}
{{- printf "%s-migrate" (include "evydence.fullname" . | trunc 55 | trimSuffix "-") -}}
{{- end -}}
