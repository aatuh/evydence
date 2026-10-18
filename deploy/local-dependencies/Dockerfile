# Local/disposable S3 test fixtures, not supported production object stores.
# Community MinIO is archived and has unresolved upstream security advisories.
# Source revisions are verified by Go's checksum database; base images are
# immutable Docker Official Images indices Go index verified on 2026-10-18; runtime index on 2026-10-11.
FROM golang:1.27.2-alpine3.23@sha256:9e45f0eb4a63ed37ad6e604950407558b7c738e34e015ae77a5d4ad369cde079 AS toolchain
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOSUMDB=sum.golang.org GOFLAGS=-p=1 GOMAXPROCS=2
WORKDIR /build

# RELEASE.2025-10-15T17-29-55Z, commit 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a.
FROM toolchain AS minio-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/out go install -p=1 -trimpath github.com/minio/minio@v0.0.0-20251015172955-9e49d5e7a648 && \
    cp /go/pkg/mod/github.com/minio/minio@v0.0.0-20251015172955-9e49d5e7a648/LICENSE /out/LICENSE

# RELEASE.2025-08-13T08-35-41Z, commit 7394ce0dd2a80935aded936b09fa12cbb3cb8096.
FROM toolchain AS mc-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/out go install -p=1 -trimpath github.com/minio/mc@v0.0.0-20250813083541-7394ce0dd2a8 && \
    cp /go/pkg/mod/github.com/minio/mc@v0.0.0-20250813083541-7394ce0dd2a8/LICENSE /out/LICENSE

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 AS minio
COPY --from=toolchain /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=minio-build /out/minio /usr/local/bin/minio
COPY --from=minio-build /out/LICENSE /usr/share/licenses/minio/LICENSE
RUN mkdir /data
EXPOSE 9000 9001
ENTRYPOINT ["minio"]
CMD ["server", "/data"]

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 AS mc
COPY --from=toolchain /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=mc-build /out/mc /usr/local/bin/mc
COPY --from=mc-build /out/LICENSE /usr/share/licenses/mc/LICENSE
ENTRYPOINT ["mc"]
