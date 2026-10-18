FROM golang:1.27.2-alpine3.23@sha256:9e45f0eb4a63ed37ad6e604950407558b7c738e34e015ae77a5d4ad369cde079 AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG EVYDENCE_BUILD_VERSION=unknown
ARG EVYDENCE_BUILD_COMMIT=unknown
ARG EVYDENCE_BUILD_TIME=unknown
ARG EVYDENCE_BUILD_DIRTY=false
ARG EVYDENCE_BUILD_GO_VERSION=unknown
ARG EVYDENCE_BUILD_RELEASE_MANIFEST_DIGEST=unknown
ENV EVYDENCE_BUILD_VERSION=${EVYDENCE_BUILD_VERSION} \
    EVYDENCE_BUILD_COMMIT=${EVYDENCE_BUILD_COMMIT} \
    EVYDENCE_BUILD_TIME=${EVYDENCE_BUILD_TIME} \
    EVYDENCE_BUILD_DIRTY=${EVYDENCE_BUILD_DIRTY} \
    EVYDENCE_BUILD_GO_VERSION=${EVYDENCE_BUILD_GO_VERSION} \
    EVYDENCE_BUILD_RELEASE_MANIFEST_DIGEST=${EVYDENCE_BUILD_RELEASE_MANIFEST_DIGEST}
RUN go build -trimpath -ldflags "$(sh scripts/build_ldflags.sh)" -o /out/evydence-api ./cmd/evydence-api
RUN go build -o /out/evydence-migrate ./cmd/evydence-migrate
RUN go build -o /out/evydence-worker ./cmd/evydence-worker
RUN go build -o /out/evydence ./cmd/evydence

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN addgroup -S evydence && adduser -S -G evydence evydence
USER evydence
WORKDIR /app
COPY --from=build /out/evydence-api /usr/local/bin/evydence-api
COPY --from=build /out/evydence-migrate /usr/local/bin/evydence-migrate
COPY --from=build /out/evydence-worker /usr/local/bin/evydence-worker
COPY --from=build /out/evydence /usr/local/bin/evydence
COPY --from=build /src/migrations /app/migrations
EXPOSE 8080
ENTRYPOINT ["evydence-api"]
