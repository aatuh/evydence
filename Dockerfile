FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
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

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
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
