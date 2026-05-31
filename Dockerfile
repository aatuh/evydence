FROM golang:1.25-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/evydence-api ./cmd/evydence-api
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
