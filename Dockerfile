FROM golang:1.26-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/evydence-api ./cmd/evydence-api
RUN go build -o /out/evydence-migrate ./cmd/evydence-migrate
RUN go build -o /out/evydence-worker ./cmd/evydence-worker
RUN go build -o /out/evydence ./cmd/evydence

FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601
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
