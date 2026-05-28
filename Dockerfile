FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/evydence-api ./cmd/evydence-api
RUN go build -o /out/evydence-worker ./cmd/evydence-worker
RUN go build -o /out/evydence ./cmd/evydence

FROM alpine:3.22
RUN addgroup -S evydence && adduser -S -G evydence evydence
USER evydence
WORKDIR /app
COPY --from=build /out/evydence-api /usr/local/bin/evydence-api
COPY --from=build /out/evydence-worker /usr/local/bin/evydence-worker
COPY --from=build /out/evydence /usr/local/bin/evydence
COPY --from=build /src/migrations /app/migrations
EXPOSE 8080
ENTRYPOINT ["evydence-api"]
