# Build context is the repo root (see docker-compose.yml `context: .`)
# so this Dockerfile can resolve the go.work module graph, including the
# local `shared` module via its replace directive.

FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.work go.work
COPY shared/ shared/
COPY auth-provider/server/ auth-provider/server/

WORKDIR /src/auth-provider/server
RUN go build -o /out/server .

FROM alpine:3.20
RUN adduser -D -u 10001 appuser
WORKDIR /app
COPY --from=build /out/server ./server
COPY --from=build /src/auth-provider/server/migrations ./migrations
USER appuser

EXPOSE 5001
ENTRYPOINT ["./server"]
