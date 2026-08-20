# Build context is the repo root (see docker-compose.yml `context: .`).
# The server module resolves the local `shared` module through a relative
# `replace` directive, so copying `shared/` alongside the service is enough;
# no go.work file is required.

FROM golang:1.25-alpine AS build
WORKDIR /src

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
