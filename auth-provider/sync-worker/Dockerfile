FROM golang:1.22-alpine AS build
WORKDIR /src

COPY shared/ shared/
COPY auth-provider/sync-worker/ auth-provider/sync-worker/

WORKDIR /src/auth-provider/sync-worker
RUN go build -o /out/sync-worker .

FROM alpine:3.20
RUN adduser -D -u 10001 appuser
WORKDIR /app
COPY --from=build /out/sync-worker ./sync-worker
USER appuser

ENTRYPOINT ["./sync-worker"]
