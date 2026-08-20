# syntax=docker/dockerfile:1
FROM golang:1.25

# Build context is the repository root (see docker-compose.yml), so the app
# sources live under applications/app-b and the shared module under shared.
WORKDIR /app
COPY applications/app-b/go.mod applications/app-b/go.sum ./
COPY shared /shared
RUN go mod download
COPY applications/app-b/. .
RUN go build -o /out/app-b .

WORKDIR /out
EXPOSE 5020
CMD ["/out/app-b"]
