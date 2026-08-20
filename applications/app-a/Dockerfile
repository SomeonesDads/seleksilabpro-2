# syntax=docker/dockerfile:1
FROM golang:1.25

# Build context is the repository root (see docker-compose.yml), so the app
# sources live under applications/app-a and the shared module under shared.
WORKDIR /app
COPY applications/app-a/go.mod applications/app-a/go.sum ./
COPY shared /shared
RUN go mod download
COPY applications/app-a/. .
RUN go build -o /out/app-a .

WORKDIR /out
EXPOSE 5010
CMD ["/out/app-a"]
