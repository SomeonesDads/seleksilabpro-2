FROM golang:1.25-alpine AS build
WORKDIR /src

COPY shared/ shared/
COPY auth-provider/control-panel/ auth-provider/control-panel/

WORKDIR /src/auth-provider/control-panel
RUN go build -o /out/control-panel .

FROM alpine:3.20
RUN adduser -D -u 10001 appuser
WORKDIR /app
COPY --from=build /out/control-panel ./control-panel
USER appuser

EXPOSE 5002
ENTRYPOINT ["./control-panel"]
