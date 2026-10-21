FROM golang:1.24-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/hk-migration-sidecar .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata wget \
  && adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/hk-migration-sidecar /app/hk-migration-sidecar
RUN mkdir -p /data && chown -R app:app /data /app
USER app
ENV HKM_LISTEN_ADDR=:8290 \
    HKM_DATA_DIR=/data
EXPOSE 8290
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8290/health || exit 1
ENTRYPOINT ["/app/hk-migration-sidecar"]
