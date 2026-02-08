# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /spleen-server ./server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /spleen-client ./client

# Server image
FROM scratch AS server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /spleen-server /app/spleen-server
WORKDIR /app
EXPOSE 54321 5432
VOLUME ["/app/data"]
ENTRYPOINT ["/app/spleen-server"]
CMD ["-d", "/app/data/config.json"]

# Client image
FROM scratch AS client
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /spleen-client /app/spleen-client
WORKDIR /app
VOLUME ["/app/data"]
ENTRYPOINT ["/app/spleen-client"]
CMD ["-d", "/app/data/config.json"]
