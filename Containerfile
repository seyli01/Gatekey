# ==============================================================================
# Multi-stage Containerfile for Gatekey (Podman Native)
# Produces an ultra-lightweight, zero-cgo, unprivileged static scratch container.
# Compatible with Podman rootless & Quadlet.
# ==============================================================================

# --- Stage 1: Build binary statically ---
FROM docker.io/library/golang:1.25-alpine AS builder

WORKDIR /src

# Install CA certificates and build dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create an unprivileged user and group for scratch
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid 10001 \
    gatekey

# Pre-fetch modules
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source files
COPY cmd/ cmd/
COPY internal/ internal/

# Build static binary with symbol stripping (-s -w)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/gatekey \
    ./cmd/gatekey

# --- Stage 2: Minimalist Scratch Runtime ---
FROM scratch

# Copy TLS root certificates for upstream HTTPS calls
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy unprivileged user
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy compiled static binary
COPY --from=builder /bin/gatekey /gatekey

# Run as unprivileged user
USER 10001:10001

# Default port
EXPOSE 8080

# Run Gatekey pointing to configuration
ENTRYPOINT ["/gatekey"]
CMD ["-config", "/etc/gatekey/config.yaml"]
