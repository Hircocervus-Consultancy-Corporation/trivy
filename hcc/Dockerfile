# TrivyScanner CV Dockerfile
# 5FS Fork of github.com/aquasecurity/trivy (Apache 2.0)
# HCC Fork: github.com/Hircocervus-Consultancy-Corporation/trivy
#
# Multi-stage build:
#   Stage 1: Build the Go MCP# server wrapper
#   Stage 2: Final image — Trivy binary + wrapper + pre-warmed vuln DB

# ── Stage 1: build Go wrapper ─────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

WORKDIR /build
COPY server/go.mod ./
RUN go mod download

COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o trivy-scanner-server .

# ── Stage 2: final image ──────────────────────────────────────────────────────
FROM aquasecurity/trivy:0.69.3

# Install curl for healthchecks
RUN apk add --no-cache curl

# Copy Go wrapper
COPY --from=builder /build/trivy-scanner-server /usr/local/bin/trivy-scanner-server

# Pre-warm vulnerability DB at build time — eliminates per-scan download delay
ENV TRIVY_CACHE_DIR=/var/trivy-db
ENV TRIVY_NO_PROGRESS=true
RUN trivy image --download-db-only --cache-dir /var/trivy-db

# Volume keeps DB cache across container restarts
VOLUME ["/var/trivy-db"]

# CV mesh port
EXPOSE 8500

# 5FS Attribution — preserve upstream NOTICE as required by Apache 2.0
# Original work: Copyright 2019 Teppei Fukuda (@knqyf263), AquaSecurity
# This fork: Hircocervus Consultancy Corporation (HCC)
LABEL org.opencontainers.image.title="TrivyScanner CV" \
      org.opencontainers.image.description="5FS fork of aquasecurity/trivy as a mesh-resident security attestation CV" \
      org.opencontainers.image.source="https://github.com/Hircocervus-Consultancy-Corporation/trivy" \
      org.opencontainers.image.upstream="https://github.com/aquasecurity/trivy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      hcc.cv.layer="9" \
      hcc.cv.role="ObservabilityGovernance" \
      hcc.5fs.upstream_author="Teppei Fukuda (@knqyf263), AquaSecurity"

ENTRYPOINT ["trivy-scanner-server"]
