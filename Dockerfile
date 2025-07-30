# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o fileserver cmd/server/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S fileserver && \
    adduser -u 1001 -S fileserver -G fileserver

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/fileserver .

# Copy necessary directories
COPY --chown=fileserver:fileserver downloads/ downloads/
COPY --chown=fileserver:fileserver configs/ configs/

# Create certs directory
RUN mkdir -p certs && chown fileserver:fileserver certs

# Switch to non-root user
USER fileserver

# Expose HTTPS port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-check-certificate --quiet --tries=1 --spider https://localhost:8443/api/v1/health || exit 1

# Run the binary
CMD ["./fileserver"]