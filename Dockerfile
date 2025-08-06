# Multi-stage Dockerfile for FileServer (Frontend + Backend)

# ================================
# Frontend Build Stage
# ================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend package files
COPY frontend/package.json frontend/yarn.lock* ./

# Install frontend dependencies
RUN yarn install --frozen-lockfile

# Copy frontend source code
COPY frontend/ ./

# Build frontend application
RUN yarn build

# ================================
# Backend Build Stage
# ================================
FROM golang:1.24-alpine AS backend-builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download Go dependencies
RUN go mod download

# Copy backend source code (excluding frontend)
COPY cmd/ cmd/
COPY internal/ internal/
COPY configs/ configs/

# Build the backend binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o fileserver cmd/server/main.go

# ================================
# Production Stage
# ================================
FROM node:20-alpine AS production

# Install system dependencies
RUN apk update && apk upgrade && apk --no-cache add ca-certificates wget && rm -rf /var/cache/apk/*

# Create users
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs && \
    addgroup -g 1002 -S fileserver && \
    adduser -u 1002 -S fileserver -G fileserver

WORKDIR /app

# ================================
# Setup Backend
# ================================
# Copy backend binary
COPY --from=backend-builder /app/fileserver ./

# Create backend directories
RUN mkdir -p data downloads configs certs logs && \
    chown -R fileserver:fileserver data downloads configs certs logs

# Copy default backend configurations
COPY --chown=fileserver:fileserver configs/ configs/

# ================================
# Setup Frontend
# ================================
# Copy built frontend application
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/public ./frontend/public
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/standalone ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/static ./frontend/.next/static

# Copy frontend server files
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/server.js ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/package.json ./frontend/

# Install frontend production dependencies
WORKDIR /app/frontend
RUN yarn install --production --frozen-lockfile

WORKDIR /app

# ================================
# Setup Startup Script
# ================================
# Create startup script to run both services
RUN cat > start.sh << 'EOF' && \
    chmod +x start.sh
#!/bin/sh

# Function to handle graceful shutdown
cleanup() {
    echo "Shutting down services..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

# Set trap for graceful shutdown
trap cleanup SIGTERM SIGINT

# Start backend service
echo "Starting backend service..."
./fileserver &
BACKEND_PID=$!

# Start frontend service
echo "Starting frontend service..."
cd frontend
su-exec nextjs node server.js &
FRONTEND_PID=$!
cd ..

# Wait for both services
echo "Both services started"
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"

# Keep script running and wait for any service to exit
wait $BACKEND_PID $FRONTEND_PID
EOF

# Install su-exec for user switching
RUN apk add --no-cache su-exec

# Environment variables
ENV NODE_ENV=production
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV GO_ENV=production
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Expose ports
EXPOSE 3000 8443

# Health check for both services
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD (wget --no-check-certificate --quiet --tries=1 --spider https://localhost:8443/api/v1/health && \
         wget --quiet --tries=1 --spider http://localhost:3000) || exit 1

# Run startup script
CMD ["./start.sh"]