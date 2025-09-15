#!/bin/bash

# ========================================
# Secure File Hub - Clean Docker Build Script
# ========================================
# This script builds a clean Docker image with only admin user

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

# Configuration
IMAGE_NAME="secure-file-hub"
IMAGE_TAG="clean"
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"
COMPOSE_FILE="docker-compose.clean.yml"

log_info "======================================="
log_info "Secure File Hub - Clean Docker Build"
log_info "======================================="

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    log_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if required files exist
if [ ! -f "Dockerfile" ]; then
    log_error "Dockerfile not found in current directory"
    exit 1
fi

if [ ! -f "scripts/init-clean-db.sql" ]; then
    log_error "Database initialization script not found: scripts/init-clean-db.sql"
    exit 1
fi

if [ ! -f "scripts/init-database.sh" ]; then
    log_error "Database initialization script not found: scripts/init-database.sh"
    exit 1
fi

# Clean up existing containers and images
log_info "Cleaning up existing containers and images..."

# Stop and remove existing containers
if docker ps -a --format "table {{.Names}}" | grep -q "secure-file-hub"; then
    log_info "Stopping existing containers..."
    docker stop $(docker ps -a --format "table {{.Names}}" | grep "secure-file-hub" | tr -d ' ') 2>/dev/null || true
    docker rm $(docker ps -a --format "table {{.Names}}" | grep "secure-file-hub" | tr -d ' ') 2>/dev/null || true
fi

# Remove existing images
if docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "${FULL_IMAGE_NAME}"; then
    log_info "Removing existing image: ${FULL_IMAGE_NAME}"
    docker rmi "${FULL_IMAGE_NAME}" 2>/dev/null || true
fi

# Build the Docker image
log_info "Building Docker image: ${FULL_IMAGE_NAME}"
log_info "This may take several minutes..."

if docker build -t "${FULL_IMAGE_NAME}" .; then
    log_success "Docker image built successfully: ${FULL_IMAGE_NAME}"
else
    log_error "Failed to build Docker image"
    exit 1
fi

# Show image information
log_info "Image information:"
docker images "${IMAGE_NAME}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

# Test the image
log_info "Testing the built image..."

# Create a temporary container to test
TEST_CONTAINER="secure-file-hub-test-$(date +%s)"
if docker run --name "${TEST_CONTAINER}" --rm -d "${FULL_IMAGE_NAME}"; then
    log_success "Test container started successfully"

    # Wait for services to start
    log_info "Waiting for services to start..."
    sleep 30

    # Check if services are running
    if docker exec "${TEST_CONTAINER}" curl -f -k https://localhost:8443/api/v1/health >/dev/null 2>&1; then
        log_success "Backend service is running"
    else
        log_warning "Backend service health check failed"
    fi

    if docker exec "${TEST_CONTAINER}" curl -f http://localhost:30000 >/dev/null 2>&1; then
        log_success "Frontend service is running"
    else
        log_warning "Frontend service health check failed"
    fi

    # Stop test container
    docker stop "${TEST_CONTAINER}" >/dev/null 2>&1
    log_success "Test container stopped"
else
    log_error "Failed to start test container"
    exit 1
fi

# Save image to file
SAVE_FILE="secure-file-hub-clean-$(date +%Y%m%d-%H%M%S).tar"
log_info "Saving image to file: ${SAVE_FILE}"
if docker save -o "${SAVE_FILE}" "${FULL_IMAGE_NAME}"; then
    log_success "Image saved to: ${SAVE_FILE}"
    log_info "File size: $(du -h "${SAVE_FILE}" | cut -f1)"
else
    log_error "Failed to save image to file"
    exit 1
fi

log_success "======================================="
log_success "Build completed successfully!"
log_success "======================================="
log_info "Image name: ${FULL_IMAGE_NAME}"
log_info "Image file: ${SAVE_FILE}"
log_info "Admin username: admin"
log_info "Admin password: admin123"
log_info ""
log_info "To run the container:"
log_info "  docker run -d -p 30000:30000 -p 8443:8443 ${FULL_IMAGE_NAME}"
log_info ""
log_info "Or use docker-compose:"
log_info "  docker-compose -f ${COMPOSE_FILE} up -d"
log_success "======================================="
