#!/bin/sh

# ========================================
# File Hub - Database Initialization Script
# ========================================
# This script initializes a clean database with only the admin user

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
DB_PATH="${DB_PATH:-/app/data/fileserver.db}"
INIT_SCRIPT="${INIT_SCRIPT:-/app/scripts/init-clean-db.sql}"
BACKUP_DIR="${BACKUP_DIR:-/app/data/backups}"

log_info "======================================="
log_info "File Hub Database Initialization"
log_info "======================================="

# Check if database file exists
if [ -f "$DB_PATH" ]; then
    log_warning "Database file already exists: $DB_PATH"

    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR"

    # Create backup with timestamp
    BACKUP_FILE="$BACKUP_DIR/fileserver_$(date +%Y%m%d_%H%M%S).db"
    log_info "Creating backup: $BACKUP_FILE"
    cp "$DB_PATH" "$BACKUP_FILE"
    log_success "Backup created successfully"

    # Remove existing database
    log_info "Removing existing database..."
    rm -f "$DB_PATH"
    log_success "Existing database removed"
else
    log_info "No existing database found, creating new one"
fi

# Ensure database directory exists
DB_DIR=$(dirname "$DB_PATH")
if [ ! -d "$DB_DIR" ]; then
    log_info "Creating database directory: $DB_DIR"
    mkdir -p "$DB_DIR"
fi

# Check if initialization script exists
if [ ! -f "$INIT_SCRIPT" ]; then
    log_error "Initialization script not found: $INIT_SCRIPT"
    exit 1
fi

log_info "Initializing database with clean schema..."

# Initialize database using SQLite
if sqlite3 "$DB_PATH" < "$INIT_SCRIPT"; then
    log_success "Database initialized successfully"
else
    log_error "Failed to initialize database"
    exit 1
fi

# Verify database initialization
log_info "Verifying database initialization..."

# Check if admin user exists
ADMIN_EXISTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE username = 'admin';")
if [ "$ADMIN_EXISTS" -eq 1 ]; then
    log_success "Admin user created successfully"
else
    log_error "Admin user not found in database"
    exit 1
fi

# Check if policies exist
POLICY_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM casbin_policies;")
if [ "$POLICY_COUNT" -gt 0 ]; then
    log_success "Casbin policies initialized ($POLICY_COUNT policies)"
else
    log_error "No Casbin policies found"
    exit 1
fi

# Check clean state
FILES_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM files;")
PACKAGES_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM packages;")
API_KEYS_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM api_keys;")

if [ "$FILES_COUNT" -eq 0 ] && [ "$PACKAGES_COUNT" -eq 0 ] && [ "$API_KEYS_COUNT" -eq 0 ]; then
    log_success "Database is clean (no files, packages, or API keys)"
else
    log_warning "Database not completely clean - Files: $FILES_COUNT, Packages: $PACKAGES_COUNT, API Keys: $API_KEYS_COUNT"
fi

# Set proper permissions
log_info "Setting database file permissions..."
chmod 644 "$DB_PATH"
chown appuser:appgroup "$DB_PATH" 2>/dev/null || true

log_success "======================================="
log_success "Database initialization completed!"
log_success "======================================="
log_info "Database path: $DB_PATH"
log_info "Admin username: admin"
log_info "Admin password: admin123"
log_info "Database is clean and ready for use"
log_success "======================================="
