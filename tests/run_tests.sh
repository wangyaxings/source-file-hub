#!/bin/bash

# Secure File Hub Test Runner
# This script runs the complete test suite for the Secure File Hub project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
VERBOSE=false
COVERAGE=false
RACE=false
TIMEOUT="10m"
PACKAGE="./tests/..."
OUTPUT_DIR="test-results"
COVERAGE_FILE="coverage.out"
CLEAN=false
HELP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -r|--race)
            RACE=true
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -p|--package)
            PACKAGE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        -h|--help)
            HELP=true
            shift
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Show help
if [ "$HELP" = true ]; then
    echo "Secure File Hub Test Runner"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -v, --verbose     Enable verbose output"
    echo "  -c, --coverage    Generate coverage report"
    echo "  -r, --race        Enable race detection"
    echo "  -t, --timeout     Set test timeout (default: 10m)"
    echo "  -p, --package     Package to test (default: ./tests/...)"
    echo "  -o, --output      Output directory (default: test-results)"
    echo "  --clean           Clean output directory before running"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Run all tests"
    echo "  $0 -c -r -v                  # Run with coverage, race detection, and verbose output"
    echo "  $0 -p ./tests/auth/...       # Run only auth tests"
    echo "  $0 --clean -c                # Clean and run with coverage"
    exit 0
fi

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command_exists go; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    if ! command_exists sqlite3; then
        print_warning "SQLite3 is not installed. Some tests may fail."
    fi
    
    print_success "Prerequisites check completed"
}

# Clean output directory
clean_output() {
    if [ "$CLEAN" = true ]; then
        print_status "Cleaning output directory: $OUTPUT_DIR"
        rm -rf "$OUTPUT_DIR"
        print_success "Output directory cleaned"
    fi
}

# Create output directory
create_output_dir() {
    print_status "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    print_success "Output directory created"
}

# Run tests
run_tests() {
    print_status "Running tests..."
    print_status "Package: $PACKAGE"
    print_status "Timeout: $TIMEOUT"
    print_status "Verbose: $VERBOSE"
    print_status "Coverage: $COVERAGE"
    print_status "Race detection: $RACE"
    
    # Build test command
    local args=("test")
    
    if [ "$VERBOSE" = true ]; then
        args+=("-v")
    fi
    
    if [ "$COVERAGE" = true ]; then
        args+=("-cover")
        args+=("-coverprofile=$COVERAGE_FILE")
    fi
    
    if [ "$RACE" = true ]; then
        args+=("-race")
    fi
    
    args+=("-timeout=$TIMEOUT")
    args+=("$PACKAGE")
    
    # Run tests
    if go "${args[@]}"; then
        print_success "Tests completed successfully"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Generate coverage report
generate_coverage_report() {
    if [ "$COVERAGE" = true ]; then
        print_status "Generating coverage report..."
        
        # Generate HTML coverage report
        if go tool cover -html="$COVERAGE_FILE" -o "$OUTPUT_DIR/coverage.html"; then
            print_success "HTML coverage report generated: $OUTPUT_DIR/coverage.html"
        else
            print_error "Failed to generate HTML coverage report"
            exit 1
        fi
        
        # Generate coverage summary
        if go tool cover -func="$COVERAGE_FILE" > "$OUTPUT_DIR/coverage.txt"; then
            print_success "Coverage summary generated: $OUTPUT_DIR/coverage.txt"
        else
            print_error "Failed to generate coverage summary"
            exit 1
        fi
        
        # Show coverage percentage
        local coverage_percent=$(go tool cover -func="$COVERAGE_FILE" | grep total | awk '{print $3}')
        print_status "Total coverage: $coverage_percent"
    fi
}

# Generate test summary
generate_test_summary() {
    print_status "Generating test summary..."
    
    local summary_file="$OUTPUT_DIR/test-summary.md"
    local current_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$summary_file" << EOF
# Test Summary

**Date:** $current_time
**Package:** $PACKAGE
**Verbose:** $VERBOSE
**Coverage:** $COVERAGE
**Race Detection:** $RACE
**Timeout:** $TIMEOUT

## Test Results

All tests passed successfully! 🎉

## Coverage

EOF
    
    if [ "$COVERAGE" = true ]; then
        cat >> "$summary_file" << EOF
Coverage report generated: $OUTPUT_DIR/coverage.html
Coverage summary: $OUTPUT_DIR/coverage.txt

EOF
    fi
    
    cat >> "$summary_file" << EOF
## Next Steps

1. Review the coverage report to identify areas for improvement
2. Add more tests for uncovered code paths
3. Consider adding integration tests for complex workflows
4. Monitor test performance and optimize slow tests

## Test Structure

- **Unit Tests:** tests/auth/, tests/database/, tests/handler/, tests/middleware/, tests/server/, tests/apikey/, tests/authz/, tests/logger/
- **Integration Tests:** tests/integration/
- **Test Helpers:** tests/helpers/

## Best Practices

- Keep tests focused and atomic
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Use table-driven tests for multiple scenarios
- Clean up test data after each test
EOF
    
    print_success "Test summary generated: $summary_file"
}

# Main execution
main() {
    echo "🧪 Secure File Hub Test Runner"
    echo "=============================="
    
    check_prerequisites
    clean_output
    create_output_dir
    run_tests
    generate_coverage_report
    generate_test_summary
    
    print_success "All tests completed successfully! 🎉"
    print_status "Results saved to: $OUTPUT_DIR"
}

# Run main function
main "$@"
