# Secure File Hub Test Runner (PowerShell)
# This script runs the complete test suite for the Secure File Hub project

param(
    [switch]$Verbose,
    [switch]$Coverage,
    [switch]$Race,
    [string]$Timeout = "10m",
    [string]$Package = "./tests/...",
    [string]$OutputDir = "test-results",
    [string]$CoverageFile = "coverage.out",
    [switch]$Clean,
    [switch]$Help
)

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Blue"
$White = "White"

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

# Show help
if ($Help) {
    Write-Host "Secure File Hub Test Runner" -ForegroundColor $White
    Write-Host ""
    Write-Host "Usage: .\run_tests.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Verbose        Enable verbose output"
    Write-Host "  -Coverage       Generate coverage report"
    Write-Host "  -Race          Enable race detection"
    Write-Host "  -Timeout       Set test timeout (default: 10m)"
    Write-Host "  -Package       Package to test (default: ./tests/...)"
    Write-Host "  -OutputDir     Output directory (default: test-results)"
    Write-Host "  -Clean         Clean output directory before running"
    Write-Host "  -Help          Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run_tests.ps1                           # Run all tests"
    Write-Host "  .\run_tests.ps1 -Coverage -Race -Verbose  # Run with coverage, race detection, and verbose output"
    Write-Host "  .\run_tests.ps1 -Package './tests/auth/...' # Run only auth tests"
    Write-Host "  .\run_tests.ps1 -Clean -Coverage          # Clean and run with coverage"
    exit 0
}

# Function to check if command exists
function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Check prerequisites
function Test-Prerequisites {
    Write-Status "Checking prerequisites..."
    
    if (-not (Test-Command "go")) {
        Write-Error "Go is not installed or not in PATH"
        exit 1
    }
    
    if (-not (Test-Command "sqlite3")) {
        Write-Warning "SQLite3 is not installed. Some tests may fail."
    }
    
    Write-Success "Prerequisites check completed"
}

# Clean output directory
function Clear-Output {
    if ($Clean) {
        Write-Status "Cleaning output directory: $OutputDir"
        if (Test-Path $OutputDir) {
            Remove-Item -Path $OutputDir -Recurse -Force
        }
        Write-Success "Output directory cleaned"
    }
}

# Create output directory
function New-OutputDirectory {
    Write-Status "Creating output directory: $OutputDir"
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    Write-Success "Output directory created"
}

# Run tests
function Invoke-Tests {
    Write-Status "Running tests..."
    Write-Status "Package: $Package"
    Write-Status "Timeout: $Timeout"
    Write-Status "Verbose: $Verbose"
    Write-Status "Coverage: $Coverage"
    Write-Status "Race detection: $Race"
    
    # Build test command
    $args = @("test")
    
    if ($Verbose) {
        $args += "-v"
    }
    
    if ($Coverage) {
        $args += "-cover"
        $args += "-coverprofile=$CoverageFile"
    }
    
    if ($Race) {
        $args += "-race"
    }
    
    $args += "-timeout=$Timeout"
    $args += $Package
    
    # Run tests
    try {
        & go $args
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Tests completed successfully"
        } else {
            Write-Error "Tests failed"
            exit 1
        }
    }
    catch {
        Write-Error "Failed to run tests: $_"
        exit 1
    }
}

# Generate coverage report
function New-CoverageReport {
    if ($Coverage) {
        Write-Status "Generating coverage report..."
        
        # Generate HTML coverage report
        try {
            & go tool cover -html=$CoverageFile -o "$OutputDir/coverage.html"
            Write-Success "HTML coverage report generated: $OutputDir/coverage.html"
        }
        catch {
            Write-Error "Failed to generate HTML coverage report: $_"
            exit 1
        }
        
        # Generate coverage summary
        try {
            & go tool cover -func=$CoverageFile | Out-File -FilePath "$OutputDir/coverage.txt" -Encoding UTF8
            Write-Success "Coverage summary generated: $OutputDir/coverage.txt"
        }
        catch {
            Write-Error "Failed to generate coverage summary: $_"
            exit 1
        }
        
        # Show coverage percentage
        try {
            $coverageOutput = & go tool cover -func=$CoverageFile
            $coveragePercent = ($coverageOutput | Select-String "total" | ForEach-Object { $_.Line.Split()[2] })
            Write-Status "Total coverage: $coveragePercent"
        }
        catch {
            Write-Warning "Could not determine coverage percentage"
        }
    }
}

# Generate test summary
function New-TestSummary {
    Write-Status "Generating test summary..."
    
    $summaryFile = "$OutputDir/test-summary.md"
    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $summary = @"
# Test Summary

**Date:** $currentTime
**Package:** $Package
**Verbose:** $Verbose
**Coverage:** $Coverage
**Race Detection:** $Race
**Timeout:** $Timeout

## Test Results

All tests passed successfully! 🎉

## Coverage

"@
    
    if ($Coverage) {
        $summary += @"

Coverage report generated: $OutputDir/coverage.html
Coverage summary: $OutputDir/coverage.txt

"@
    }
    
    $summary += @"

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
"@
    
    $summary | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Success "Test summary generated: $summaryFile"
}

# Main execution
function Main {
    Write-Host "🧪 Secure File Hub Test Runner" -ForegroundColor $White
    Write-Host "==============================" -ForegroundColor $White
    
    Test-Prerequisites
    Clear-Output
    New-OutputDirectory
    Invoke-Tests
    New-CoverageReport
    New-TestSummary
    
    Write-Success "All tests completed successfully! 🎉"
    Write-Status "Results saved to: $OutputDir"
}

# Run main function
Main
