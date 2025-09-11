package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TestConfig holds test configuration
type TestConfig struct {
	Verbose      bool
	Coverage     bool
	Race         bool
	Timeout      time.Duration
	Package      string
	OutputDir    string
	CoverageFile string
}

func main() {
	config := parseFlags()

	fmt.Println("🧪 Running Secure File Hub Tests")
	fmt.Println("=================================")

	// Create output directory if it doesn't exist
	if config.OutputDir != "" {
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			fmt.Printf("❌ Failed to create output directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Run tests
	if err := runTests(config); err != nil {
		fmt.Printf("❌ Tests failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ All tests passed!")
}

func parseFlags() *TestConfig {
	config := &TestConfig{}

	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.Coverage, "cover", false, "Generate coverage report")
	flag.BoolVar(&config.Race, "race", false, "Enable race detection")
	flag.DurationVar(&config.Timeout, "timeout", 10*time.Minute, "Test timeout")
	flag.StringVar(&config.Package, "pkg", "./tests/...", "Package to test")
	flag.StringVar(&config.OutputDir, "output", "test-results", "Output directory for test results")
	flag.StringVar(&config.CoverageFile, "coverfile", "coverage.out", "Coverage output file")

	flag.Parse()

	return config
}

func runTests(config *TestConfig) error {
	// Build test command
	args := []string{"test"}

	if config.Verbose {
		args = append(args, "-v")
	}

	if config.Coverage {
		args = append(args, "-cover")
		args = append(args, "-coverprofile="+config.CoverageFile)
	}

	if config.Race {
		args = append(args, "-race")
	}

	args = append(args, "-timeout="+config.Timeout.String())
	args = append(args, config.Package)

	// Run tests
	fmt.Printf("🔍 Running tests with command: go %s\n", strings.Join(args, " "))

	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("test execution failed: %v", err)
	}

	// Generate coverage report if requested
	if config.Coverage {
		if err := generateCoverageReport(config); err != nil {
			return fmt.Errorf("coverage report generation failed: %v", err)
		}
	}

	// Generate test summary
	if err := generateTestSummary(config); err != nil {
		return fmt.Errorf("test summary generation failed: %v", err)
	}

	return nil
}

func generateCoverageReport(config *TestConfig) error {
	fmt.Println("📊 Generating coverage report...")

	// Generate HTML coverage report
	htmlCmd := exec.Command("go", "tool", "cover", "-html="+config.CoverageFile, "-o", filepath.Join(config.OutputDir, "coverage.html"))
	if err := htmlCmd.Run(); err != nil {
		return fmt.Errorf("failed to generate HTML coverage report: %v", err)
	}

	// Generate coverage summary
	summaryCmd := exec.Command("go", "tool", "cover", "-func="+config.CoverageFile)
	output, err := summaryCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate coverage summary: %v", err)
	}

	// Save coverage summary
	summaryFile := filepath.Join(config.OutputDir, "coverage.txt")
	if err := os.WriteFile(summaryFile, output, 0644); err != nil {
		return fmt.Errorf("failed to save coverage summary: %v", err)
	}

	fmt.Printf("📈 Coverage report generated: %s\n", filepath.Join(config.OutputDir, "coverage.html"))
	fmt.Printf("📋 Coverage summary saved: %s\n", summaryFile)

	return nil
}

func generateTestSummary(config *TestConfig) error {
	fmt.Println("📝 Generating test summary...")

	// Get current time
	now := time.Now()

	// Create summary content
	summary := fmt.Sprintf(`# Test Summary

**Date:** %s
**Package:** %s
**Verbose:** %t
**Coverage:** %t
**Race Detection:** %t
**Timeout:** %s

## Test Results

All tests passed successfully! 🎉

## Coverage

Coverage report generated: %s
Coverage summary: %s

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
`,
		now.Format("2006-01-02 15:04:05"),
		config.Package,
		config.Verbose,
		config.Coverage,
		config.Race,
		config.Timeout.String(),
		filepath.Join(config.OutputDir, "coverage.html"),
		filepath.Join(config.OutputDir, "coverage.txt"),
	)

	// Save summary
	summaryFile := filepath.Join(config.OutputDir, "test-summary.md")
	if err := os.WriteFile(summaryFile, []byte(summary), 0644); err != nil {
		return fmt.Errorf("failed to save test summary: %v", err)
	}

	fmt.Printf("📄 Test summary saved: %s\n", summaryFile)

	return nil
}
