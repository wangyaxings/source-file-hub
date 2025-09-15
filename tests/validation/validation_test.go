package validation

import (
	"net/url"
	"reflect"
	"testing"

	"secure-file-hub/internal/presentation/http/validation"
)

func TestParsePagination_Defaults(t *testing.T) {
	q := url.Values{}
	pagination, details := validation.ParsePagination(q, 20, 100)

	if pagination.Page != 1 {
		t.Errorf("Expected default page 1, got %d", pagination.Page)
	}
	if pagination.Limit != 20 {
		t.Errorf("Expected default limit 20, got %d", pagination.Limit)
	}
	if len(details) != 0 {
		t.Errorf("Expected no validation errors, got %v", details)
	}
}

func TestParsePagination_ValidValues(t *testing.T) {
	q := url.Values{}
	q.Set("page", "3")
	q.Set("limit", "50")
	
	pagination, details := validation.ParsePagination(q, 20, 100)

	if pagination.Page != 3 {
		t.Errorf("Expected page 3, got %d", pagination.Page)
	}
	if pagination.Limit != 50 {
		t.Errorf("Expected limit 50, got %d", pagination.Limit)
	}
	if len(details) != 0 {
		t.Errorf("Expected no validation errors, got %v", details)
	}
}

func TestParsePagination_InvalidPage(t *testing.T) {
	q := url.Values{}
	q.Set("page", "invalid")
	q.Set("limit", "25")
	
	pagination, details := validation.ParsePagination(q, 20, 100)

	if pagination.Page != 1 {
		t.Errorf("Expected default page 1 for invalid input, got %d", pagination.Page)
	}
	if pagination.Limit != 25 {
		t.Errorf("Expected limit 25, got %d", pagination.Limit)
	}
	if details["page"] != "must be a positive integer" {
		t.Errorf("Expected page validation error, got %v", details["page"])
	}
}

func TestParsePagination_InvalidLimit(t *testing.T) {
	q := url.Values{}
	q.Set("page", "2")
	q.Set("limit", "invalid")
	
	pagination, details := validation.ParsePagination(q, 20, 100)

	if pagination.Page != 2 {
		t.Errorf("Expected page 2, got %d", pagination.Page)
	}
	if pagination.Limit != 20 {
		t.Errorf("Expected default limit 20 for invalid input, got %d", pagination.Limit)
	}
	if details["limit"] != "must be a positive integer" {
		t.Errorf("Expected limit validation error, got %v", details["limit"])
	}
}

func TestParsePagination_NegativeValues(t *testing.T) {
	q := url.Values{}
	q.Set("page", "-1")
	q.Set("limit", "0")
	
	pagination, details := validation.ParsePagination(q, 20, 100)

	if pagination.Page != 1 {
		t.Errorf("Expected default page 1 for negative input, got %d", pagination.Page)
	}
	if pagination.Limit != 20 {
		t.Errorf("Expected default limit 20 for zero input, got %d", pagination.Limit)
	}
	if details["page"] != "must be a positive integer" {
		t.Errorf("Expected page validation error, got %v", details["page"])
	}
	if details["limit"] != "must be a positive integer" {
		t.Errorf("Expected limit validation error, got %v", details["limit"])
	}
}

func TestParsePagination_ExceedsMaxLimit(t *testing.T) {
	q := url.Values{}
	q.Set("page", "1")
	q.Set("limit", "150")
	
	pagination, details := validation.ParsePagination(q, 20, 100)

	if pagination.Page != 1 {
		t.Errorf("Expected page 1, got %d", pagination.Page)
	}
	if pagination.Limit != 100 {
		t.Errorf("Expected limit capped at 100, got %d", pagination.Limit)
	}
	
	limitDetails, ok := details["limit"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected limit details to be a map, got %T", details["limit"])
	} else if limitDetails["max"] != 100 {
		t.Errorf("Expected max limit 100 in details, got %v", limitDetails["max"])
	}
}

func TestParsePagination_NoMaxLimit(t *testing.T) {
	q := url.Values{}
	q.Set("limit", "1000")
	
	pagination, details := validation.ParsePagination(q, 20, 0) // maxLimit = 0 means no limit

	if pagination.Limit != 1000 {
		t.Errorf("Expected limit 1000 when no max limit, got %d", pagination.Limit)
	}
	if len(details) != 0 {
		t.Errorf("Expected no validation errors when no max limit, got %v", details)
	}
}

func TestValidateUserRole_ValidRoles(t *testing.T) {
	validRoles := []string{"viewer", "administrator"}
	
	for _, role := range validRoles {
		if !validation.ValidateUserRole(role) {
			t.Errorf("Expected role '%s' to be valid", role)
		}
	}
}

func TestValidateUserRole_InvalidRoles(t *testing.T) {
	invalidRoles := []string{"", "admin", "user", "guest", "superuser", "VIEWER", "Administrator"}
	
	for _, role := range invalidRoles {
		if validation.ValidateUserRole(role) {
			t.Errorf("Expected role '%s' to be invalid", role)
		}
	}
}

func TestValidateUserStatus_ValidStatuses(t *testing.T) {
	validStatuses := []string{"", "active", "suspended", "disabled", "pending"}
	
	for _, status := range validStatuses {
		if !validation.ValidateUserStatus(status) {
			t.Errorf("Expected status '%s' to be valid", status)
		}
	}
}

func TestValidateUserStatus_InvalidStatuses(t *testing.T) {
	invalidStatuses := []string{"inactive", "banned", "deleted", "ACTIVE", "Pending"}
	
	for _, status := range invalidStatuses {
		if validation.ValidateUserStatus(status) {
			t.Errorf("Expected status '%s' to be invalid", status)
		}
	}
}

func TestValidateFileTypeExtension_ValidCombinations(t *testing.T) {
	testCases := []struct {
		fileType string
		filename string
		expected bool
	}{
		{"roadmap", "test.tsv", true},
		{"recommendation", "report.xlsx", true},
		{"config", "app.json", true},
		{"config", "settings.yaml", true},
		{"config", "docker.yml", true},
		{"certificate", "server.crt", true},
		{"certificate", "key.pem", true},
		{"certificate", "private.key", true},
		{"docs", "readme.txt", true},
		{"docs", "guide.md", true},
		{"docs", "manual.pdf", true},
	}

	for _, tc := range testCases {
		result := validation.ValidateFileTypeExtension(tc.fileType, tc.filename)
		if result != tc.expected {
			t.Errorf("Expected ValidateFileTypeExtension('%s', '%s') = %v, got %v", 
				tc.fileType, tc.filename, tc.expected, result)
		}
	}
}

func TestValidateFileTypeExtension_InvalidCombinations(t *testing.T) {
	testCases := []struct {
		fileType string
		filename string
		expected bool
	}{
		{"roadmap", "test.xlsx", false},
		{"recommendation", "report.tsv", false},
		{"config", "app.txt", false},
		{"certificate", "server.json", false},
		{"docs", "readme.xlsx", false},
		{"unknown", "file.txt", false},
		{"roadmap", "test.TSV", true}, // Case insensitive
	}

	for _, tc := range testCases {
		result := validation.ValidateFileTypeExtension(tc.fileType, tc.filename)
		if result != tc.expected {
			t.Errorf("Expected ValidateFileTypeExtension('%s', '%s') = %v, got %v", 
				tc.fileType, tc.filename, tc.expected, result)
		}
	}
}

func TestValidateFileTypeExtension_CaseInsensitive(t *testing.T) {
	// Test that extensions are case-insensitive
	testCases := []struct {
		fileType string
		filename string
		expected bool
	}{
		{"config", "app.JSON", true},
		{"config", "settings.YAML", true},
		{"docs", "readme.TXT", true},
		{"docs", "guide.MD", true},
	}

	for _, tc := range testCases {
		result := validation.ValidateFileTypeExtension(tc.fileType, tc.filename)
		if result != tc.expected {
			t.Errorf("Expected ValidateFileTypeExtension('%s', '%s') = %v, got %v", 
				tc.fileType, tc.filename, tc.expected, result)
		}
	}
}

func TestGetAllowedExtensions_ValidFileTypes(t *testing.T) {
	testCases := []struct {
		fileType string
		expected []string
	}{
		{"roadmap", []string{".tsv"}},
		{"recommendation", []string{".xlsx"}},
		{"config", []string{".json", ".yaml", ".yml"}},
		{"certificate", []string{".crt", ".pem", ".key"}},
		{"docs", []string{".txt", ".md", ".pdf"}},
	}

	for _, tc := range testCases {
		result := validation.GetAllowedExtensions(tc.fileType)
		if !reflect.DeepEqual(result, tc.expected) {
			t.Errorf("Expected GetAllowedExtensions('%s') = %v, got %v", 
				tc.fileType, tc.expected, result)
		}
	}
}

func TestGetAllowedExtensions_InvalidFileType(t *testing.T) {
	result := validation.GetAllowedExtensions("unknown")
	expected := []string{}
	
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected GetAllowedExtensions('unknown') = %v, got %v", expected, result)
	}
}

func TestGetAllowedExtensions_EmptyFileType(t *testing.T) {
	result := validation.GetAllowedExtensions("")
	expected := []string{}
	
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected GetAllowedExtensions('') = %v, got %v", expected, result)
	}
}
