package handler

import "net/http"

// Test helper functions to expose unexported functions for testing

// WriteErrorWithCodeForTest exposes writeErrorWithCode for testing
func WriteErrorWithCodeForTest(w http.ResponseWriter, status int, code, message string) {
	writeErrorWithCode(w, status, code, message)
}

// WriteErrorWithCodeDetailsForTest exposes writeErrorWithCodeDetails for testing
func WriteErrorWithCodeDetailsForTest(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
	writeErrorWithCodeDetails(w, status, code, message, details)
}

// WriteErrorResponseForTest exposes writeErrorResponse for testing
func WriteErrorResponseForTest(w http.ResponseWriter, status int, message string) {
	writeErrorResponse(w, status, message)
}
