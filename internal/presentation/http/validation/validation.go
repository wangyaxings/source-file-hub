package validation

import (
    "net/url"
    "strconv"
)

// Pagination holds parsed pagination params.
type Pagination struct {
    Page  int
    Limit int
}

// ParsePagination parses page/limit from query with sensible defaults and bounds.
// Defaults: page=1, limit=20. maxLimit applies an upper bound if >0.
// Returns the parsed Pagination and a details map for validation errors (if any).
func ParsePagination(q url.Values, defaultLimit, maxLimit int) (Pagination, map[string]interface{}) {
    page := 1
    limit := defaultLimit
    details := map[string]interface{}{}

    if v := q.Get("page"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            page = n
        } else {
            details["page"] = "must be a positive integer"
        }
    }
    if v := q.Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            limit = n
        } else {
            details["limit"] = "must be a positive integer"
        }
    }
    if maxLimit > 0 && limit > maxLimit {
        details["limit"] = map[string]interface{}{
            "max": maxLimit,
        }
        limit = maxLimit
    }
    return Pagination{Page: page, Limit: limit}, details
}

// ValidateUserRole returns true if role is supported for application users.
func ValidateUserRole(role string) bool {
    switch role {
    case "viewer", "administrator":
        return true
    default:
        return false
    }
}

// ValidateUserStatus returns true if status is supported for user_roles.status.
func ValidateUserStatus(status string) bool {
    if status == "" { // empty is allowed (no change)
        return true
    }
    switch status {
    case "active", "suspended", "disabled", "pending":
        return true
    default:
        return false
    }
}

