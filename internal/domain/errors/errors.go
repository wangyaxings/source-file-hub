package domainerrors

type DomainError struct {
    Code    string                 `json:"code"`
    Message string                 `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
}

func (e DomainError) Error() string { return e.Message }

func New(code, message string, details map[string]interface{}) DomainError {
    return DomainError{Code: code, Message: message, Details: details}
}

var (
    ErrUserNotFound     = DomainError{Code: "USER_NOT_FOUND", Message: "User not found"}
    ErrInvalidPassword  = DomainError{Code: "INVALID_PASSWORD", Message: "Invalid password"}
    ErrFileNotFound     = DomainError{Code: "FILE_NOT_FOUND", Message: "File not found"}
    ErrInsufficientAuth = DomainError{Code: "INSUFFICIENT_AUTH", Message: "Insufficient permissions"}
    ErrInternal         = DomainError{Code: "INTERNAL_ERROR", Message: "Internal server error"}
)

