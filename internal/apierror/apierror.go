package apierror

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// APIError represents a standardized, strongly-typed machine-readable error payload.
type APIError struct {
	Code       string `json:"code"`                  // Machine-readable identifier (e.g. "invalid_token")
	Message    string `json:"message"`               // Human-readable explanation
	Status     int    `json:"status"`                // HTTP status code (e.g. 401, 429)
	RetryAfter int    `json:"retry_after,omitempty"` // Wait time in seconds (for 429)
}

func (e APIError) Error() string {
	return fmt.Sprintf("[%d %s] %s", e.Status, e.Code, e.Message)
}

// Envelope wraps the APIError in a standard "error" root object consistent with Stripe and OpenAI standards.
type Envelope struct {
	Error APIError `json:"error"`
}

// Write writes the HTTP headers, status code, and JSON payload to the ResponseWriter.
func (e APIError) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	}
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(Envelope{Error: e})
}

// Pre-defined static errors for high-performance reuse (0 alloc)
var (
	ErrRouteNotFound = APIError{
		Code:    "route_not_found",
		Message: "No upstream route matches the requested path.",
		Status:  http.StatusNotFound,
	}

	ErrMissingToken = APIError{
		Code:    "missing_token",
		Message: "Authentication header is missing or empty.",
		Status:  http.StatusUnauthorized,
	}

	ErrInvalidToken = APIError{
		Code:    "invalid_token",
		Message: "Provided client token is invalid or unauthorized for this route.",
		Status:  http.StatusUnauthorized,
	}

	ErrBadGateway = APIError{
		Code:    "bad_gateway",
		Message: "Failed to connect to upstream service.",
		Status:  http.StatusBadGateway,
	}

	ErrInternal = APIError{
		Code:    "internal_server_error",
		Message: "An unexpected internal server error occurred.",
		Status:  http.StatusInternalServerError,
	}
)

// NewRateLimitExceeded creates a 429 Too Many Requests error with retry details.
func NewRateLimitExceeded(rpm int, retrySeconds int) APIError {
	if retrySeconds < 1 {
		retrySeconds = 1
	}
	return APIError{
		Code:       "rate_limit_exceeded",
		Message:    fmt.Sprintf("Rate limit of %d req/min exceeded. Please retry after %d seconds.", rpm, retrySeconds),
		Status:     http.StatusTooManyRequests,
		RetryAfter: retrySeconds,
	}
}

// NewPayloadTooLarge creates a 413 Payload Too Large error with size details.
func NewPayloadTooLarge(maxMB int64) APIError {
	return APIError{
		Code:    "payload_too_large",
		Message: fmt.Sprintf("Request body exceeds maximum allowed size of %d MB.", maxMB),
		Status:  http.StatusRequestEntityTooLarge,
	}
}

// NewMethodNotAllowed creates a 405 Method Not Allowed error.
func NewMethodNotAllowed(allowedMethod string) APIError {
	return APIError{
		Code:    "method_not_allowed",
		Message: fmt.Sprintf("HTTP method not allowed. Only %s is permitted.", allowedMethod),
		Status:  http.StatusMethodNotAllowed,
	}
}

// NewForbidden creates a 403 Forbidden error with a custom reason.
func NewForbidden(reason string) APIError {
	return APIError{
		Code:    "forbidden",
		Message: reason,
		Status:  http.StatusForbidden,
	}
}

// NewBadRequest creates a 400 Bad Request error.
func NewBadRequest(reason string) APIError {
	return APIError{
		Code:    "bad_request",
		Message: reason,
		Status:  http.StatusBadRequest,
	}
}

// NewCredentialRefreshFailed creates a 502 when Gatekey could not renew its own
// upstream credential. It is deliberately a failure and never a pass-through of
// an expired token: a spend guard that forwards a dead credential turns a
// recoverable blip into a confusing provider error.
func NewCredentialRefreshFailed(route string) APIError {
	return APIError{
		Code:    "credential_refresh_failed",
		Message: fmt.Sprintf("Could not renew the upstream credential for route %s. This is usually transient; retry shortly.", route),
		Status:  http.StatusBadGateway,
	}
}

// NewReauthRequired creates a 502 when the refresh token itself was rejected.
// Unlike a refresh failure this never resolves on its own: someone has to
// authorise the application again, so the message says so rather than inviting a
// retry that cannot succeed.
func NewReauthRequired(route string) APIError {
	return APIError{
		Code:    "reauth_required",
		Message: fmt.Sprintf("The stored credential for route %s was rejected by the provider and must be re-authorised. Run the device flow again.", route),
		Status:  http.StatusBadGateway,
	}
}

// NewTokenQuotaExceeded creates a 402 Payment Required error when a token exceeds its allocated token budget.
func NewTokenQuotaExceeded(limit, current uint64) APIError {
	return APIError{
		Code:    "token_quota_exceeded",
		Message: fmt.Sprintf("Token quota exceeded: consumed %d tokens out of allowed %d tokens.", current, limit),
		Status:  http.StatusPaymentRequired,
	}
}

// NewBudgetQuotaExceeded creates a 402 Payment Required error when a token exceeds its dollar budget.
func NewBudgetQuotaExceeded(limitUSD, currentUSD float64) APIError {
	return APIError{
		Code:    "budget_quota_exceeded",
		Message: fmt.Sprintf("Dollar budget quota exceeded: consumed $%.4f out of allowed $%.2f.", currentUSD, limitUSD),
		Status:  http.StatusPaymentRequired,
	}
}

// NewTotalQuotaExceeded creates a 402 Payment Required error when a route has
// spent its budget across every install. The message gives no amounts: they
// describe the operator's spending, not the caller's.
func NewTotalQuotaExceeded() APIError {
	return APIError{
		Code:    "total_quota_exceeded",
		Message: "This service has reached its usage limit for the current period.",
		Status:  http.StatusPaymentRequired,
	}
}
