package apierror

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIError_Write(t *testing.T) {
	rec := httptest.NewRecorder()
	err := NewRateLimitExceeded(60, 5)
	err.Write(rec)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", rec.Code)
	}

	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json Content-Type, got %s", rec.Header().Get("Content-Type"))
	}

	if rec.Header().Get("Retry-After") != "5" {
		t.Errorf("expected Retry-After: 5, got %s", rec.Header().Get("Retry-After"))
	}

	var env Envelope
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if env.Error.Code != "rate_limit_exceeded" {
		t.Errorf("expected code rate_limit_exceeded, got %s", env.Error.Code)
	}
	if env.Error.Status != 429 {
		t.Errorf("expected status 429, got %d", env.Error.Status)
	}
	if env.Error.RetryAfter != 5 {
		t.Errorf("expected retry_after 5, got %d", env.Error.RetryAfter)
	}
}
