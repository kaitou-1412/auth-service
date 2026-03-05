package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaitou-1412/auth-service/internal/handler"
)

func TestRespondWithJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	payload := map[string]string{"key": "value"}

	handler.RespondWithJSON(rr, http.StatusOK, payload)

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("got Content-Type %q, want application/json", ct)
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["key"] != "value" {
		t.Errorf("got key %q, want \"value\"", resp["key"])
	}
}

func TestRespondWithError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{"bad_request", http.StatusBadRequest, "invalid input"},
		{"unauthorized", http.StatusUnauthorized, "unauthorized"},
		{"not_found", http.StatusNotFound, "not found"},
		{"internal_error", http.StatusInternalServerError, "internal server error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			handler.RespondWithError(rr, tt.statusCode, tt.message)

			if rr.Code != tt.statusCode {
				t.Errorf("got status %d, want %d", rr.Code, tt.statusCode)
			}

			var resp map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}
			if resp["error"] != tt.message {
				t.Errorf("got error %q, want %q", resp["error"], tt.message)
			}
		})
	}
}
