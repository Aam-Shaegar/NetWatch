package api

import (
	"net/http/httptest"
	"testing"
)

func TestHealthDoesNotPretendReadiness(t *testing.T) {
	for path, want := range map[string]int{"/health/live": 200, "/health/ready": 503, "/v1/windows": 404} {
		r := httptest.NewRecorder()
		Handler().ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != want {
			t.Fatalf("%s: %d", path, r.Code)
		}
	}
}
