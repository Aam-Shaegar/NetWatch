package api

import (
	"net/http/httptest"
	"netwatch.local/netwatch/internal/store"
	"strings"
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

func TestJournalRoleBoundary(t *testing.T) {
	sensor, operator := strings.Repeat("s", 32), strings.Repeat("o", 32)
	c := Config{Tokens: map[string]string{"sensor": sensor}, Operators: map[string]string{"operator": operator}, ModelID: "model", PolicyVersion: "policy", Store: &store.Store{}}
	h, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/v1/incidents", "", 401}, {"GET", "/v1/incidents", sensor, 401}, {"POST", "/v1/incidents/1/ack", sensor, 401},
		{"GET", "/v1/windows/example", operator, 401}, {"GET", "/v1/incidents?from=3&until=2", operator, 400}, {"GET", "/v1/incidents/no-id", operator, 400},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		out := httptest.NewRecorder()
		h.ServeHTTP(out, r)
		if out.Code != tc.want {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, out.Code, tc.want)
		}
	}
	for _, collision := range []string{sensor, operator} {
		c.Operators["other"] = collision
		if _, err = New(c); err == nil {
			t.Fatal("overlapping credential accepted")
		}
	}
}
