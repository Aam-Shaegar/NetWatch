package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckHealthUsesStatusWithinDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusNoContent)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	for _, path := range []string{"/ok", "/redirect", "/offline"} {
		if got := checkHealth(client, server.URL+path, time.Now().Add(time.Second)); got != (path == "/ok") {
			t.Errorf("%s available = %v", path, got)
		}
	}
	if checkHealth(client, server.URL+"/ok", time.Now().Add(-time.Second)) {
		t.Error("expired probe reported a successful sample")
	}
}
