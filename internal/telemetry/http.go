package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type responseStatus struct {
	http.ResponseWriter
	code int
}

func (w *responseStatus) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseStatus) WriteHeader(code int) {
	if w.code == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseStatus) Write(data []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

// AccessLog logs only route templates and response metadata, without input content.
func AccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var random [16]byte
		_, _ = rand.Read(random[:])
		requestID := hex.EncodeToString(random[:])
		req.Header.Set("X-Request-ID", requestID)
		w.Header().Set("X-Request-ID", requestID)
		start := time.Now()
		out := &responseStatus{ResponseWriter: w}
		next.ServeHTTP(out, req)
		if out.code == 0 {
			out.code = http.StatusOK
		}
		level := slog.LevelInfo
		switch {
		case out.code >= 500:
			level = slog.LevelError
		case out.code >= 400:
			level = slog.LevelWarn
		case req.Pattern == "GET /health/live" || req.Pattern == "GET /health/ready":
			level = slog.LevelDebug
		}
		log.Log(req.Context(), level, "http_request", "request_id", requestID, "route", req.Pattern,
			"status", out.code, "duration_ms", float64(time.Since(start))/float64(time.Millisecond))
	})
}
