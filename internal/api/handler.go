package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/store"
	"netwatch.local/netwatch/internal/transport"
)

type Config struct {
	Store                  *store.Store
	Tokens                 map[string]string
	ModelID, PolicyVersion string
}

// Handler retains a liveness-only startup profile when no database is configured.
func Handler() http.Handler { return routes(Config{}, nil) }
func New(c Config) (http.Handler, error) {
	if strings.ContainsRune(c.ModelID+c.PolicyVersion, 0) {
		return nil, fmt.Errorf("invalid inference target")
	}
	if c.Store == nil || c.ModelID == "" || len(c.ModelID) > 200 || c.PolicyVersion == "" || len(c.PolicyVersion) > 200 || len(c.Tokens) == 0 {
		return nil, fmt.Errorf("store, model, policy and sensor credentials are required")
	}
	tokens := map[[32]byte]string{}
	for sensor, token := range c.Tokens {
		if strings.ContainsRune(sensor, 0) || sensor == "" || len(sensor) > 200 || len(token) < 32 || strings.ContainsAny(token, " \r\n\t") {
			return nil, fmt.Errorf("invalid sensor credential configuration")
		}
		hash := sha256.Sum256([]byte(token))
		if _, exists := tokens[hash]; exists {
			return nil, fmt.Errorf("sensor tokens must be distinct")
		}
		tokens[hash] = sensor
	}
	return routes(c, tokens), nil
}
func sendJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func routes(c Config, tokens map[[32]byte]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { sendJSON(w, 200, map[string]string{"status": "alive"}) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if c.Store == nil || c.Store.Ready(ctx) != nil {
			sendJSON(w, 503, map[string]string{"status": "not_ready", "reason": "database_or_schema_unavailable"})
			return
		}
		sendJSON(w, 200, map[string]string{"status": "ready", "component": "ingestion", "ml_readiness": "separate"})
	})
	if c.Store == nil {
		return mux
	}
	authorize := func(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			token, ok := strings.CutPrefix(header, "Bearer ")
			sensor, found := tokens[sha256.Sum256([]byte(token))]
			if !ok || !found {
				w.Header().Set("WWW-Authenticate", "Bearer")
				sendJSON(w, 401, map[string]string{"error": "unauthorized"})
				return
			}
			next(w, r, sensor)
		}
	}
	mux.HandleFunc("POST /v1/windows", authorize(func(w http.ResponseWriter, r *http.Request, sensor string) {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			sendJSON(w, 415, map[string]string{"error": "application_json_required"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var max *http.MaxBytesError
			if errors.As(err, &max) {
				sendJSON(w, 413, map[string]string{"error": "body_too_large"})
			} else {
				sendJSON(w, 400, map[string]string{"error": "invalid_body"})
			}
			return
		}
		// Validate the envelope independently so invalid windows produce indexed 422s.
		var b transport.Batch
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&b) != nil || b.SchemaVersion != 1 || len(b.Windows) < 1 || len(b.Windows) > 100 || !validBatchID(b.BatchID) || r.Header.Get("Idempotency-Key") != b.BatchID {
			sendJSON(w, 400, map[string]string{"error": "invalid_batch"})
			return
		}
		var rest any
		if decoder.Decode(&rest) != io.EOF {
			sendJSON(w, 400, map[string]string{"error": "invalid_batch"})
			return
		}
		if strings.ContainsRune(b.QueueLoss.FirstEventID+b.QueueLoss.LastEventID, 0) {
			sendJSON(w, 400, map[string]string{"error": "invalid_batch"})
			return
		}
		seen := map[string]bool{}
		for i, data := range b.Windows {
			var window contract.Window
			err := contract.Validate("window", data)
			if err == nil {
				err = json.Unmarshal(data, &window)
			}
			if err == nil && strings.ContainsRune(window.EventID+window.CaptureEpoch+window.EntityID+window.SensorID, 0) {
				err = fmt.Errorf("NUL is not supported by PostgreSQL JSONB")
			}
			if err != nil {
				sendJSON(w, 422, transport.Rejection{BatchID: b.BatchID, Code: "invalid_window", ErrorIndex: &i})
				return
			}
			if window.SensorID != sensor {
				sendJSON(w, 403, map[string]string{"error": "sensor_scope_mismatch"})
				return
			}
			end, _ := strconv.ParseInt(window.WindowEndNS, 10, 64)
			if end > time.Now().Add(5*time.Minute).UnixNano() {
				sendJSON(w, 422, transport.Rejection{BatchID: b.BatchID, Code: "invalid_window", ErrorIndex: &i})
				return
			}
			if seen[window.EventID] {
				sendJSON(w, 400, map[string]string{"error": "duplicate_event_id"})
				return
			}
			seen[window.EventID] = true
			// Match Go's JSON string decoding while preserving exact JSON numbers.
			canonical := json.NewDecoder(bytes.NewReader(data))
			canonical.UseNumber()
			var value any
			if canonical.Decode(&value) != nil {
				sendJSON(w, 400, map[string]string{"error": "invalid_batch"})
				return
			}
			b.Windows[i], err = json.Marshal(value)
			if err != nil {
				sendJSON(w, 400, map[string]string{"error": "invalid_batch"})
				return
			}
		}
		if contract.Validate("batch", raw) != nil {
			sendJSON(w, 400, map[string]string{"error": "invalid_batch"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		err = c.Store.Ingest(ctx, b, sensor, c.ModelID, c.PolicyVersion)
		if errors.Is(err, store.ErrConflict) {
			sendJSON(w, 409, map[string]string{"error": "identity_conflict"})
			return
		}
		if err != nil {
			sendJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		ids := make([]string, 0, len(b.Windows))
		for _, raw := range b.Windows {
			var window contract.Window
			json.Unmarshal(raw, &window)
			ids = append(ids, window.EventID)
		}
		sendJSON(w, 200, transport.Ack{BatchID: b.BatchID, AcceptedEventIDs: ids})
	}))
	mux.HandleFunc("GET /v1/windows/{event_id}", authorize(func(w http.ResponseWriter, r *http.Request, sensor string) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		raw, err := c.Store.Window(ctx, sensor, r.PathValue("event_id"))
		if errors.Is(err, pgx.ErrNoRows) {
			sendJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		if err != nil {
			sendJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		sendJSON(w, 200, raw)
	}))
	mux.HandleFunc("GET /v1/predictions/{event_id}", authorize(func(w http.ResponseWriter, r *http.Request, sensor string) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		raw, err := c.Store.Predictions(ctx, sensor, r.PathValue("event_id"))
		if err != nil {
			sendJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		sendJSON(w, 200, map[string]any{"predictions": raw})
	}))
	return mux
}
func validBatchID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
