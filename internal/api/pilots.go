package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/store"
)

const pilotReportRoute = "GET /v1/pilots/{name}/report"

func pilotRoutes(mux *http.ServeMux, c Config, protect protectedHandler) {
	mux.HandleFunc("POST /v1/pilots/{name}/start", protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		result, err := c.Store.StartPilot(r.Context(), r.PathValue("name"), c.ModelID, c.PolicyVersion)
		pilotResponse(w, result, err)
	}))
	mux.HandleFunc(pilotReportRoute, protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		result, err := c.Store.PilotReport(r.Context(), r.PathValue("name"))
		pilotResponse(w, result, err)
	}))
	mux.HandleFunc("POST /v1/pilots/{name}/labels", protect(func(w http.ResponseWriter, r *http.Request, actor string) {
		var label store.PilotLabel
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&label) != nil || decoder.Decode(new(any)) != io.EOF {
			pilotResponse(w, nil, store.ErrPilotLabel)
			return
		}
		err := c.Store.AddPilotLabel(r.Context(), r.PathValue("name"), actor, label)
		pilotResponse(w, label, err)
	}))
}

func pilotResponse(w http.ResponseWriter, data any, err error) {
	switch {
	case err == nil:
		sendJSON(w, http.StatusOK, data)
	case errors.Is(err, store.ErrPilotName), errors.Is(err, store.ErrPilotLabel):
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_pilot_request"})
	case errors.Is(err, store.ErrConflict):
		sendJSON(w, http.StatusConflict, map[string]string{"error": "conflicting_reference_interval"})
	case errors.Is(err, pgx.ErrNoRows):
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "pilot_or_sensor_not_found"})
	default:
		sendJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
	}
}

// A weekly aggregation can outlive the default timeout for interactive requests.
const pilotReportTimeout = 110 * time.Second
