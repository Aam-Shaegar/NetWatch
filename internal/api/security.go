package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/assessment"
	"netwatch.local/netwatch/internal/contract"
)

func readObservation(w http.ResponseWriter, r *http.Request) []byte {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			sendJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "observation_too_large"})
		} else {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		}
		return nil
	}
	if contract.Validate("security-observation", raw) != nil {
		sendJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid_security_observation"})
		return nil
	}
	return raw
}

func securityIngest(c Config) func(http.ResponseWriter, *http.Request, string) {
	client := assessment.New(c.SecurityEndpoint, 10*time.Second)
	return func(w http.ResponseWriter, r *http.Request, sensor string) {
		raw := readObservation(w, r)
		if raw == nil {
			return
		}
		result, err := client.Assess(r.Context(), raw)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, assessment.ErrUnavailable) {
				status = http.StatusServiceUnavailable
			}
			sendJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		id, err := c.Store.SaveAssessment(r.Context(), sensor, raw, result)
		if err != nil {
			sendJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		sendJSON(w, http.StatusOK, map[string]any{"id": id, "assessment": json.RawMessage(result)})
	}
}

func securityEnqueue(c Config) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sensor string) {
		raw := readObservation(w, r)
		if raw == nil {
			return
		}
		id, err := c.Store.EnqueueAssessment(r.Context(), sensor, raw)
		if err != nil {
			sendJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
			return
		}
		w.Header().Set("Location", "/v1/security/observations/"+id)
		sendJSON(w, http.StatusAccepted, map[string]string{"job_id": id})
	}
}

func securityStatus(c Config) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sensor string) {
		id, err := strconv.ParseInt(r.PathValue("job_id"), 10, 64)
		if err != nil || id <= 0 {
			sendJSON(w, http.StatusNotFound, map[string]string{"error": "observation_not_found"})
			return
		}
		receipt, err := c.Store.AssessmentStatus(r.Context(), sensor, id)
		if errors.Is(err, pgx.ErrNoRows) {
			sendJSON(w, http.StatusNotFound, map[string]string{"error": "observation_not_found"})
		} else if err != nil {
			sendJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
		} else {
			sendJSON(w, http.StatusOK, json.RawMessage(receipt))
		}
	}
}
