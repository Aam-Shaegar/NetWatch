package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"netwatch.local/netwatch/internal/store"
)

type protectedHandler func(func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc

func catalogRoutes(mux *http.ServeMux, c Config, protect protectedHandler) {
	mux.HandleFunc("GET /v1/catalog/incidents", protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		data, err := c.Store.CatalogIncidents(r.Context())
		if err != nil {
			sendJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		sendJSON(w, 200, data)
	}))
	if !c.SensorRPC {
		return
	}
	mux.HandleFunc("GET /v1/sensors", protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		sensors, err := c.Store.ListSensors(r.Context())
		if err != nil {
			sensorFailure(w, err)
			return
		}
		if sensors == nil {
			sensors = []store.RegisteredSensor{}
		}
		sendJSON(w, 200, map[string]any{"sensors": sensors})
	}))
	mux.HandleFunc("POST /v1/sensors/enrollment", protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		var input struct {
			ID string `json:"id"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			sendJSON(w, 400, map[string]string{"error": "invalid_sensor_registration"})
			return
		}
		registration, err := c.Store.CreateSensorRegistration(r.Context(), input.ID)
		if err != nil {
			sensorFailure(w, err)
			return
		}
		sendJSON(w, 201, registration)
	}))
	mux.HandleFunc("POST /v1/sensors/{id}/{action}", protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		if err := c.Store.SetSensorState(r.Context(), r.PathValue("id"), r.PathValue("action")); err != nil {
			sensorFailure(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func sensorFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrSensorInput):
		sendJSON(w, 400, map[string]string{"error": "invalid_sensor_request"})
	case errors.Is(err, store.ErrSensorUnknown):
		sendJSON(w, 404, map[string]string{"error": "sensor_not_found"})
	case errors.Is(err, store.ErrSensorState):
		sendJSON(w, 409, map[string]string{"error": "sensor_state_conflict"})
	default:
		sendJSON(w, 503, map[string]string{"error": "storage_unavailable"})
	}
}
