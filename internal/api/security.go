package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"netwatch.local/netwatch/internal/contract"
)

func securityIngest(c Config) func(http.ResponseWriter, *http.Request, string) {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(w http.ResponseWriter, r *http.Request, sensor string) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if err != nil {
			sendJSON(w, 413, map[string]string{"error": "observation_too_large"})
			return
		}
		if contract.Validate("security-observation", raw) != nil {
			sendJSON(w, 422, map[string]string{"error": "invalid_security_observation"})
			return
		}
		endpoint := c.SecurityEndpoint
		if endpoint == "" {
			endpoint = "http://127.0.0.1:8000/v1/security/assess"
		}
		req, err := http.NewRequestWithContext(r.Context(), "POST", endpoint, bytes.NewReader(raw))
		if err != nil {
			sendJSON(w, 503, map[string]string{"error": "assessment_unavailable"})
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			sendJSON(w, 503, map[string]string{"error": "assessment_unavailable"})
			return
		}
		defer resp.Body.Close()
		result, err := io.ReadAll(io.LimitReader(resp.Body, 131073))
		if err != nil || resp.StatusCode != 200 || len(result) > 131072 || contract.Validate("security-assessment", result) != nil {
			sendJSON(w, 502, map[string]string{"error": "invalid_assessment_response"})
			return
		}
		var input, output struct {
			Entity   string
			Start    int64 `json:"start_s"`
			Interval int   `json:"interval_s"`
		}
		if json.Unmarshal(raw, &input) != nil || json.Unmarshal(result, &output) != nil || input != output {
			sendJSON(w, 502, map[string]string{"error": "assessment_identity_mismatch"})
			return
		}
		id, err := c.Store.SaveAssessment(r.Context(), sensor, raw, result)
		if err != nil {
			sendJSON(w, 503, map[string]string{"error": "storage_unavailable"})
			return
		}
		sendJSON(w, 200, map[string]any{"id": id, "assessment": json.RawMessage(result)})
	}
}

func validSecurityEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() != "" && u.User == nil && u.Fragment == "" && (u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))
}
