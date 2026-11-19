package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"netwatch.local/netwatch/internal/contract"
)

var (
	ErrUnavailable     = errors.New("assessment_unavailable")
	ErrInvalidResponse = errors.New("invalid_assessment_response")
	ErrMismatched      = errors.New("assessment_identity_mismatch")
	ErrRejected        = errors.New("assessment_rejected")
)

func ValidEndpoint(raw, internalPath string, privateCompose bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return privateCompose && u.Host == "ml:8000" && u.EscapedPath() == internalPath
	}
}

type Client struct {
	endpoint string
	http     *http.Client
}

func New(endpoint string, timeout time.Duration) *Client {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8000/v1/security/assess"
	}
	return &Client{
		endpoint: endpoint,
		http: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func (c *Client) Close() {
	c.http.CloseIdleConnections()
}

func (c *Client) Assess(ctx context.Context, raw []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(io.LimitReader(resp.Body, 131073))
	if err != nil || len(result) > 131072 {
		return nil, ErrInvalidResponse
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		var reject struct{ Error string }
		if json.Unmarshal(result, &reject) == nil && reject.Error == "invalid_security_observation" {
			return nil, ErrRejected
		}
	}
	if resp.StatusCode != http.StatusOK || contract.Validate("security-assessment", result) != nil {
		return nil, ErrInvalidResponse
	}
	var input, output struct {
		Entity   string
		Start    int64 `json:"start_s"`
		Interval int   `json:"interval_s"`
	}
	if json.Unmarshal(raw, &input) != nil || json.Unmarshal(result, &output) != nil || input != output {
		return nil, ErrMismatched
	}
	return result, nil
}
