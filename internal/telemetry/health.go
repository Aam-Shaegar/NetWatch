package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// healthEndpoint only accepts an explicit numeric loopback address for the private listener.
func healthEndpoint(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || number <= 0 || number > 65535 {
		return "", fmt.Errorf("health address must be a loopback IP and port")
	}
	return "http://" + address + "/health/ready", nil
}

// CheckReady queries a local readiness socket with a bounded deadline.
func CheckReady(ctx context.Context, address string) error {
	endpoint, err := healthEndpoint(address)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("readiness listener is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("process is not ready (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// StartHealth starts an optional loopback readiness server and returns its failure channel.
func StartHealth(ctx context.Context, address string, check func(context.Context) error) (<-chan error, error) {
	if address == "" {
		return nil, nil
	}
	if _, err := healthEndpoint(address); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("could not bind health address: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, http.StatusOK, "alive")
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, req *http.Request) {
		requestCtx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if check(requestCtx) != nil {
			writeHealth(w, http.StatusServiceUnavailable, "not_ready")
			return
		}
		writeHealth(w, http.StatusOK, "ready")
	})
	srv := &http.Server{
		Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second,
		IdleTimeout: 3 * time.Second, MaxHeaderBytes: 4096,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	done := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- err
		}
	}()
	return done, nil
}

func writeHealth(w http.ResponseWriter, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}
