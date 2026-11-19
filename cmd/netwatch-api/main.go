package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netwatch.local/netwatch/internal/api"
	"netwatch.local/netwatch/internal/store"
	"netwatch.local/netwatch/internal/telemetry"
)

func run(log *slog.Logger) error {
	checkReady := flag.Bool("check-ready", false, "check the loopback readiness endpoint and exit")
	migrate := flag.Bool("migrate-only", false, "apply versioned SQL migrations and exit")
	flag.Parse()
	if flag.NArg() != 0 || (*migrate && *checkReady) {
		return fmt.Errorf("unexpected arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	healthAddress := os.Getenv("NETWATCH_API_HEALTH_ADDRESS")
	if *checkReady {
		return telemetry.CheckReady(ctx, healthAddress)
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	url := os.Getenv("NETWATCH_DATABASE_URL")
	if url == "" {
		return fmt.Errorf("NETWATCH_DATABASE_URL is required")
	}
	db, err := store.Open(startup, url)
	if err != nil {
		return err
	}
	defer db.Close()
	if *migrate {
		if err := db.Migrate(startup); err != nil {
			return err
		}
		log.Info("migrations_applied")
		return nil
	}
	if err = db.Ready(startup); err != nil {
		return err
	}
	var tokens map[string]string
	if json.Unmarshal([]byte(os.Getenv("NETWATCH_SENSOR_TOKENS")), &tokens) != nil {
		return fmt.Errorf("NETWATCH_SENSOR_TOKENS must map sensor IDs to tokens")
	}
	policy := os.Getenv("NETWATCH_POLICY_VERSION")
	if policy == "" {
		policy = "v1"
	}
	var operators map[string]string
	if raw := os.Getenv("NETWATCH_OPERATOR_TOKENS"); raw != "" {
		if json.Unmarshal([]byte(raw), &operators) != nil {
			return fmt.Errorf("invalid operator configuration")
		}
	}
	handler, err := api.New(api.Config{Store: db, PrivateCompose: os.Getenv("NETWATCH_PRIVATE_COMPOSE") == "true", SecurityEndpoint: os.Getenv("NETWATCH_SECURITY_ENDPOINT"), Tokens: tokens, Operators: operators, WebDir: os.Getenv("NETWATCH_WEB_DIR"), ModelID: os.Getenv("NETWATCH_MODEL_ID"), PolicyVersion: policy})
	if err != nil {
		return err
	}
	addr := os.Getenv("NETWATCH_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address")
	}
	ip := net.ParseIP(host)
	cert, key := os.Getenv("NETWATCH_TLS_CERT"), os.Getenv("NETWATCH_TLS_KEY")
	if (cert == "") != (key == "") {
		return fmt.Errorf("TLS requires both certificate and key")
	}
	if (ip == nil || !ip.IsLoopback()) && host != "localhost" && cert == "" && os.Getenv("NETWATCH_ALLOW_INSECURE_HTTP") != "true" {
		return fmt.Errorf("non-loopback API requires TLS or explicit isolated-lab HTTP")
	}
	srv := &http.Server{Addr: addr, Handler: telemetry.AccessLog(log, handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	srv.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelError)
	if cert != "" {
		certificates, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("could not load API TLS certificate and key")
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificates}, MinVersion: tls.VersionTLS12}
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	health, err := telemetry.StartHealth(ctx, healthAddress, db.Ready)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			done <- srv.ServeTLS(listener, "", "")
		} else {
			done <- srv.Serve(listener)
		}
	}()
	log.Info("api_listening", "address", addr, "tls", srv.TLSConfig != nil)
	select {
	case err = <-health:
		_ = srv.Close()
		return err
	case err = <-done:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			return err
		}
		log.Info("api_stopped")
		return nil
	}
}
func main() {
	log := telemetry.NewLogger("api")
	if err := run(log); err != nil {
		log.Error("api_failed", "error", err.Error())
		os.Exit(1)
	}
}
