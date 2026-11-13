package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netwatch.local/netwatch/internal/store"
	"netwatch.local/netwatch/internal/worker"
)

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	url := os.Getenv("NETWATCH_DATABASE_URL")
	if url == "" {
		return fmt.Errorf("NETWATCH_DATABASE_URL is required")
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	db, err := store.Open(startup, url)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = db.Ready(startup); err != nil {
		return err
	}
	config := worker.DefaultConfig()
	if endpoint := os.Getenv("NETWATCH_ML_ENDPOINT"); endpoint != "" {
		config.Endpoint = endpoint
	}
	for name, target := range map[string]*time.Duration{"NETWATCH_LEASE": &config.Lease, "NETWATCH_ML_TIMEOUT": &config.Timeout, "NETWATCH_WORKER_POLL": &config.Poll} {
		if value := os.Getenv(name); value != "" {
			d, e := time.ParseDuration(value)
			if e != nil {
				return fmt.Errorf("invalid %s", name)
			}
			*target = d
		}
	}
	config.AllowInsecureHTTP = os.Getenv("NETWATCH_ALLOW_INSECURE_HTTP") == "true"
	runner, err := worker.New(db, config)
	if err != nil {
		return err
	}
	logs := json.NewEncoder(os.Stderr)
	runner.Log = func(event, detail string) { _ = logs.Encode(map[string]string{"event": event, "detail": detail}) }
	return runner.Run(ctx)
}
func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"event": "worker_failed", "error": err.Error()})
		os.Exit(1)
	}
}
