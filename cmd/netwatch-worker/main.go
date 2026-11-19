package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netwatch.local/netwatch/internal/store"
	"netwatch.local/netwatch/internal/telemetry"
	"netwatch.local/netwatch/internal/worker"
)

func run(log *slog.Logger) error {
	checkReady := flag.Bool("check-ready", false, "check the loopback readiness endpoint and exit")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected worker arguments")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	healthAddress := os.Getenv("NETWATCH_WORKER_HEALTH_ADDRESS")
	if *checkReady {
		return telemetry.CheckReady(ctx, healthAddress)
	}

	databaseURL := os.Getenv("NETWATCH_DATABASE_URL")
	if databaseURL == "" {
		return fmt.Errorf("NETWATCH_DATABASE_URL is required")
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	db, err := store.Open(startup, databaseURL)
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
	for name, target := range map[string]*time.Duration{"NETWATCH_LEASE": &config.Lease, "NETWATCH_ML_TIMEOUT": &config.Timeout, "NETWATCH_WORKER_POLL": &config.Poll, "NETWATCH_INCIDENT_GAP_WAIT": &config.GapWait} {
		if value := os.Getenv(name); value != "" {
			d, e := time.ParseDuration(value)
			if e != nil {
				return fmt.Errorf("invalid %s", name)
			}
			*target = d
		}
	}
	config.AllowInsecureHTTP = os.Getenv("NETWATCH_ALLOW_INSECURE_HTTP") == "true"
	config.SecurityEndpoint = os.Getenv("NETWATCH_SECURITY_ENDPOINT")
	config.PrivateCompose = os.Getenv("NETWATCH_PRIVATE_COMPOSE") == "true"
	runner, err := worker.New(db, config)
	if err != nil {
		return err
	}
	runner.Log = func(event, detail string) {
		switch event {
		case "prediction_saved":
			log.Info(event, "event_id", detail)
		case "assessment_saved":
			log.Info(event, "job_id", detail)
		case "lease_lost":
			log.Warn(event, "event_id", detail)
		default:
			log.Warn(event, "detail", detail)
		}
	}
	health, err := telemetry.StartHealth(ctx, healthAddress, readiness(db, config.Endpoint, os.Getenv("NETWATCH_MODEL_ID"), os.Getenv("NETWATCH_POLICY_VERSION")))
	if err != nil {
		return err
	}
	log.Info("worker_started")
	finished := make(chan error, 1)
	go func() { finished <- runner.Run(ctx) }()
	select {
	case err := <-finished:
		log.Info("worker_stopped")
		return err
	case err := <-health:
		stop()
		<-finished
		return err
	}
}

func readiness(db *store.Store, inference, requiredModel, requiredPolicy string) func(context.Context) error {
	endpoint, _ := url.Parse(inference)
	endpoint.Path = "/health/ready"
	endpoint.RawPath = ""
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return func(ctx context.Context) error {
		if err := db.Ready(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		result := struct {
			Status        string `json:"status"`
			ModelID       string `json:"model_id"`
			PolicyVersion string `json:"policy_version"`
		}{}
		if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result) != nil ||
			result.Status != "ready" || (requiredModel != "" && requiredModel != result.ModelID) ||
			(requiredPolicy != "" && requiredPolicy != result.PolicyVersion) {
			return fmt.Errorf("ML readiness check failed")
		}
		return nil
	}
}

func main() {
	log := telemetry.NewLogger("worker")
	if err := run(log); err != nil {
		log.Error("worker_failed", "error", err.Error())
		os.Exit(1)
	}
}
