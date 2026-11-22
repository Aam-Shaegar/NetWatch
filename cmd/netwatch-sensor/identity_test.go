package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollIfNeededPreservesIdentityAndChecksEndpoint(t *testing.T) {
	t.Setenv("NETWATCH_SENSOR_CA_PEM", "")
	path := filepath.Join(t.TempDir(), "sensor.json")
	saved := sensorIdentity{ID: "pilot", Endpoint: "grpcs://localhost:8444", Token: strings.Repeat("a", 64)}
	if err := writeIdentity(path, saved, false); err != nil {
		t.Fatal(err)
	}
	enroll := func(endpoint string) error {
		return identityCommand(context.Background(), "enroll", []string{"--if-needed", "--identity", path, "--endpoint", endpoint})
	}
	if err := enroll(saved.Endpoint); err != nil {
		t.Fatal(err)
	}
	if err := enroll("grpcs://localhost:8445"); err == nil {
		t.Fatal("accepted another endpoint for the stored registration")
	}
	if got, err := readIdentity(path); err != nil || got != saved {
		t.Fatalf("original registration was not preserved: %v", err)
	}
}
