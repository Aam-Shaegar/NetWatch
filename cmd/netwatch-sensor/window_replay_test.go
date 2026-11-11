package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"netwatch.local/netwatch/internal/contract"
)

func TestWindowReplayGolden(t *testing.T) {
	output := filepath.Join(t.TempDir(), "windows.jsonl")
	args := []string{"--input", "../../tests/fixtures/pcap/syn-retry.pcap", "--output", output,
		"--host", "192.0.2.10", "--sensor", "test", "--epoch", "fixture",
		"--coverage-start", "1700000000000000000", "--coverage-end", "1700000005000000000"}
	if err := replay(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err = contract.Validate("window", data); err != nil {
		t.Fatal(err)
	}
	var got, want contract.Window
	json.Unmarshal(data, &got)
	golden, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(golden, &want)
	if !reflect.DeepEqual(got.Features, want.Features) || !reflect.DeepEqual(got.Quality, want.Quality) {
		t.Fatalf("CLI golden mismatch: %+v", got)
	}
	if err = replay(context.Background(), args); err == nil {
		t.Fatal("overwrote existing output")
	}
	after, _ := os.ReadFile(output)
	if string(after) != string(data) {
		t.Fatal("existing output changed")
	}
	args[3] = filepath.Join(t.TempDir(), "invalid.jsonl")
	args[len(args)-1] = args[len(args)-3] // identical start and end
	if err = replay(context.Background(), args); err == nil {
		t.Fatal("accepted empty coverage")
	}
	if _, err = os.Stat(args[3]); !os.IsNotExist(err) {
		t.Fatal("published failed replay")
	}
}
