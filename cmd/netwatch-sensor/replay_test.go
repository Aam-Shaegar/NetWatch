package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReplayProtectsFiles(t *testing.T) {
	in := "../../tests/fixtures/pcap/syn-retry.pcap"
	out := filepath.Join(t.TempDir(), "packets.jsonl")
	args := []string{"--input", in, "--output", out}
	if err := replay(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if bytes.Count(data, []byte("\n")) != 2 {
		t.Fatal("bad record count")
	}
	if err := replay(context.Background(), args); err == nil {
		t.Fatal("existing output overwritten")
	}
	after, _ := os.ReadFile(out)
	if !bytes.Equal(data, after) {
		t.Fatal("output changed")
	}
}
