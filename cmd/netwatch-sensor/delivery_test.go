package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/spool"
	"netwatch.local/netwatch/internal/transport"
)

func TestReplayEnqueueRestartSend(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "windows.jsonl")
	queueDir := filepath.Join(dir, "queue")
	if err := replay(context.Background(), []string{"--input", "../../tests/fixtures/pcap/syn-retry.pcap", "--output", output, "--host", "192.0.2.10", "--epoch", "delivery-test"}); err != nil {
		t.Fatal(err)
	}
	if err := queueCommand(context.Background(), "enqueue", []string{"--input", output, "--spool", queueDir}); err != nil {
		t.Fatal(err)
	}
	q, err := spool.Open(queueDir, spool.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	items, err := q.Peek(100, 1<<20)
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	expectedID := items[0].EventID
	q.Close()
	received := make(chan contract.Window, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b transport.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Error(err)
			return
		}
		if len(b.Windows) != 1 {
			t.Error("unexpected batch size")
			return
		}
		var window contract.Window
		json.Unmarshal(b.Windows[0], &window)
		received <- window
		json.NewEncoder(w).Encode(transport.Ack{BatchID: b.BatchID, AcceptedEventIDs: []string{window.EventID}})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = queueCommand(ctx, "send", []string{"--spool", queueDir, "--endpoint", server.URL, "--once"}); err != nil {
		t.Fatal(err)
	}
	got := <-received
	if got.EventID != expectedID || got.CaptureEpoch != "delivery-test" || *got.Features["out_packets"] != 2 {
		t.Fatal(got)
	}
	q, err = spool.Open(queueDir, spool.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q.Stats().Pending != 0 {
		t.Fatal(q.Stats())
	}
}
func TestEnqueueKeepsCommittedPrefixOnInvalidLine(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var window contract.Window
	json.Unmarshal(data, &window)
	data, _ = json.Marshal(window)
	input := filepath.Join(dir, "input.jsonl")
	os.WriteFile(input, append(append(data, '\n'), []byte("invalid\n")...), 0600)
	queueDir := filepath.Join(dir, "queue")
	if err = queueCommand(context.Background(), "enqueue", []string{"--spool", queueDir, "--input", input}); err == nil {
		t.Fatal("invalid input accepted")
	}
	q, err := spool.Open(queueDir, spool.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q.Stats().Pending != 1 {
		t.Fatal(q.Stats())
	}
}
func TestBackgroundDeliveryFailureStopsCaptureContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer server.Close()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	options := deliveryFlags(fs)
	fs.Parse([]string{"--spool", t.TempDir(), "--endpoint", server.URL})
	ctx, d, err := startDelivery(context.Background(), options, newEventLog())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile("../../contracts/examples/window.valid.json")
	var window contract.Window
	json.Unmarshal(data, &window)
	if err = d.append(window); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("fatal delivery error did not stop capture")
	}
	if d.queue.Stats().Pending != 1 {
		t.Fatal("fatal error deleted pending window")
	}
	if err = d.close(); err == nil {
		t.Fatal("fatal error hidden on shutdown")
	}
}
func TestLiveOverflowIsVisibleAndNonBlocking(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	options := deliveryFlags(fs)
	fs.Parse([]string{"--spool", t.TempDir(), "--spool-bytes", "2048", "--segment-bytes", "2048"})
	_, d, err := startDelivery(context.Background(), options, newEventLog())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	data, _ := os.ReadFile("../../contracts/examples/window.valid.json")
	var window contract.Window
	json.Unmarshal(data, &window)
	for i := 0; i < 5; i++ {
		if err = d.append(window); err != nil {
			t.Fatal(err)
		}
	}
	if d.queue.Stats().Loss.Count == 0 || !d.queue.Stats().Degraded {
		t.Fatal("overflow not reported")
	}
}
func TestDeliveryRejectsInvalidModes(t *testing.T) {
	if err := live(context.Background(), []string{"--interface", "eth0", "--filter", "tcp", "--output", "unused", "--spool", t.TempDir()}); err == nil {
		t.Fatal("packet metadata was allowed into window spool")
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	options := deliveryFlags(fs)
	fs.Parse([]string{"--endpoint", "http://127.0.0.1/v1/windows"})
	if _, _, err := startDelivery(context.Background(), options, newEventLog()); err == nil {
		t.Fatal("endpoint without queue accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q, err := spool.Open(t.TempDir(), spool.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	c := transport.DefaultConfig()
	c.Endpoint = "http://127.0.0.1/v1/windows"
	sender, err := transport.New(q, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = sender.Run(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
