package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netwatch.local/netwatch/internal/spool"
)

func queued(t *testing.T, ids ...string) *spool.Queue {
	t.Helper()
	q, err := spool.Open(t.TempDir(), spool.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	fixture, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		var w map[string]any
		json.Unmarshal(fixture, &w)
		w["event_id"] = id
		data, _ := json.Marshal(w)
		if err = q.Append(data); err != nil {
			t.Fatal(err)
		}
	}
	return q
}
func sender(t *testing.T, q *spool.Queue, endpoint string) *Sender {
	t.Helper()
	c := DefaultConfig()
	c.Endpoint = endpoint
	c.Backoff = 5 * time.Millisecond
	c.MaxBackoff = 20 * time.Millisecond
	c.Timeout = 100 * time.Millisecond
	s, err := New(q, c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func acknowledge(w http.ResponseWriter, b Batch) {
	ids := []string{}
	for _, data := range b.Windows {
		var item struct {
			EventID string `json:"event_id"`
		}
		json.Unmarshal(data, &item)
		ids = append(ids, item.EventID)
	}
	json.NewEncoder(w).Encode(Ack{b.BatchID, ids})
}
func deadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCommitThenLostAckRetriesIdenticalBatch(t *testing.T) {
	q := queued(t, "a", "b")
	var mu sync.Mutex
	attempts := 0
	stored := map[string]bool{}
	var first string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var b Batch
		json.Unmarshal(body, &b)
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if r.Header.Get("Idempotency-Key") != b.BatchID || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing request identity/auth")
		}
		if attempts == 1 {
			first = string(body)
		} else if first != string(body) {
			t.Error("retry changed batch")
		}
		for _, data := range b.Windows {
			var item struct {
				EventID string `json:"event_id"`
			}
			json.Unmarshal(data, &item)
			stored[item.EventID] = true
		}
		if attempts == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		if q.Stats().Pending != 2 {
			t.Error("queue removed before ACK")
		}
		acknowledge(w, b)
	}))
	defer server.Close()
	s := sender(t, q, server.URL)
	s.config.Token = "test-token"
	if err := s.Run(deadline(t), true); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 2 || len(stored) != 2 || q.Stats().Pending != 0 {
		t.Fatal(attempts, stored, q.Stats())
	}
}
func TestAPIUnavailableThenRestored(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	q := queued(t, "offline")
	s := sender(t, q, "http://"+address+"/v1/windows")
	retried := make(chan struct{}, 1)
	s.Log = func(event string, _ any) {
		if event == "delivery_retry" {
			select {
			case retried <- struct{}{}:
			default:
			}
		}
	}
	ctx := deadline(t)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, true) }()
	select {
	case <-retried:
	case <-ctx.Done():
		t.Fatal("no retry during outage")
	}
	if q.Stats().Pending != 1 {
		t.Fatal("outage lost queued window")
	}
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		json.NewDecoder(r.Body).Decode(&b)
		acknowledge(w, b)
	})}
	go server.Serve(listener)
	defer server.Close()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("delivery did not recover")
	}
	if q.Stats().Pending != 0 {
		t.Fatal(q.Stats())
	}
}
func TestBadAcknowledgmentsNeverDelete(t *testing.T) {
	for _, response := range []string{`{}`, `{"batch_id":"wrong","accepted_event_ids":["a"]}`, `not json`, "oversized", "wrong IDs"} {
		t.Run(response, func(t *testing.T) {
			q := queued(t, "a")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var b Batch
				json.NewDecoder(r.Body).Decode(&b)
				switch response {
				case "oversized":
					w.Write(make([]byte, 65537))
				case "wrong IDs":
					json.NewEncoder(w).Encode(Ack{b.BatchID, []string{"other"}})
				default:
					io.WriteString(w, response)
				}
			}))
			defer server.Close()
			s := sender(t, q, server.URL)
			ctx, cancel := context.WithCancel(deadline(t))
			s.Log = func(event string, _ any) {
				if event == "delivery_retry" {
					cancel()
				}
			}
			if err := s.Run(ctx, true); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if q.Stats().Pending != 1 {
				t.Fatal("bad ACK deleted data")
			}
		})
	}
}
func TestStatusPolicyAndQuarantine(t *testing.T) {
	t.Run("422", func(t *testing.T) {
		q := queued(t, "good-a", "bad", "good-b")
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var b Batch
			json.NewDecoder(r.Body).Decode(&b)
			if calls.Add(1) == 1 {
				index := 1
				w.WriteHeader(422)
				json.NewEncoder(w).Encode(Rejection{b.BatchID, "invalid_window", &index})
				return
			}
			if len(b.Windows) != 2 {
				t.Error("bad record not isolated")
			}
			acknowledge(w, b)
		}))
		defer server.Close()
		if err := sender(t, q, server.URL).Run(deadline(t), true); err != nil {
			t.Fatal(err)
		}
		if q.Stats().Pending != 0 || q.Stats().Quarantined != 1 {
			t.Fatal(q.Stats())
		}
	})
	for _, status := range []int{301, 400, 401, 403, 404, 413, 422} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			q := queued(t, "a")
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(status)
			}))
			defer server.Close()
			if err := sender(t, q, server.URL).Run(deadline(t), true); err == nil {
				t.Fatal("permanent error ignored")
			}
			if calls.Load() != 1 || q.Stats().Pending != 1 {
				t.Fatal(calls.Load(), q.Stats())
			}
		})
	}
	for _, status := range []int{408, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			q := queued(t, "a")
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(status)
					return
				}
				var b Batch
				json.NewDecoder(r.Body).Decode(&b)
				acknowledge(w, b)
			}))
			defer server.Close()
			if err := sender(t, q, server.URL).Run(deadline(t), true); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 || q.Stats().Pending != 0 {
				t.Fatal(calls.Load(), q.Stats())
			}
		})
	}
}
func TestTimeoutAndCancellation(t *testing.T) {
	q := queued(t, "a")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	s := sender(t, q, server.URL)
	s.config.Timeout = 20 * time.Millisecond
	s.client.Timeout = s.config.Timeout
	ctx, cancel := context.WithCancel(deadline(t))
	s.Log = func(event string, _ any) {
		if event == "delivery_retry" {
			cancel()
		}
	}
	start := time.Now()
	if err := s.Run(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second || q.Stats().Pending != 1 {
		t.Fatal("deadline/cancellation not respected")
	}
}
func TestDuplicateImportsAndBatchBounds(t *testing.T) {
	q := queued(t, "a", "a", "b", "c")
	sizes := make(chan int, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		json.NewDecoder(r.Body).Decode(&b)
		sizes <- len(b.Windows)
		acknowledge(w, b)
	}))
	defer server.Close()
	s := sender(t, q, server.URL)
	s.config.BatchSize = 2
	if err := s.Run(deadline(t), true); err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 3 {
		t.Fatal("unexpected batch count", len(sizes))
	}
	for _, want := range []int{1, 2, 1} {
		if got := <-sizes; got != want {
			t.Fatal(got, want)
		}
	}
}
func TestEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"file:///tmp/data", "http://user:secret@localhost/v1/windows", "http://example.test/v1/windows", "https://example.test/v1/windows", "http://localhost/?token=secret"} {
		c := DefaultConfig()
		c.Endpoint = endpoint
		if _, err := New(nil, c); err == nil {
			t.Fatal("unsafe endpoint accepted", endpoint)
		}
	}
}
