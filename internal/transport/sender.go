// Package transport delivers durable windows with explicit, atomic acknowledgments.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/spool"
)

type Batch struct {
	SchemaVersion int               `json:"schema_version"`
	BatchID       string            `json:"batch_id"`
	Windows       []json.RawMessage `json:"windows"`
	QueueLoss     spool.Loss        `json:"queue_loss"`
}
type Ack struct {
	BatchID          string   `json:"batch_id"`
	AcceptedEventIDs []string `json:"accepted_event_ids"`
}
type Rejection struct {
	BatchID    string `json:"batch_id"`
	Code       string `json:"code"`
	ErrorIndex *int   `json:"error_index"`
}
type Config struct {
	Endpoint, Token                        string
	TrustedCAPEM                           string
	AllowInsecureHTTP                      bool
	Timeout, Interval, Backoff, MaxBackoff time.Duration
	BatchSize                              int
}

func DefaultConfig() Config {
	return Config{Timeout: 10 * time.Second, Interval: 250 * time.Millisecond, Backoff: 250 * time.Millisecond, MaxBackoff: 30 * time.Second, BatchSize: 100}
}

type Sender struct {
	queue  *spool.Queue
	config Config
	client *http.Client
	grpc   *GRPCClient
	Log    func(string, any)
}

func New(q *spool.Queue, c Config) (*Sender, error) {
	if c.Timeout <= 0 || c.Interval <= 0 || c.Backoff <= 0 || c.MaxBackoff < c.Backoff || c.MaxBackoff > time.Hour || c.BatchSize < 1 || c.BatchSize > 100 {
		return nil, fmt.Errorf("invalid sender limits")
	}
	if strings.HasPrefix(c.Endpoint, "grpcs://") {
		if c.Token == "" || strings.ContainsAny(c.Token, " \r\n\t") {
			return nil, fmt.Errorf("gRPC requires the enrolled sensor credential")
		}
		client, err := NewGRPCClient(c.Endpoint, c.TrustedCAPEM)
		if err != nil {
			return nil, err
		}
		return &Sender{queue: q, config: c, grpc: client}, nil
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("endpoint must be an HTTP(S) URL without credentials, query or fragment")
	}
	local := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		local = ip.IsLoopback()
	}
	if u.Scheme == "http" && !local && !c.AllowInsecureHTTP {
		return nil, fmt.Errorf("remote delivery requires HTTPS (isolated labs may opt into HTTP)")
	}
	if !local && !c.AllowInsecureHTTP && c.Token == "" {
		return nil, fmt.Errorf("remote delivery requires a sensor token")
	}
	if strings.ContainsAny(c.Token, "\r\n") {
		return nil, fmt.Errorf("invalid token")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxResponseHeaderBytes = 64 << 10
	if c.TrustedCAPEM != "" {
		if u.Scheme != "https" {
			return nil, fmt.Errorf("a trusted CA requires an HTTPS endpoint")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system trust store: %w", err)
		}
		if !roots.AppendCertsFromPEM([]byte(c.TrustedCAPEM)) {
			return nil, fmt.Errorf("NETWATCH_SENSOR_CA_PEM must contain a PEM certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &Sender{queue: q, config: c, client: &http.Client{Timeout: c.Timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func NewBatch(items []spool.Item, loss spool.Loss) (Batch, error) {
	b := Batch{SchemaVersion: 1, Windows: make([]json.RawMessage, 0, len(items)), QueueLoss: loss}
	seen := map[string]bool{}
	for _, item := range items {
		if seen[item.EventID] {
			return b, fmt.Errorf("duplicate event ID in batch")
		}
		seen[item.EventID] = true
		b.Windows = append(b.Windows, item.Window)
	}
	data, err := json.Marshal(b)
	if err != nil {
		return b, err
	}
	hash := sha256.Sum256(data)
	b.BatchID = hex.EncodeToString(hash[:])
	data, err = json.Marshal(b)
	if err != nil {
		return b, err
	}
	return b, contract.Validate("batch", data)
}
func (s *Sender) log(event string, data any) {
	if s.Log != nil {
		s.Log(event, data)
	}
}
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Run keeps one immutable batch through retries. Cancellation leaves unacked data on disk.
// once drains the current queue and exits; it still retries unavailable API responses.
func (s *Sender) Run(ctx context.Context, once bool) error {
	if s.grpc != nil {
		defer s.grpc.Close()
	} else {
		defer s.client.CloseIdleConnections()
	}
	var lastContact time.Time
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		items, err := s.queue.Peek(s.config.BatchSize, 1<<20)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			if s.grpc != nil && (once || time.Since(lastContact) >= 2*time.Second) {
				heartbeatContext, cancel := context.WithTimeout(ctx, s.config.Timeout)
				loss := s.queue.Stats().Loss
				_, contactErr := s.grpc.Contact(heartbeatContext, s.config.Token, &loss)
				cancel()
				lastContact = time.Now()
				if contactErr != nil {
					if !retryGRPC(contactErr) {
						return fmt.Errorf("sensor contact rejected; queue retained")
					}
					s.log("delivery_retry", "sensor contact temporarily unavailable")
					if err = sleep(ctx, 2*time.Second); err != nil {
						return err
					}
					continue
				}
			}
			if once {
				return nil
			}
			if err = sleep(ctx, s.config.Interval); err != nil {
				return err
			}
			continue
		}
		// Repeated imports can contain the same event ID. Split at the first duplicate;
		// each remains a valid retry and the receiver deduplicates across batches.
		ids := map[string]bool{}
		for i, item := range items {
			if ids[item.EventID] {
				items = items[:i]
				break
			}
			ids[item.EventID] = true
		}
		batch, err := NewBatch(items, s.queue.Stats().Loss)
		if err != nil {
			return err
		}
		var body []byte
		if s.grpc == nil {
			body, err = json.Marshal(batch)
			if err != nil {
				return err
			}
		}
		delay := s.config.Backoff
		for {
			rejected, retry, err := s.post(ctx, batch, items, body)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if rejected >= 0 {
				if err = s.queue.Reject(items[rejected], "API rejected invalid_window"); err != nil {
					return err
				}
				s.log("delivery_quarantined", map[string]any{"event_id": items[rejected].EventID, "stats": s.queue.Stats()})
				break
			}
			if err == nil {
				if err = s.queue.Ack(items); err != nil {
					return err
				}
				s.log("delivery_ack", map[string]any{"batch_id": batch.BatchID, "windows": len(items), "stats": s.queue.Stats()})
				break
			}
			if !retry {
				return err
			}
			wait := time.Duration(rand.Int64N(int64(delay)))
			s.log("delivery_retry", map[string]any{"batch_id": batch.BatchID, "delay_ms": wait.Milliseconds(), "reason": err.Error()})
			if err = sleep(ctx, wait); err != nil {
				return err
			}
			if delay < s.config.MaxBackoff/2 {
				delay *= 2
			} else {
				delay = s.config.MaxBackoff
			}
		}
	}
}
func (s *Sender) post(ctx context.Context, b Batch, items []spool.Item, body []byte) (int, bool, error) {
	if s.grpc != nil {
		return s.postGRPC(ctx, b, items)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return -1, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", b.BatchID)
	if s.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return -1, true, fmt.Errorf("HTTP request failed or timed out")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil {
		return -1, true, fmt.Errorf("incomplete HTTP response")
	}
	if len(data) > 64<<10 {
		return -1, true, fmt.Errorf("HTTP response exceeds limit")
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		var r Rejection
		if err = contract.Validate("rejection", data); err != nil {
			return -1, false, fmt.Errorf("invalid rejection schema; batch retained")
		}
		if err = decode(data, &r); err != nil || r.BatchID != b.BatchID || r.Code != "invalid_window" || r.ErrorIndex == nil || *r.ErrorIndex < 0 || *r.ErrorIndex >= len(items) {
			return -1, false, fmt.Errorf("invalid rejection response; batch retained")
		}
		return *r.ErrorIndex, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500
		return -1, retry, fmt.Errorf("HTTP status %d; batch retained", resp.StatusCode)
	}
	var ack Ack
	if err = contract.Validate("ack", data); err != nil {
		return -1, true, fmt.Errorf("invalid acknowledgment schema; batch retained")
	}
	if err = decode(data, &ack); err != nil || ack.BatchID != b.BatchID || len(ack.AcceptedEventIDs) != len(items) {
		return -1, true, fmt.Errorf("invalid acknowledgment; batch retained")
	}
	return verifyAck(items, ack.AcceptedEventIDs)
}

func (s *Sender) postGRPC(ctx context.Context, b Batch, items []spool.Item) (int, bool, error) {
	call, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	ack, err := s.grpc.submit(call, s.config.Token, b)
	if err != nil {
		return -1, retryGRPC(err), fmt.Errorf("gRPC delivery status %s; batch retained", status.Code(err))
	}
	if ack.GetSchemaVersion() != SensorProtocolVersion || ack.GetBatchId() != b.BatchID {
		return -1, true, fmt.Errorf("invalid gRPC acknowledgment; batch retained")
	}
	if ack.InvalidWindowIndex != nil {
		index := int(ack.GetInvalidWindowIndex())
		if index >= len(items) || len(ack.GetAcceptedEventIds()) != 0 {
			return -1, false, fmt.Errorf("invalid gRPC rejection; batch retained")
		}
		return index, false, nil
	}
	return verifyAck(items, ack.GetAcceptedEventIds())
}

func retryGRPC(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	case codes.FailedPrecondition:
		return status.Convert(err).Message() == "sensor paused"
	default:
		return false
	}
}

func verifyAck(items []spool.Item, ids []string) (int, bool, error) {
	if len(ids) != len(items) {
		return -1, true, fmt.Errorf("incomplete acknowledgment")
	}
	expected := map[string]bool{}
	for _, item := range items {
		expected[item.EventID] = true
	}
	for _, id := range ids {
		if !expected[id] {
			return -1, true, fmt.Errorf("incorrect acknowledged event IDs")
		}
		delete(expected, id)
	}
	if len(expected) != 0 {
		return -1, true, fmt.Errorf("incomplete acknowledgment")
	}
	return -1, false, nil
}
func decode(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var rest any
	if !errors.Is(d.Decode(&rest), io.EOF) {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
