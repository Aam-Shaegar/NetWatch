package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"netwatch.local/netwatch/internal/spool"
	"netwatch.local/netwatch/internal/transport"
)

type eventLog struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func newEventLog() *eventLog           { return &eventLog{encoder: json.NewEncoder(os.Stderr)} }
func (l *eventLog) Encode(v any) error { l.mu.Lock(); defer l.mu.Unlock(); return l.encoder.Encode(v) }

type deliveryOptions struct {
	dir, endpoint                           *string
	maxBytes, segmentBytes, quarantineBytes *int64
	timeout                                 *time.Duration
	insecure                                *bool
}

func deliveryFlags(fs *flag.FlagSet) deliveryOptions {
	defaults := spool.DefaultConfig()
	return deliveryOptions{
		dir:             fs.String("spool", "", "durable queue directory; required for delivery"),
		endpoint:        fs.String("endpoint", "", "HTTP endpoint, normally /v1/windows; token from NETWATCH_SENSOR_TOKEN"),
		maxBytes:        fs.Int64("spool-bytes", defaults.MaxBytes, "maximum segment bytes; drop newest on overflow"),
		segmentBytes:    fs.Int64("segment-bytes", defaults.SegmentBytes, "maximum bytes per segment"),
		quarantineBytes: fs.Int64("quarantine-bytes", defaults.QuarantineBytes, "maximum quarantine bytes"),
		timeout:         fs.Duration("http-timeout", 10*time.Second, "per-request HTTP deadline"),
		insecure:        fs.Bool("allow-insecure-http", false, "allow remote HTTP only for an isolated laboratory"),
	}
}
func (o deliveryOptions) open() (*spool.Queue, error) {
	return spool.Open(*o.dir, spool.Config{MaxBytes: *o.maxBytes, SegmentBytes: *o.segmentBytes, QuarantineBytes: *o.quarantineBytes})
}
func (o deliveryOptions) sender(q *spool.Queue, log *eventLog) (*transport.Sender, error) {
	config := transport.DefaultConfig()
	config.Endpoint = *o.endpoint
	config.Token = os.Getenv("NETWATCH_SENSOR_TOKEN")
	config.Timeout = *o.timeout
	config.AllowInsecureHTTP = *o.insecure
	sender, err := transport.New(q, config)
	if err != nil {
		return nil, err
	}
	sender.Log = func(event string, data any) { _ = log.Encode(map[string]any{"event": event, "data": data}) }
	return sender, nil
}

type delivery struct {
	queue  *spool.Queue
	cancel context.CancelFunc
	done   chan error
	log    *eventLog
}

func startDelivery(ctx context.Context, o deliveryOptions, log *eventLog) (context.Context, *delivery, error) {
	if *o.dir == "" {
		if *o.endpoint != "" {
			return ctx, nil, fmt.Errorf("--endpoint requires --spool")
		}
		return ctx, nil, nil
	}
	q, err := o.open()
	if err != nil {
		return ctx, nil, err
	}
	child, cancel := context.WithCancel(ctx)
	d := &delivery{queue: q, cancel: cancel, log: log}
	if *o.endpoint != "" {
		sender, err := o.sender(q, log)
		if err != nil {
			cancel()
			q.Close()
			return ctx, nil, err
		}
		d.done = make(chan error, 1)
		go func() {
			err := sender.Run(child, false)
			if errors.Is(err, context.Canceled) {
				err = nil
			}
			if err != nil {
				_ = log.Encode(map[string]any{"event": "delivery_failed", "error": err.Error()})
				cancel()
			}
			d.done <- err
		}()
	}
	_ = log.Encode(map[string]any{"event": "spool_opened", "stats": q.Stats()})
	return child, d, nil
}
func (d *delivery) append(v any) error {
	if d == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	err = d.queue.Append(data)
	if errors.Is(err, spool.ErrFull) {
		return d.log.Encode(map[string]any{"event": "spool_overflow", "stats": d.queue.Stats()})
	}
	return err
}
func (d *delivery) close() error {
	if d == nil {
		return nil
	}
	d.cancel()
	var err error
	if d.done != nil {
		err = <-d.done
	}
	logErr := d.log.Encode(map[string]any{"event": "spool_closed", "stats": d.queue.Stats()})
	return errors.Join(err, logErr, d.queue.Close())
}

// queueCommand imports replay output, drains a queue, or inspects persistent health.
func queueCommand(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	o := deliveryFlags(fs)
	input := fs.String("input", "", "window JSONL file (enqueue only)")
	once := fs.Bool("once", false, "exit when the queue is drained")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *o.dir == "" {
		return fmt.Errorf("%s requires --spool", command)
	}
	if command == "send" && (*o.endpoint == "" || *input != "") {
		return fmt.Errorf("send requires --endpoint and no --input")
	}
	if command != "send" && (*o.endpoint != "" || *once) {
		return fmt.Errorf("endpoint and once apply only to send")
	}
	if command == "enqueue" && *input == "" {
		return fmt.Errorf("enqueue requires --input")
	}
	if command == "spool-status" && *input != "" {
		return fmt.Errorf("spool-status does not accept input")
	}
	if command != "enqueue" {
		info, err := os.Stat(*o.dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("spool is not a directory")
		}
	}
	q, err := o.open()
	if err != nil {
		return err
	}
	defer q.Close()
	log := newEventLog()
	if command == "spool-status" {
		return json.NewEncoder(os.Stdout).Encode(q.Stats())
	}
	if command == "send" {
		sender, err := o.sender(q, log)
		if err != nil {
			return err
		}
		_ = log.Encode(map[string]any{"event": "spool_opened", "stats": q.Stats()})
		err = sender.Run(ctx, *once)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	file, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), spool.MaxRecord+1)
	line := 0
	dropped := false
	for scanner.Scan() {
		line++
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err = q.Append(scanner.Bytes()); errors.Is(err, spool.ErrFull) {
			dropped = true
			_ = log.Encode(map[string]any{"event": "spool_overflow", "line": line, "stats": q.Stats()})
			continue
		} else if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	if err = log.Encode(map[string]any{"event": "enqueue_completed", "lines": line, "stats": q.Stats()}); err != nil {
		return err
	}
	if dropped {
		return spool.ErrFull
	}
	return nil
}
