package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"netwatch.local/netwatch/internal/capture"
	"netwatch.local/netwatch/internal/window"
)

func interfaces() error {
	devices, err := net.Interfaces()
	if err != nil {
		return err
	}
	type device struct {
		Name       string
		Index, MTU int
		Flags      string
		Addresses  []string
	}
	out := make([]device, 0, len(devices))
	for _, d := range devices {
		addresses, err := d.Addrs()
		if err != nil {
			return err
		}
		row := device{Name: d.Name, Index: d.Index, MTU: d.MTU, Flags: d.Flags.String()}
		for _, a := range addresses {
			row.Addresses = append(row.Addresses, a.String())
		}
		out = append(out, row)
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func live(ctx context.Context, args []string, logs *eventLog) (returnErr error) {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	iface := fs.String("interface", "", "named capture interface")
	filter := fs.String("filter", "", "required BPF filter")
	output := fs.String("output", "", "new JSONL output; optional with a configured spool and endpoint")
	record := fs.String("record-pcap", "", "optional laboratory raw recording (includes payload)")
	sensor := fs.String("sensor", "live", "sensor ID")
	bufferMiB := fs.Int("capture-buffer-mib", 16, "libpcap capture buffer in MiB (1–64)")
	duration := fs.Duration("duration", 0, "optional capture duration; zero waits for a signal")
	options := windowFlags(fs)
	deliveryOptions := deliveryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *iface == "" || *filter == "" || *duration < 0 {
		return fmt.Errorf("live requires --interface and --filter")
	}
	if *bufferMiB < 1 || *bufferMiB > 64 {
		return fmt.Errorf("--capture-buffer-mib must be between 1 and 64")
	}
	if *output == "" && (*deliveryOptions.dir == "" || *deliveryOptions.endpoint == "") {
		return fmt.Errorf("live requires --output or a configured --spool and --endpoint")
	}
	if *options.start != "" || *options.end != "" {
		return fmt.Errorf("live measures its own coverage bounds")
	}
	if *options.epoch == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		*options.epoch = hex.EncodeToString(id[:])
	}
	engine, err := options.engine()
	if err != nil {
		return err
	}
	if *deliveryOptions.dir != "" && engine == nil {
		return fmt.Errorf("spooling requires --host or --service windows")
	}
	ctx, delivery, err := startDelivery(ctx, deliveryOptions, logs)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, delivery.close()) }()
	var file *os.File
	var encoder *json.Encoder
	if *output != "" {
		file, err = os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		encoder = json.NewEncoder(file)
	}
	var raw *os.File
	if *record != "" {
		raw, err = os.OpenFile(*record, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer raw.Close()
	}
	// An untyped nil is required here: a typed nil *os.File is a non-nil io.Writer.
	var source *capture.LiveSource
	if raw == nil {
		source, err = capture.OpenLive(*iface, *filter, *sensor, *bufferMiB<<20, nil)
	} else {
		source, err = capture.OpenLive(*iface, *filter, *sensor, *bufferMiB<<20, raw)
	}
	if err != nil {
		return err
	}
	defer source.Close()
	started := time.Now().UnixNano()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	if err = logs.Encode(map[string]any{"event": "live_started", "start_ns": fmt.Sprint(started), "epoch": *options.epoch, "interface": *iface, "filter": *filter, "capture_buffer_mib": *bufferMiB}); err != nil {
		return err
	}
	counts := map[string]uint64{}
	var total uint64
	var stats capture.Stats
	type lossInterval struct {
		start, end int64
		delta      capture.Stats
	}
	var losses []lossInterval
	lastPoll := started
	coverage := newCoverage(started)
	poll := func() error {
		previous := stats
		var err error
		stats, err = source.Stats()
		if err != nil {
			return err
		}
		if stats.Received < previous.Received || stats.Dropped < previous.Dropped || stats.InterfaceDropped < previous.InterfaceDropped {
			return fmt.Errorf("capture counters wrapped")
		}
		now := time.Now().UnixNano()
		if engine != nil && (stats.Dropped > previous.Dropped || stats.InterfaceDropped > previous.InterfaceDropped) {
			engine.InvalidateConnectionAges(now)
			losses = append(losses, lossInterval{lastPoll, now, capture.Stats{Dropped: stats.Dropped - previous.Dropped, InterfaceDropped: stats.InterfaceDropped - previous.InterfaceDropped}})
		}
		lastPoll = now
		return logs.Encode(map[string]any{"event": "capture_stats", "stats": stats})
	}
	write := func(results []window.Result, end int64, failed bool, through int64) error {
		emit := func(r window.Result) error {
			var delta capture.Stats
			for len(losses) > 0 && losses[0].end <= r.Start {
				losses = losses[1:]
			}
			for _, loss := range losses {
				if loss.start < r.End && loss.end > r.Start {
					delta.Dropped += loss.delta.Dropped
					delta.InterfaceDropped += loss.delta.InterfaceDropped
				}
			}
			r.Coverage = liveCoverage(r, started, end, delta, failed)
			w, err := engine.Export(r, *sensor, *options.epoch)
			if err != nil {
				return err
			}
			dropped := delta.Dropped
			w.Quality.CaptureDropped = &dropped
			if err = delivery.append(w); err != nil {
				return err
			}
			if encoder != nil {
				return encoder.Encode(w)
			}
			return nil
		}
		if err := coverage.write(results, emit); err != nil {
			return err
		}
		return coverage.through(through, emit)
	}
	nextPoll := time.Now()
	var runErr error
	for ctx.Err() == nil {
		if !time.Now().Before(nextPoll) {
			if runErr = poll(); runErr != nil {
				break
			}
			nextPoll = time.Now().Add(time.Second)
		}
		p, err := source.Next(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			break
		}
		if errors.Is(err, capture.ErrTimeout) {
			if engine != nil {
				now := time.Now().UnixNano()
				results, e := engine.Advance(now)
				if e != nil {
					runErr = e
					break
				}
				if runErr = poll(); runErr == nil {
					runErr = write(results, now, false, now-int64(*options.lateness))
				}
				if runErr != nil {
					break
				}
			}
			continue
		}
		if err != nil {
			runErr = err
			break
		}
		counts[p.Status]++
		total++
		if engine == nil {
			runErr = encoder.Encode(p)
		} else {
			before := engine.LatePackets
			results, e := engine.Push(p)
			if e == nil && engine.LatePackets > before {
				e = logs.Encode(map[string]any{"event": "late_packet", "timestamp_ns": p.Timestamp, "epoch": *options.epoch})
			}
			runErr = e
			if e == nil && (len(results) > 0 || coverage.next <= engine.ClosedThrough()-windowNS) {
				if runErr = poll(); runErr == nil {
					runErr = write(results, time.Now().UnixNano(), false, engine.ClosedThrough())
				}
			}
		}
		if runErr != nil {
			break
		}
	}
	stopped := time.Now().UnixNano()
	if err = poll(); runErr == nil {
		runErr = err
	}
	if engine != nil {
		if err = write(engine.Finish(), stopped, runErr != nil, stopped); runErr == nil {
			runErr = err
		}
	}
	if file != nil {
		if err = file.Sync(); runErr == nil {
			runErr = err
		}
	}
	if raw != nil {
		if err = raw.Sync(); runErr == nil {
			runErr = err
		}
	}
	summary := map[string]any{"event": "live_stopped", "start_ns": fmt.Sprint(started), "end_ns": fmt.Sprint(stopped), "records": total, "status_counts": counts, "stats": stats}
	if engine != nil {
		summary["late_packets"] = engine.LatePackets
	}
	if runErr != nil {
		summary["error"] = runErr.Error()
	}
	if err = logs.Encode(summary); runErr == nil {
		runErr = err
	}
	return runErr
}

// liveCoverage never upgrades gaps caused by decoding, late data or state limits.
func liveCoverage(r window.Result, start, end int64, stats capture.Stats, failed bool) string {
	if failed || stats.Dropped > 0 || stats.InterfaceDropped > 0 {
		return "gap"
	}
	if r.Coverage == "partial" && r.Start >= start && r.End <= end {
		return "complete"
	}
	return r.Coverage
}
