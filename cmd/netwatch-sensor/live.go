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

func live(ctx context.Context, args []string) (returnErr error) {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	iface := fs.String("interface", "", "named capture interface")
	filter := fs.String("filter", "", "required BPF filter")
	output := fs.String("output", "", "new JSONL output")
	record := fs.String("record-pcap", "", "optional laboratory raw recording (includes payload)")
	sensor := fs.String("sensor", "live", "sensor ID")
	duration := fs.Duration("duration", 0, "optional capture duration; zero waits for a signal")
	options := windowFlags(fs)
	deliveryOptions := deliveryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *iface == "" || *filter == "" || *output == "" || *duration < 0 {
		return fmt.Errorf("live requires --interface, --filter and --output")
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
	logs := newEventLog()
	ctx, delivery, err := startDelivery(ctx, deliveryOptions, logs)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, delivery.close()) }()
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
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
		source, err = capture.OpenLive(*iface, *filter, *sensor, nil)
	} else {
		source, err = capture.OpenLive(*iface, *filter, *sensor, raw)
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
	if err = logs.Encode(map[string]any{"event": "live_started", "start_ns": fmt.Sprint(started), "epoch": *options.epoch, "interface": *iface, "filter": *filter}); err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	counts := map[string]uint64{}
	var total uint64
	var stats capture.Stats
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
		return logs.Encode(map[string]any{"event": "capture_stats", "stats": stats})
	}
	write := func(results []window.Result, end int64, failed bool) error {
		for _, r := range results {
			r.Coverage = liveCoverage(r, started, end, stats, failed)
			w, err := engine.Export(r, *sensor, *options.epoch)
			if err != nil {
				return err
			}
			dropped := stats.Dropped
			w.Quality.CaptureDropped = &dropped
			if err = delivery.append(w); err != nil {
				return err
			}
			if err = encoder.Encode(w); err != nil {
				return err
			}
		}
		return nil
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
				if len(results) > 0 {
					if runErr = poll(); runErr == nil {
						runErr = write(results, now, false)
					}
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
			results, e := engine.Push(p)
			runErr = e
			if e == nil && len(results) > 0 {
				if runErr = poll(); runErr == nil {
					runErr = write(results, time.Now().UnixNano(), false)
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
		if err = write(engine.Finish(), started, runErr != nil); runErr == nil {
			runErr = err
		}
	}
	if err = file.Sync(); runErr == nil {
		runErr = err
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
