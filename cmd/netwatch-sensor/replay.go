package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"netwatch.local/netwatch/internal/capture"
	"os"
	"path/filepath"
)

// Publish the complete JSONL atomically, without overwriting an existing file.
func replay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	in := fs.String("input", "", "input PCAP/PCAPNG")
	out := fs.String("output", "", "new metadata JSONL path")
	id := fs.String("sensor", "offline", "observation source")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: netwatch-sensor replay --input capture.pcap --output new.jsonl")
	}
	src, err := capture.Open(ctx, *in, *id)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(*out), ".replay-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	enc := json.NewEncoder(tmp)
	counts := map[string]int{}
	total := 0
	for {
		m, e := src.Next(ctx)
		if e == io.EOF {
			break
		}
		if e != nil {
			return fmt.Errorf("record %d: %w", total+1, e)
		}
		if e = enc.Encode(m); e != nil {
			return e
		}
		counts[m.Status]++
		total++
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Link(tmp.Name(), *out); err != nil {
		return err
	}
	return json.NewEncoder(os.Stderr).Encode(map[string]any{"records": total, "status_counts": counts})
}
