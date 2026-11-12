package main

import (
	"context"
	"testing"

	"netwatch.local/netwatch/internal/capture"
	"netwatch.local/netwatch/internal/window"
)

func TestLiveCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, initial, want string
		start, end          int64
		stats               capture.Stats
		failed              bool
	}{
		{name: "elapsed", initial: "partial", want: "complete", start: 5, end: 20},
		{name: "startup", initial: "partial", want: "partial", start: 11, end: 20},
		{name: "shutdown", initial: "partial", want: "partial", start: 5, end: 5},
		{name: "decoder gap", initial: "gap", want: "gap", start: 5, end: 20},
		{name: "kernel drop", initial: "partial", want: "gap", start: 5, end: 20, stats: capture.Stats{Dropped: 1}},
		{name: "interface drop", initial: "partial", want: "gap", start: 5, end: 20, stats: capture.Stats{InterfaceDropped: 1}},
		{name: "capture error", initial: "partial", want: "gap", start: 5, end: 20, failed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := window.Result{Start: 10, End: 15, Coverage: tc.initial}
			if got := liveCoverage(r, tc.start, tc.end, tc.stats, tc.failed); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestLiveRejectsInvalidArgumentsBeforeOpeningCapture(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--interface", "eth0", "--output", "unused"},
		{"--interface", "eth0", "--filter", "tcp", "--output", "unused", "--duration", "-1s"},
		{"--interface", "eth0", "--filter", "tcp", "--output", "unused", "--coverage-start", "1"},
		{"--interface", "eth0", "--filter", "tcp", "--output", "unused", "--service", "unset:8080"},
	} {
		if err := live(context.Background(), args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
