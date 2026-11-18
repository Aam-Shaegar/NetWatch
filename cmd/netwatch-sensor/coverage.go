package main

import (
	"math"
	"netwatch.local/netwatch/internal/window"
)

const windowNS int64 = 5_000_000_000

// Only a verified observation interval permits zero-traffic windows.
// Stream missing intervals individually, even for a long recording.
type coverageCursor struct {
	next int64
}

func newCoverage(start int64) *coverageCursor {
	next := start - start%windowNS
	if next < start && next > math.MaxInt64-windowNS {
		return nil
	}
	if next < start {
		next += windowNS
	}
	return &coverageCursor{next: next}
}

func (c *coverageCursor) through(end int64, emit func(window.Result) error) error {
	for c != nil && c.next <= end-windowNS {
		r := window.Result{Start: c.next, End: c.next + windowNS, Coverage: "complete"}
		if err := emit(r); err != nil {
			return err
		}
		c.next = r.End
	}
	return nil
}

func (c *coverageCursor) write(results []window.Result, emit func(window.Result) error) error {
	for _, r := range results {
		if err := c.through(r.Start, emit); err != nil {
			return err
		}
		if err := emit(r); err != nil {
			return err
		}
		if c != nil && r.End > c.next {
			c.next = r.End
		}
	}
	return nil
}
