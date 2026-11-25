package main

import (
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	wire "netwatch.local/netwatch/contracts/sensorv1"
)

type resourceSampler struct {
	next     time.Time
	measured time.Time
	cpu      time.Duration
}

func (s *resourceSampler) sample(now time.Time) *wire.ProcessResources {
	if now.Before(s.next) {
		return nil
	}
	s.next = now.Add(time.Minute)

	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return nil
	}
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return nil
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	pageSize := int64(os.Getpagesize())
	if err != nil || pages <= 0 || pages > math.MaxInt64/pageSize {
		return nil
	}

	cpu := time.Duration(usage.Utime.Nano()) + time.Duration(usage.Stime.Nano())
	previous, previousCPU := s.measured, s.cpu
	s.measured, s.cpu = now, cpu
	if previous.IsZero() || cpu < previousCPU {
		return nil
	}
	return &wire.ProcessResources{
		CpuPct:   100 * float64(cpu-previousCPU) / float64(now.Sub(previous)),
		RssBytes: pages * pageSize,
	}
}
