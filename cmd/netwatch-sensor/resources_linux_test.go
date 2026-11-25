package main

import (
	"testing"
	"time"
)

func TestResourceSamplerCadence(t *testing.T) {
	var sampler resourceSampler
	start := time.Now()
	if sample := sampler.sample(start); sample != nil {
		t.Fatal("reported CPU before measuring an interval")
	}
	if sample := sampler.sample(start.Add(59 * time.Second)); sample != nil {
		t.Fatal("reported before a minute elapsed")
	}
	sample := sampler.sample(start.Add(time.Minute))
	if sample == nil || sample.RssBytes <= 0 || sample.CpuPct < 0 {
		t.Fatalf("invalid Linux process sample: %v", sample)
	}
	if sample := sampler.sample(start.Add(61 * time.Second)); sample != nil {
		t.Fatal("reported the same interval twice")
	}
}
