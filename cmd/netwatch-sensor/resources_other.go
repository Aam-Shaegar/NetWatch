//go:build !linux

package main

import (
	"time"

	wire "netwatch.local/netwatch/contracts/sensorv1"
)

type resourceSampler struct{}

func (*resourceSampler) sample(time.Time) *wire.ProcessResources { return nil }
