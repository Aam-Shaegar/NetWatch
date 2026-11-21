package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/telemetry"
)

func main() {
	log := telemetry.NewLogger("sensor")
	events := &eventLog{logger: log}
	if len(os.Args) > 1 && os.Args[1] == "interfaces" {
		if err := interfaces(); err != nil {
			log.Error("sensor_failed", "error", err.Error())
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "enroll", "pause", "resume", "remove":
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := identityCommand(ctx, os.Args[1], os.Args[2:]); err != nil {
				log.Error("sensor_failed", "error", err.Error())
				os.Exit(1)
			}
			return
		}
	}
	if len(os.Args) > 1 && (os.Args[1] == "replay" || os.Args[1] == "live" || os.Args[1] == "enqueue" || os.Args[1] == "send" || os.Args[1] == "spool-status") {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		run := replay
		if os.Args[1] == "live" {
			run = func(ctx context.Context, args []string) error { return live(ctx, args, events) }
		}
		if os.Args[1] == "enqueue" || os.Args[1] == "send" || os.Args[1] == "spool-status" {
			run = func(ctx context.Context, args []string) error { return queueCommand(ctx, os.Args[1], args, events) }
		}
		if err := run(ctx, os.Args[2:]); err != nil {
			log.Error("sensor_failed", "error", err.Error())
			os.Exit(1)
		}
		return
	}

	kind := flag.String("validate", "window", "contract: window, prediction, packet")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: netwatch-sensor -validate window FILE.json | interfaces | replay --input PCAP --output JSONL | live --interface NAME --filter BPF --output JSONL | enqueue --spool DIR --input JSONL | send --spool DIR --endpoint URL | spool-status --spool DIR | enroll --endpoint grpcs://HOST:PORT --identity PATH | pause|resume|remove --identity PATH")
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err == nil {
		err = contract.Validate(*kind, data)
	}
	if err != nil {
		log.Error("sensor_failed", "error", err.Error())
		os.Exit(1)
	}
	fmt.Println("contract valid")
}
