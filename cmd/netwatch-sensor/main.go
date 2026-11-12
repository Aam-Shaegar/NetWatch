package main

import (
	"context"
	"flag"
	"fmt"
	"netwatch.local/netwatch/internal/contract"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "interfaces" {
		if err := interfaces(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "replay" || os.Args[1] == "live") {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		run := replay
		if os.Args[1] == "live" {
			run = live
		}
		if err := run(ctx, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	kind := flag.String("validate", "window", "contract: window, prediction, packet")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: netwatch-sensor -validate window FILE.json | interfaces | replay --input PCAP --output JSONL | live --interface NAME --filter BPF --output JSONL")
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err == nil {
		err = contract.Validate(*kind, data)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("contract valid")
}
