package main

import (
	"flag"
	"fmt"
	"netwatch.local/netwatch/internal/contract"
	"os"
)

func main() {
	kind := flag.String("validate", "window", "contract: window, prediction, packet")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: netwatch-sensor -validate window FILE.json; capture/replay not implemented yet")
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
