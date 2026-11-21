// netwatch-catalog runs the production rules on labeled-data windows without inference.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"netwatch.local/netwatch/internal/catalog"
	"netwatch.local/netwatch/internal/contract"
)

func run(input io.Reader, output io.Writer, disabled string) error {
	rules, err := catalog.NewRules(disabled)
	if err != nil {
		return err
	}
	type streamKey struct{ group, sensor, epoch, entity string }
	type streamState struct {
		start   int64
		history []contract.Window
	}
	streams := map[streamKey]streamState{}
	reader := bufio.NewScanner(input)
	reader.Buffer(make([]byte, 4096), 256<<10)
	writer := json.NewEncoder(output)
	for line := 1; reader.Scan(); line++ {
		var item struct {
			Group  string          `json:"group"`
			Window json.RawMessage `json:"window"`
		}
		var window contract.Window
		if json.Unmarshal(reader.Bytes(), &item) != nil || item.Group == "" ||
			contract.Validate("window", item.Window) != nil || json.Unmarshal(item.Window, &window) != nil ||
			window.FeatureSetVersion != catalog.FeatureSet {
			return fmt.Errorf("line %d: expected group and valid traffic-v3 window", line)
		}
		key := streamKey{item.Group, window.SensorID, window.CaptureEpoch, window.EntityID}
		state := streams[key]
		start, _ := strconv.ParseInt(window.WindowStartNS, 10, 64)
		if state.start > start {
			return fmt.Errorf("line %d: stream windows must be in chronological order", line)
		}
		if err := writer.Encode(rules.Evaluate(window, state.history)); err != nil {
			return err
		}
		if catalog.Eligible(window) {
			state.history = append(state.history, window)
			if len(state.history) > catalog.HistoryLimit {
				copy(state.history, state.history[1:])
				state.history = state.history[:catalog.HistoryLimit]
			}
		}
		state.start = start
		streams[key] = state
	}
	return reader.Err()
}

func main() {
	if err := run(os.Stdin, os.Stdout, os.Getenv("NETWATCH_DISABLED_RULES")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
