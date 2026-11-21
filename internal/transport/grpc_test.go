package transport

import (
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"
	wire "netwatch.local/netwatch/contracts/sensorv1"
	"netwatch.local/netwatch/internal/contract"
)

func TestProtobufObservationPreservesUnavailableAndMeasuredZero(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var observation contract.Window
	if err = json.Unmarshal(raw, &observation); err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	observation.Quality.CaptureDropped = &zero
	observation.Features["std_interarrival_seconds"] = nil
	raw, err = json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	message, err := observationToWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded wire.Observation
	if err = proto.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	replay, err := ObservationJSON(&decoded)
	if err != nil || string(replay) != string(raw) {
		t.Fatalf("protobuf round-trip changed canonical window: %v", err)
	}
}
