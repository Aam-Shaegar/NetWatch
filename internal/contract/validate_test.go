package contract

import (
	"encoding/json"
	"os"
	"testing"
)

func TestWindowContract(t *testing.T) {
	b, e := os.ReadFile("../../contracts/examples/window.valid.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = Validate("window", b); e != nil {
		t.Fatal(e)
	}
	cases := []func(map[string]any){
		func(m map[string]any) { m["schema_version"] = 2 },
		func(m map[string]any) { m["window_end_ns"] = m["window_start_ns"] },
		func(m map[string]any) { m["window_start_ns"] = "9999999999999999999" },
		func(m map[string]any) { m["extra"] = "bad" },
		func(m map[string]any) { m["features"].(map[string]any)["out_packets"] = 1.5 },
	}
	for i, change := range cases {
		var m map[string]any
		json.Unmarshal(b, &m)
		change(m)
		raw, _ := json.Marshal(m)
		if Validate("window", raw) == nil {
			t.Fatalf("accepted invalid %d", i)
		}
	}
}
func TestPrediction(t *testing.T) {
	b, _ := os.ReadFile("../../contracts/examples/prediction.valid.json")
	if e := Validate("prediction", b); e != nil {
		t.Fatal(e)
	}
}
