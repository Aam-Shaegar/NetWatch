package incidents

import "testing"

func TestLifecycle(t *testing.T) {
	var s State
	tick := int64(0)
	step := func(status string, want string) {
		t.Helper()
		score, threshold := 0.5, 1.
		if status == "anomalous" {
			score = 1.2
		}
		if status == "near" {
			score = .97
			status = "normal"
		}
		c := s.Observe(Point{ID: "window", Start: tick, End: tick + 5, Status: status, Score: &score, Threshold: &threshold})
		tick += 5
		if c.Kind != want {
			t.Fatalf("%s: got %s, want %s", status, c.Kind, want)
		}
		if c.Kind == "opened" {
			if len(c.Open) != 3 {
				t.Fatal("missing evidence")
			}
			s.Active = 1
		}
	}
	step("anomalous", "")
	tick += 5
	step("normal", "")
	step("anomalous", "")
	step("anomalous", "opened")
	step("anomalous", "signal")
	step("normal", "observed")
	step("insufficient_data", "unknown")
	step("normal", "observed")
	step("near", "observed")
	step("normal", "observed")
	step("normal", "observed")
	step("normal", "closed")
	if c := s.Observe(Point{Start: 1, End: 6}); c.Kind != "" || s.Late != 1 {
		t.Fatal("late window changed history")
	}
}
