// Package incidents evaluates consecutive observations in event-time order.
package incidents

const (
	LegacyPolicy      = "v1"
	PersistencePolicy = "v2"
)

func Rule(policy string) string {
	if policy == PersistencePolicy {
		return "two_of_three_close_after_three_without_persistence"
	}
	return "two_of_three_close_three_at_95pct"
}

type Point struct {
	ID               string
	Start, End       int64
	Status           string
	Score, Threshold *float64
}

func (p Point) Signal() bool {
	return p.Status == "anomalous" && p.Score != nil && p.Threshold != nil && *p.Score > *p.Threshold
}

type State struct {
	End        int64
	Recent     []Point
	Recoveries int
	Active     int64
	Late       int64
	Missing    int64
}
type Change struct {
	Open          []Point
	Kind          string
	InterruptedAt *int64
	LinkWindow    bool
}

func (s *State) Observe(p Point) Change {
	return s.ObserveWithPolicy(p, LegacyPolicy)
}

// ObserveWithPolicy preserves historical behavior on existing v1 streams.
func (s *State) ObserveWithPolicy(p Point, policy string) Change {
	if s.End > p.Start {
		s.Late++
		return Change{}
	}
	previousEnd := s.End
	discontinuous := previousEnd != p.Start
	if discontinuous {
		s.Recent = nil
		s.Recoveries = 0
	}
	s.End = p.End
	valid := p.Score != nil && p.Threshold != nil && (p.Status == "anomalous" || p.Status == "normal")
	if policy == PersistencePolicy && s.Active != 0 && (discontinuous || !valid) {
		s.Recent = nil
		s.Recoveries = 0
		if valid {
			s.remember(p)
		}
		at := min(previousEnd, p.Start)
		return Change{Kind: "interrupted", InterruptedAt: &at, LinkWindow: !valid}
	}
	if !valid {
		s.Recent = nil
		s.Recoveries = 0
		if s.Active != 0 {
			return Change{Kind: "unknown"}
		}
		return Change{}
	}
	signal := p.Signal()
	if policy == PersistencePolicy && s.Active != 0 {
		s.remember(p)
		if signal && s.signalCount() >= 2 {
			s.Recoveries = 0
			return Change{Kind: "signal"}
		}
		s.Recoveries++
		if s.Recoveries == 3 {
			s.Recoveries = 0
			return Change{Kind: "closed"}
		}
		return Change{Kind: "observed"}
	}
	if s.Active != 0 {
		s.Recent = nil
		if signal {
			s.Recoveries = 0
			return Change{Kind: "signal"}
		}
		if p.Status == "normal" && *p.Score <= 0.95*(*p.Threshold) {
			s.Recoveries++
		} else {
			s.Recoveries = 0
		}
		if s.Recoveries == 3 {
			s.Recoveries = 0
			return Change{Kind: "closed"}
		}
		return Change{Kind: "observed"}
	}
	s.remember(p)
	if len(s.Recent) == 3 && s.signalCount() >= 2 {
		history := s.Recent
		if policy != PersistencePolicy {
			s.Recent = nil
		}
		return Change{Open: history, Kind: "opened"}
	}
	return Change{}
}

func (s *State) remember(p Point) {
	s.Recent = append(s.Recent, p)
	if len(s.Recent) > 3 {
		s.Recent = s.Recent[1:]
	}
}

func (s *State) signalCount() int {
	count := 0
	for _, p := range s.Recent {
		if p.Signal() {
			count++
		}
	}
	return count
}
