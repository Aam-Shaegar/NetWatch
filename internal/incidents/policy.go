// Package incidents evaluates consecutive observations in event-time order.
package incidents

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
}
type Change struct {
	Open []Point
	Kind string
}

func (s *State) Observe(p Point) Change {
	if s.End > p.Start {
		s.Late++
		return Change{}
	}
	if s.End != p.Start {
		s.Recent = nil
		s.Recoveries = 0
	}
	s.End = p.End
	valid := p.Score != nil && p.Threshold != nil && (p.Status == "anomalous" || p.Status == "normal")
	if !valid {
		s.Recent = nil
		s.Recoveries = 0
		if s.Active != 0 {
			return Change{Kind: "unknown"}
		}
		return Change{}
	}
	signal := p.Signal()
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
	s.Recent = append(s.Recent, p)
	if len(s.Recent) > 3 {
		s.Recent = s.Recent[1:]
	}
	if len(s.Recent) == 3 {
		count := 0
		for _, v := range s.Recent {
			if v.Signal() {
				count++
			}
		}
		if count >= 2 {
			history := s.Recent
			s.Recent = nil
			return Change{Open: history, Kind: "opened"}
		}
	}
	return Change{}
}
