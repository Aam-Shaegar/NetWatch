package window

import (
	"time"

	"netwatch.local/netwatch/internal/flow"
)

type connectionKey struct {
	state       *flow.State
	incarnation uint64
}

type connectionAges struct {
	// Key by incarnation, so reusing a four-tuple does not merge lifetimes.
	age                  map[connectionKey]float64
	known                uint64
	sum, max             float64
	closed               uint64
	closedSum, closedMax float64
	overflow             bool
}

func (c *connectionAges) observe(state *flow.State, at, since int64, closed bool, limit int) {
	if c.overflow {
		return
	}
	start, incarnation, known := state.TCPStart()
	key := connectionKey{state: state, incarnation: incarnation}
	previous, seen := c.age[key]
	if !seen && len(c.age) == limit {
		c.overflow = true
		c.age = nil
		return
	}
	if c.age == nil {
		c.age = make(map[connectionKey]float64)
	}
	if !known || start < since {
		if !seen {
			c.age[key] = -1 // The opening timestamp is censored.
		}
		return
	}
	seconds := float64(at-start) / float64(time.Second)
	if !seen || previous < 0 {
		c.known++
		previous = 0
	}
	c.age[key] = seconds
	c.sum += seconds - previous
	c.max = max(c.max, seconds)
	if closed {
		c.closed++
		c.closedSum += seconds
		c.closedMax = max(c.closedMax, seconds)
	}
}

func (c connectionAges) export(r *Result) {
	if c.overflow {
		return
	}
	r.TCPKnownStartFraction = fraction(c.known, uint64(len(c.age)))
	if c.known != 0 {
		average := c.sum / float64(c.known)
		r.TCPAgeMean, r.TCPAgeMax = &average, &c.max
	}
	if c.closed != 0 {
		average := c.closedSum / float64(c.closed)
		r.TCPClosedMean, r.TCPClosedMax = &average, &c.closedMax
	}
}
