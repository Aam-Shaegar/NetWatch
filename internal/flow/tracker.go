package flow

import "netwatch.local/netwatch/internal/decode"

// Tracker belongs to one capture. Its zero value is ready to use.
type Tracker struct {
	flows map[Key]*State
}

type State struct {
	FirstFromLow bool
	Packets      uint64
	Attempts     uint64
	Established  uint64
	// Last opening SYN per sender. A nil slot means no SYN observed.
	syn [2]*uint32
}

// Observe returns the current flow and whether this packet repeated an opening SYN.
func (t *Tracker) Observe(p decode.Meta) (state *State, repeated bool) {
	key, fromLow, ok := packetKey(p)
	if !ok {
		return nil, false
	}
	if t.flows == nil {
		t.flows = make(map[Key]*State)
	}
	state = t.flows[key]
	if state == nil {
		state = &State{FirstFromLow: fromLow}
		t.flows[key] = state
	}
	state.Packets++
	const syn, ack = 0x02, 0x10
	if p.Protocol != "TCP" || p.TCPFlags == nil || *p.TCPFlags&(syn|ack) != syn || p.TCPSeq == nil {
		return state, false
	}
	side := 0
	if !fromLow {
		side = 1
	}
	seq := *p.TCPSeq
	if prev := state.syn[side]; prev != nil && *prev == seq {
		return state, true
	}
	state.syn[side] = &seq
	state.Attempts++
	return state, false
}
