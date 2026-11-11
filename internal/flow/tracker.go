package flow

import (
	"container/list"
	"strconv"
	"time"

	"netwatch.local/netwatch/internal/decode"
)

// Tracker belongs to one capture. Its zero value is ready to use.
type Tracker struct {
	flows map[Key]*State
	// Each protocol has a different idle timeout. Front is least recently seen.
	recency        [2]list.List
	now            int64
	limit          int
	StateEvictions uint64
}

type State struct {
	FirstFromLow bool
	Packets      uint64
	Attempts     uint64
	Established  uint64
	ClosedBy     string // "fin" after both FINs, "rst" on a reset
	syn          [2]*uint32
	reply        [2]*uint32 // responder sequence indexed by opening SYN side
	fin          [2]bool
	last         int64
	entry        *list.Element
}

// Advance expires idle state in capture time. Older timestamps never rewind it.
func (t *Tracker) Advance(ns int64) {
	t.now = max(t.now, ns)
	for i, idle := range [2]time.Duration{60 * time.Second, 30 * time.Second} {
		queue := &t.recency[i]
		for e := queue.Front(); e != nil; e = queue.Front() {
			key := e.Value.(Key)
			if t.now-t.flows[key].last < int64(idle) {
				break
			}
			t.remove(i, key)
		}
	}
}

func (t *Tracker) remove(i int, key Key) {
	state := t.flows[key]
	t.recency[i].Remove(state.entry)
	state.entry = nil
	delete(t.flows, key)
}

func (t *Tracker) evictOldest() {
	i := 0
	a, b := t.recency[0].Front(), t.recency[1].Front()
	if a == nil || (b != nil && t.flows[b.Value.(Key)].last < t.flows[a.Value.(Key)].last) {
		i = 1
	}
	t.remove(i, t.recency[i].Front().Value.(Key))
	t.StateEvictions++
}

// Observe returns the current flow and whether this packet repeated an opening SYN.
func (t *Tracker) Observe(p decode.Meta) (state *State, repeated bool) {
	ns, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil || ns < 0 {
		return nil, false
	}
	t.Advance(ns)
	key, fromLow, ok := packetKey(p)
	if !ok {
		return nil, false
	}
	if t.flows == nil {
		t.flows = make(map[Key]*State)
		if t.limit == 0 {
			t.limit = 100_000
		}
	}
	i, side := 0, 0
	if p.Protocol == "UDP" {
		i = 1
	}
	if !fromLow {
		side = 1
	}
	var flags uint8
	if p.TCPFlags != nil && i == 0 {
		flags = *p.TCPFlags
	}
	const fin, syn, rst, ack = 1, 2, 4, 16
	opening := flags&(fin|syn|rst|ack) == syn && p.TCPSeq != nil
	state = t.flows[key]
	if state != nil && opening && (state.ClosedBy != "" || (state.Established > 0 && (state.syn[side] == nil || *state.syn[side] != *p.TCPSeq))) {
		t.remove(i, key)
		state = nil
	}
	if state == nil {
		if len(t.flows) >= t.limit {
			t.evictOldest()
		}
		state = &State{FirstFromLow: fromLow, entry: t.recency[i].PushBack(key)}
		t.flows[key] = state
	}
	state.last = t.now
	t.recency[i].MoveToBack(state.entry)
	state.Packets++
	if state.ClosedBy != "" {
		return state, false
	}
	if opening {
		seq := *p.TCPSeq
		if prev := state.syn[side]; prev != nil && *prev == seq {
			return state, true
		}
		state.syn[side], state.reply[side] = &seq, nil
		state.Attempts++
	}
	if flags&rst != 0 {
		state.ClosedBy = "rst"
		return state, false
	}
	if flags&fin != 0 {
		state.fin[side] = true
		if state.fin[1-side] {
			state.ClosedBy = "fin"
		}
	}
	if p.TCPSeq == nil || p.TCPAck == nil || state.Established != 0 {
		return state, false
	}
	if flags&(syn|ack|fin) == syn|ack {
		if first := state.syn[1-side]; first != nil && *p.TCPAck == *first+1 {
			seq := *p.TCPSeq
			state.reply[1-side] = &seq
		}
	} else if flags&(syn|ack) == ack {
		first, reply := state.syn[side], state.reply[side]
		if first != nil && reply != nil && *p.TCPSeq == *first+1 && *p.TCPAck == *reply+1 {
			state.Established++
		}
	}
	return state, false
}

// Changes describes events observed in this packet, including a new incarnation.
type Changes struct {
	Attempts, Established, Completed uint64
}

func (t *Tracker) ObserveChanges(p decode.Meta) (state *State, changes Changes) {
	key, ok := KeyFromPacket(p)
	if !ok {
		return nil, changes
	}
	previous := t.flows[key]
	var attempts, established uint64
	var closed string
	if previous != nil {
		attempts, established, closed = previous.Attempts, previous.Established, previous.ClosedBy
	}
	state, _ = t.Observe(p)
	if state == nil {
		return nil, changes
	}
	if state != previous {
		attempts, established, closed = 0, 0, ""
	}
	changes.Attempts = state.Attempts - attempts
	changes.Established = state.Established - established
	if closed == "" && state.ClosedBy != "" {
		changes.Completed = 1
	}
	return state, changes
}
