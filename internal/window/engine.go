// Package window computes the initial traffic counters for one observed entity.
package window

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"netwatch.local/netwatch/internal/decode"
	"netwatch.local/netwatch/internal/flow"
)

const width = int64(5 * time.Second)

type Config struct {
	Host                       netip.Addr
	Service                    netip.AddrPort
	Protocol                   string
	Lateness                   time.Duration
	MaxUnique                  int
	MaxPending                 int
	CoverageStart, CoverageEnd *int64
}

// Count is exact unless its set exceeded the configured limit.
type Count struct {
	Value    int
	Overflow bool
}

type Result struct {
	Start, End                             int64
	InPackets, OutPackets                  uint64
	InBytes, OutBytes                      uint64
	Peers, DestinationPorts, ActiveFlows   Count
	NewTCPAttempts                         uint64
	EstablishedTCPAttempts, CompletedFlows uint64
	SYNFraction, RSTFraction               *float64
	MeanPacketSize, StdPacketSize          *float64
	MeanInterarrival, StdInterarrival      *float64
	Coverage                               string
	LatePackets, StateEvictions            uint64
}

type distinct[T comparable] struct {
	values   map[T]struct{}
	overflow bool
}

func (d *distinct[T]) add(value T, limit int) {
	if d.overflow {
		return
	}
	if _, exists := d.values[value]; exists {
		return
	}
	if len(d.values) == limit {
		d.overflow = true
		d.values = nil
		return
	}
	if d.values == nil {
		d.values = make(map[T]struct{})
	}
	d.values[value] = struct{}{}
}

func (d *distinct[T]) count() Count {
	return Count{Value: len(d.values), Overflow: d.overflow}
}

type accumulator struct {
	Result
	peers            distinct[netip.Addr]
	ports            distinct[uint16]
	flows            distinct[flow.Key]
	sizes, intervals moments
	lastPacket       int64
	tcp, syn, rst    uint64
	gap              bool
}

type event struct {
	at  int64
	p   decode.Meta
	tie string
}

// Tie order is deterministic even when two captures list equal timestamps differently.
type pending []event

func (p pending) Len() int { return len(p) }
func (p pending) Less(i, j int) bool {
	a, b := p[i], p[j]
	if a.at != b.at {
		return a.at < b.at
	}
	return a.tie < b.tie
}
func (p pending) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p *pending) Push(v any)   { *p = append(*p, v.(event)) }
func (p *pending) Pop() any {
	last := len(*p) - 1
	v := (*p)[last]
	(*p)[last] = event{}
	*p = (*p)[:last]
	return v
}

// Engine is owned by one goroutine and one capture/observation domain.
type Engine struct {
	config      Config
	queue       pending
	windows     map[int64]*accumulator
	tracker     flow.Tracker
	watermark   int64
	LatePackets uint64
	finished    bool
	restarted   bool
}

func New(c Config) (*Engine, error) {
	if c.Host.IsValid() == c.Service.IsValid() || c.Lateness < 0 || c.MaxUnique <= 0 || c.MaxPending <= 0 {
		return nil, fmt.Errorf("choose one entity, nonnegative lateness and positive limits")
	}
	if c.Service.IsValid() && c.Protocol != "TCP" && c.Protocol != "UDP" {
		return nil, fmt.Errorf("service requires TCP or UDP")
	}
	if (c.CoverageStart == nil) != (c.CoverageEnd == nil) {
		return nil, fmt.Errorf("coverage needs both bounds")
	}
	if c.CoverageStart != nil {
		start, end := *c.CoverageStart, *c.CoverageEnd
		if start < 0 || end <= start {
			return nil, fmt.Errorf("invalid coverage interval")
		}
		c.CoverageStart, c.CoverageEnd = &start, &end
	}
	return &Engine{config: c, windows: make(map[int64]*accumulator)}, nil
}

// Push returns newly closed windows. An overflow error leaves this packet unaccepted.
func (e *Engine) Push(p decode.Meta) ([]Result, error) {
	if e.finished {
		return nil, fmt.Errorf("engine already finished")
	}
	at, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil || at < 0 || at > math.MaxInt64-width {
		return nil, fmt.Errorf("unsupported packet timestamp")
	}
	if e.config.CoverageStart != nil && (at < *e.config.CoverageStart || at >= *e.config.CoverageEnd) {
		return nil, fmt.Errorf("packet outside declared coverage")
	}
	if p.IPLength < 0 {
		return nil, fmt.Errorf("negative IP length")
	}
	if at < e.watermark {
		e.LatePackets++
		return nil, nil
	}
	if len(e.queue) >= e.config.MaxPending {
		return nil, fmt.Errorf("pending packet limit exceeded")
	}
	// Copy optional fields: the caller may reuse its packet storage.
	copyPort := func(v *uint16) *uint16 {
		if v == nil {
			return nil
		}
		n := *v
		return &n
	}
	copyWord := func(v *uint32) *uint32 {
		if v == nil {
			return nil
		}
		n := *v
		return &n
	}
	p.SrcPort, p.DstPort = copyPort(p.SrcPort), copyPort(p.DstPort)
	p.TCPSeq, p.TCPAck = copyWord(p.TCPSeq), copyWord(p.TCPAck)
	if p.TCPFlags != nil {
		v := *p.TCPFlags
		p.TCPFlags = &v
	}
	serialized, _ := json.Marshal(p)
	heap.Push(&e.queue, event{at: at, p: p, tie: string(serialized)})
	e.watermark = max(e.watermark, at-int64(e.config.Lateness))
	return e.drain(false), nil
}

// Finish drains the tail. It makes no claim that capture coverage was complete.
func (e *Engine) Finish() []Result {
	e.finished = true
	return e.drain(true)
}

func (e *Engine) drain(all bool) []Result {
	for len(e.queue) > 0 && (all || e.queue[0].at < e.watermark) {
		e.accumulate(heap.Pop(&e.queue).(event))
	}
	starts := make([]int64, 0)
	for start := range e.windows {
		if all || start+width <= e.watermark {
			starts = append(starts, start)
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	out := make([]Result, 0, len(starts))
	for _, start := range starts {
		w := e.windows[start]
		w.Peers, w.DestinationPorts, w.ActiveFlows = w.peers.count(), w.ports.count(), w.flows.count()
		w.MeanPacketSize, w.StdPacketSize = w.sizes.values()
		w.MeanInterarrival, w.StdInterarrival = w.intervals.values()
		w.SYNFraction, w.RSTFraction = fraction(w.syn, w.tcp), fraction(w.rst, w.tcp)
		w.Coverage = "partial"
		if e.config.CoverageStart != nil && w.Start >= *e.config.CoverageStart && w.End <= *e.config.CoverageEnd {
			w.Coverage = "complete"
		}
		w.LatePackets = e.LatePackets
		if w.gap || w.Peers.Overflow || w.DestinationPorts.Overflow || w.ActiveFlows.Overflow || w.StateEvictions > 0 || w.LatePackets > 0 {
			w.Coverage = "gap"
		}
		out = append(out, w.Result)
		delete(e.windows, start)
	}
	return out
}

func (e *Engine) accumulate(ev event) {
	e.tracker.Advance(ev.at)
	p := ev.p
	if p.Status != "decoded" {
		if p.Status != "non_ip" {
			e.bucket(ev.at).gap = true
		}
		return
	}
	src, err := netip.ParseAddr(p.Src)
	if err != nil {
		e.bucket(ev.at).gap = true
		return
	}
	dst, err := netip.ParseAddr(p.Dst)
	if err != nil {
		e.bucket(ev.at).gap = true
		return
	}
	in, out := dst == e.config.Host, src == e.config.Host
	if e.config.Service.IsValid() {
		s, okS := flow.Endpoint(p.Src, p.SrcPort)
		d, okD := flow.Endpoint(p.Dst, p.DstPort)
		in = okD && d == e.config.Service && p.Protocol == e.config.Protocol
		out = okS && s == e.config.Service && p.Protocol == e.config.Protocol
	}
	if !in && !out {
		return
	}
	w := e.bucket(ev.at)
	if w.sizes.n > 0 {
		w.intervals.add(float64(ev.at-w.lastPacket) / float64(time.Second))
	}
	w.lastPacket = ev.at
	w.sizes.add(float64(p.IPLength))
	if p.Protocol == "TCP" {
		w.tcp++
		if p.TCPFlags != nil {
			if *p.TCPFlags&2 != 0 {
				w.syn++
			}
			if *p.TCPFlags&4 != 0 {
				w.rst++
			}
		}
	}
	if in {
		w.InPackets++
		w.InBytes += uint64(p.IPLength)
		w.peers.add(src, e.config.MaxUnique)
	}
	if out {
		w.OutPackets++
		w.OutBytes += uint64(p.IPLength)
		w.peers.add(dst, e.config.MaxUnique)
	}
	if e.config.Service.IsValid() {
		w.ports.add(e.config.Service.Port(), e.config.MaxUnique)
	} else if out && (p.Protocol == "TCP" || p.Protocol == "UDP") && p.DstPort != nil {
		w.ports.add(*p.DstPort, e.config.MaxUnique)
	}
	key, ok := flow.KeyFromPacket(p)
	if !ok {
		return
	}
	w.flows.add(key, e.config.MaxUnique)
	before := e.tracker.StateEvictions
	_, changes := e.tracker.ObserveChanges(p)
	w.NewTCPAttempts += changes.Attempts
	w.EstablishedTCPAttempts += changes.Established
	w.CompletedFlows += changes.Completed
	w.StateEvictions += e.tracker.StateEvictions - before
}

// Restart ends the current observation epoch and discards connection history.
// Callers must use a new capture_epoch when serializing subsequent results.
func (e *Engine) Restart() []Result {
	out := e.drain(true)
	for i := range out {
		out[i].Coverage = "gap"
	}
	e.tracker = flow.Tracker{}
	e.config.CoverageStart, e.config.CoverageEnd = nil, nil
	e.LatePackets = 0
	e.restarted = true
	e.finished = false
	return out
}

// bucket also permits quality-only windows when a damaged packet has no addresses.
func (e *Engine) bucket(at int64) *accumulator {
	start := at / width * width
	w := e.windows[start]
	if w == nil {
		w = &accumulator{Result: Result{Start: start, End: start + width}, gap: e.restarted}
		e.restarted = false
		e.windows[start] = w
	}
	return w
}
