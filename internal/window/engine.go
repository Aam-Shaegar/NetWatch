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
	Host       netip.Addr
	Service    netip.AddrPort
	Protocol   string
	Lateness   time.Duration
	MaxUnique  int
	MaxPending int
}

// Count is exact unless its set exceeded the configured limit.
type Count struct {
	Value    int
	Overflow bool
}

type Result struct {
	Start, End                           int64
	InPackets, OutPackets                uint64
	InBytes, OutBytes                    uint64
	Peers, DestinationPorts, ActiveFlows Count
	NewTCPAttempts                       uint64
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
	peers distinct[netip.Addr]
	ports distinct[uint16]
	flows distinct[flow.Key]
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
}

func New(c Config) (*Engine, error) {
	if c.Host.IsValid() == c.Service.IsValid() || c.Lateness < 0 || c.MaxUnique <= 0 || c.MaxPending <= 0 {
		return nil, fmt.Errorf("choose one entity, nonnegative lateness and positive limits")
	}
	if c.Service.IsValid() && c.Protocol != "TCP" && c.Protocol != "UDP" {
		return nil, fmt.Errorf("service requires TCP or UDP")
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
		out = append(out, w.Result)
		delete(e.windows, start)
	}
	return out
}

func (e *Engine) accumulate(ev event) {
	e.tracker.Advance(ev.at)
	p := ev.p
	if p.Status != "decoded" {
		return
	}
	src, err := netip.ParseAddr(p.Src)
	if err != nil {
		return
	}
	dst, err := netip.ParseAddr(p.Dst)
	if err != nil {
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
	start := ev.at / width * width
	w := e.windows[start]
	if w == nil {
		w = &accumulator{Result: Result{Start: start, End: start + width}}
		e.windows[start] = w
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
	state, retry := e.tracker.Observe(p)
	const fin, syn, rst, ack = 1, 2, 4, 16
	if state != nil && !retry && p.Protocol == "TCP" && p.TCPFlags != nil && *p.TCPFlags&(fin|syn|rst|ack) == syn && p.TCPSeq != nil {
		w.NewTCPAttempts++
	}
}
