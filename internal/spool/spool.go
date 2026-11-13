// Package spool implements a single-owner, bounded, append-only window queue.
package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"netwatch.local/netwatch/internal/contract"
	"os"
	"path/filepath"
	"sync"
)

const MaxRecord = 64 << 10
const headerSize = 20

var ErrFull = errors.New("spool full: newest window dropped")

type Config struct{ MaxBytes, SegmentBytes, QuarantineBytes int64 }

func DefaultConfig() Config { return Config{256 << 20, 4 << 20, 16 << 20} }

type Loss struct {
	Count              uint64 `json:"count"`
	FirstEventID       string `json:"first_event_id,omitempty"`
	LastEventID        string `json:"last_event_id,omitempty"`
	FirstWindowStartNS string `json:"first_window_start_ns,omitempty"`
	LastWindowStartNS  string `json:"last_window_start_ns,omitempty"`
}
type state struct {
	Version int    `json:"version"`
	Ack     uint64 `json:"ack"`
	Loss    Loss   `json:"loss"`
}
type Stats struct {
	Degraded           bool  `json:"degraded"`
	Pending            int   `json:"pending"`
	Bytes              int64 `json:"bytes"`
	Quarantined        int   `json:"quarantined"`
	RecoveredTailBytes int64 `json:"recovered_tail_bytes"`
	Loss               Loss  `json:"loss"`
}
type Item struct {
	Sequence uint64
	Window   json.RawMessage
	EventID  string
}
type entry struct {
	seq     uint64
	segment string
	offset  int64
	size    int
}
type segment struct {
	name  string
	bytes int64
	last  uint64
}
type Queue struct {
	mu                                sync.Mutex
	dir                               string
	config                            Config
	lock                              *os.File
	state                             state
	entries                           []entry
	segments                          []segment
	rejected                          map[uint64]bool
	bytes, quarantineBytes, recovered int64
	next                              uint64
	fatal                             error
	closed                            bool
}

func (q *Queue) check() error {
	if q.closed {
		return fmt.Errorf("spool closed")
	}
	return q.fatal
}
func (q *Queue) fail(err error) error {
	if err != nil {
		q.fatal = err
	}
	return err
}
func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, e := range q.entries {
		if !q.rejected[e.seq] {
			n++
		}
	}
	return Stats{Degraded: q.state.Loss.Count > 0 || len(q.rejected) > 0 || q.recovered > 0 || q.fatal != nil, Pending: n, Bytes: q.bytes, Quarantined: len(q.rejected), RecoveredTailBytes: q.recovered, Loss: q.state.Loss}
}

// Append returns only after file data and newly created directory entries are synced.
func (q *Queue) Append(data []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.check(); err != nil {
		return err
	}
	if len(data) > MaxRecord || int64(len(data)+headerSize) > q.config.SegmentBytes {
		return fmt.Errorf("window exceeds record/segment limit")
	}
	if err := contract.Validate("window", data); err != nil {
		return err
	}
	var w contract.Window
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	size := int64(headerSize + len(data))
	if q.bytes+size > q.config.MaxBytes {
		s := q.state
		if s.Loss.Count == ^uint64(0) {
			return q.fail(fmt.Errorf("loss counter exhausted"))
		}
		s.Loss.Count++
		if s.Loss.Count == 1 {
			s.Loss.FirstEventID = w.EventID
			s.Loss.FirstWindowStartNS = w.WindowStartNS
		}
		s.Loss.LastEventID = w.EventID
		s.Loss.LastWindowStartNS = w.WindowStartNS
		if err := q.save(s); err != nil {
			return q.fail(err)
		}
		q.state = s
		return ErrFull
	}
	if q.next == ^uint64(0) {
		return q.fail(fmt.Errorf("sequence exhausted"))
	}
	created := len(q.segments) == 0 || q.segments[len(q.segments)-1].bytes+size > q.config.SegmentBytes
	var seg segment
	if created {
		seg = segment{name: fmt.Sprintf("%020d.seg", q.next)}
	} else {
		seg = q.segments[len(q.segments)-1]
	}
	flags := os.O_WRONLY | os.O_APPEND
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(filepath.Join(q.dir, seg.name), flags, 0600)
	if err != nil {
		return q.fail(err)
	}
	head := make([]byte, headerSize)
	copy(head, "NWQ1")
	binary.BigEndian.PutUint32(head[4:8], uint32(len(data)))
	binary.BigEndian.PutUint64(head[8:16], q.next)
	binary.BigEndian.PutUint32(head[16:20], checksum(head, data))
	record := append(head, data...)
	n, err := f.Write(record)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil && created {
		err = syncDir(q.dir)
	}
	if err != nil {
		return q.fail(err)
	}
	q.entries = append(q.entries, entry{q.next, seg.name, seg.bytes, len(data)})
	seg.bytes += size
	seg.last = q.next
	q.next++
	q.bytes += size
	if created {
		q.segments = append(q.segments, seg)
	} else {
		q.segments[len(q.segments)-1] = seg
	}
	return nil
}

func (q *Queue) read(e entry) (Item, error) {
	f, err := os.Open(filepath.Join(q.dir, e.segment))
	if err != nil {
		return Item{}, err
	}
	defer f.Close()
	record := make([]byte, headerSize+e.size)
	if _, err = f.ReadAt(record, e.offset); err != nil {
		return Item{}, err
	}
	if binary.BigEndian.Uint64(record[8:16]) != e.seq || checksum(record[:headerSize], record[headerSize:]) != binary.BigEndian.Uint32(record[16:20]) {
		return Item{}, fmt.Errorf("queued record corrupted")
	}
	var w contract.Window
	if err = json.Unmarshal(record[headerSize:], &w); err != nil {
		return Item{}, err
	}
	return Item{e.seq, json.RawMessage(record[headerSize:]), w.EventID}, nil
}
func (q *Queue) Peek(limit, maxBytes int) ([]Item, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.check(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 || maxBytes < MaxRecord {
		return nil, fmt.Errorf("invalid batch bounds")
	}
	var out []Item
	size := 0
	for _, e := range q.entries {
		if q.rejected[e.seq] {
			continue
		}
		if len(out) == limit || size+e.size > maxBytes {
			break
		}
		item, err := q.read(e)
		if err != nil {
			return nil, q.fail(err)
		}
		out = append(out, item)
		size += e.size
	}
	return out, nil
}

// Ack persists the cursor before reclaiming segments. Only the pending prefix is legal.
func (q *Queue) Ack(items []Item) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.check(); err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("empty acknowledgment")
	}
	i := 0
	last := q.state.Ack
	for _, e := range q.entries {
		if q.rejected[e.seq] {
			last = e.seq
			continue
		}
		if i == len(items) {
			break
		}
		if e.seq != items[i].Sequence {
			return fmt.Errorf("ack is not the pending prefix")
		}
		last = e.seq
		i++
	}
	if i != len(items) {
		return fmt.Errorf("ack exceeds queue")
	}
	s := q.state
	s.Ack = last
	if err := q.save(s); err != nil {
		return q.fail(err)
	}
	q.state = s
	return q.fail(q.cleanup())
}

// Reject durably preserves an invalid event before removing it from delivery.
// The bounded quarantine is retained for operator inspection, including after ACK.
func (q *Queue) Reject(item Item, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.check(); err != nil {
		return err
	}
	var found *entry
	for i := range q.entries {
		if q.entries[i].seq == item.Sequence {
			found = &q.entries[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("unknown rejected sequence")
	}
	if q.rejected[item.Sequence] {
		return nil
	}
	actual, err := q.read(*found)
	if err != nil {
		return q.fail(err)
	}
	if len(reason) > 512 {
		reason = reason[:512]
	}
	data, err := json.Marshal(struct {
		Sequence uint64          `json:"sequence"`
		Reason   string          `json:"reason"`
		Window   json.RawMessage `json:"window"`
	}{item.Sequence, reason, actual.Window})
	if err != nil {
		return err
	}
	data, err = seal(data)
	if err != nil {
		return err
	}
	if q.quarantineBytes+int64(len(data)) > q.config.QuarantineBytes || len(q.rejected) >= 1000 {
		return fmt.Errorf("quarantine full; delivery stopped")
	}
	dir := filepath.Join(q.dir, "quarantine")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return q.fail(err)
	}
	if err = syncDir(q.dir); err != nil {
		return q.fail(err)
	}
	if err = atomicFile(dir, fmt.Sprintf("%020d.json", item.Sequence), data); err != nil {
		return q.fail(err)
	}
	q.rejected[item.Sequence] = true
	q.quarantineBytes += int64(len(data))
	// Advance only across a rejected prefix, never across an unacknowledged event.
	s := q.state
	for _, e := range q.entries {
		if !q.rejected[e.seq] {
			break
		}
		s.Ack = e.seq
	}
	if s.Ack != q.state.Ack {
		if err = q.save(s); err != nil {
			return q.fail(err)
		}
		q.state = s
		return q.fail(q.cleanup())
	}
	return nil
}
func (q *Queue) cleanup() error {
	kept := q.entries[:0]
	for _, e := range q.entries {
		if e.seq > q.state.Ack {
			kept = append(kept, e)
		}
	}
	q.entries = kept
	segments := q.segments[:0]
	removed := false
	for _, s := range q.segments {
		if s.bytes == 0 || s.last <= q.state.Ack {
			if err := os.Remove(filepath.Join(q.dir, s.name)); err != nil {
				return err
			}
			q.bytes -= s.bytes
			removed = true
		} else {
			segments = append(segments, s)
		}
	}
	q.segments = segments
	if removed {
		return syncDir(q.dir)
	}
	return nil
}
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	return q.lock.Close()
}
