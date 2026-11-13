package spool

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Open exclusively owns the directory and restores pending records before use.
func Open(dir string, c Config) (_ *Queue, err error) {
	if c.SegmentBytes < 1024 || c.MaxBytes < c.SegmentBytes || c.QuarantineBytes < MaxRecord {
		return nil, fmt.Errorf("invalid spool limits")
	}
	if err = durableMkdir(dir); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("spool already owned: %w", err)
	}
	q := &Queue{dir: dir, config: c, lock: lock, next: 1, state: state{Version: 1}, rejected: map[uint64]bool{}}
	defer func() {
		if err != nil {
			q.Close()
		}
	}()
	data, e := readSealed(filepath.Join(dir, "state.json"))
	if e == nil {
		if err = json.Unmarshal(data, &q.state); err != nil {
			return nil, fmt.Errorf("invalid spool state: %w", err)
		}
		if q.state.Version != 1 {
			return nil, fmt.Errorf("unsupported spool version")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if q.state.Ack == ^uint64(0) {
		return nil, fmt.Errorf("sequence exhausted")
	}
	q.next = q.state.Ack + 1
	names, err := filepath.Glob(filepath.Join(dir, "*.seg"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var previous uint64
	for i, name := range names {
		if err = q.recoverSegment(name, i == len(names)-1, &previous); err != nil {
			return nil, err
		}
	}
	quarantine, err := filepath.Glob(filepath.Join(dir, "quarantine", "*.json"))
	if err != nil {
		return nil, err
	}
	for _, name := range quarantine {
		n, e := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), ".json"), 10, 64)
		if e != nil {
			return nil, e
		}
		info, e := os.Stat(name)
		if e != nil {
			return nil, e
		}
		if n == 0 || n >= q.next {
			return nil, fmt.Errorf("invalid quarantine sequence")
		}
		data, e := readSealed(name)
		if e != nil {
			return nil, e
		}
		var saved struct {
			Sequence uint64          `json:"sequence"`
			Window   json.RawMessage `json:"window"`
		}
		if e = json.Unmarshal(data, &saved); e != nil || saved.Sequence != n {
			return nil, fmt.Errorf("invalid quarantine record")
		}
		for _, entry := range q.entries {
			if entry.seq == n {
				actual, e := q.read(entry)
				if e != nil {
					return nil, e
				}
				canonical, e := json.Marshal(actual.Window)
				if e != nil {
					return nil, e
				}
				if !bytes.Equal(canonical, saved.Window) {
					return nil, fmt.Errorf("quarantine differs from queued record")
				}
				break
			}
		}
		q.rejected[n] = true
		q.quarantineBytes += info.Size()
	}
	if q.bytes > c.MaxBytes || q.quarantineBytes > c.QuarantineBytes || len(q.rejected) > 1000 {
		return nil, fmt.Errorf("existing queue exceeds configured limits")
	}
	if len(q.entries) > 0 && q.entries[0].seq != q.state.Ack+1 {
		return nil, fmt.Errorf("missing pending segment")
	}
	recoveredState := q.state
	for _, e := range q.entries {
		if !q.rejected[e.seq] {
			break
		}
		recoveredState.Ack = e.seq
	}
	if recoveredState.Ack != q.state.Ack {
		if err = q.save(recoveredState); err != nil {
			return nil, err
		}
		q.state = recoveredState
	}
	if err = q.cleanup(); err != nil {
		return nil, err
	}
	for _, folder := range []string{dir, filepath.Join(dir, "quarantine")} {
		temps, e := filepath.Glob(filepath.Join(folder, ".state-*"))
		if e != nil {
			return nil, e
		}
		for _, name := range temps {
			if e = os.Remove(name); e != nil {
				return nil, e
			}
		}
		if len(temps) > 0 {
			if e = syncDir(folder); e != nil {
				return nil, e
			}
		}
	}
	return q, nil
}

func (q *Queue) recoverSegment(name string, last bool, previous *uint64) error {
	first, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), ".seg"), 10, 64)
	if err != nil || first == 0 {
		return fmt.Errorf("invalid segment name %s", filepath.Base(name))
	}
	file, err := os.OpenFile(name, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > q.config.SegmentBytes {
		return fmt.Errorf("segment exceeds configured size")
	}
	seg := segment{name: filepath.Base(name)}
	for offset := int64(0); offset < info.Size(); {
		head := make([]byte, headerSize)
		n, e := file.ReadAt(head, offset)
		if e != nil && e != io.EOF {
			return e
		}
		if n < headerSize {
			if !last {
				return fmt.Errorf("torn closed segment")
			}
			return q.repairTail(file, seg, offset, info.Size())
		}
		size := int(binary.BigEndian.Uint32(head[4:8]))
		seq := binary.BigEndian.Uint64(head[8:16])
		if string(head[:4]) != "NWQ1" || size < 1 || size > MaxRecord || seq == 0 || seq == ^uint64(0) {
			return fmt.Errorf("corrupt record header")
		}
		if offset == 0 && seq != first || seq <= *previous || (seq > q.state.Ack && seq != max(*previous, q.state.Ack)+1) {
			return fmt.Errorf("non-contiguous sequence")
		}
		if offset+headerSize+int64(size) > info.Size() {
			if !last {
				return fmt.Errorf("torn closed segment")
			}
			return q.repairTail(file, seg, offset, info.Size())
		}
		data := make([]byte, size)
		if _, err = file.ReadAt(data, offset+headerSize); err != nil {
			return err
		}
		if checksum(head, data) != binary.BigEndian.Uint32(head[16:20]) || !json.Valid(data) {
			return fmt.Errorf("corrupt record checksum or JSON")
		}
		*previous = seq
		q.next = max(q.next, seq+1)
		if seq > q.state.Ack {
			q.entries = append(q.entries, entry{seq, seg.name, offset, size})
		}
		offset += headerSize + int64(size)
		seg.bytes = offset
		seg.last = seq
	}
	q.segments = append(q.segments, seg)
	q.bytes += seg.bytes
	return nil
}
func (q *Queue) repairTail(file *os.File, seg segment, offset, total int64) error {
	if err := file.Truncate(offset); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	q.recovered += total - offset
	seg.bytes = offset
	q.segments = append(q.segments, seg)
	q.bytes += offset
	return nil
}
