package spool

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, id string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var w map[string]any
	if err = json.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	w["event_id"] = id
	data, err = json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func openTest(t *testing.T, dir string, c Config) *Queue {
	t.Helper()
	q, err := Open(dir, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}
func appendTest(t *testing.T, q *Queue, id string) {
	t.Helper()
	if err := q.Append(fixture(t, id)); err != nil {
		t.Fatal(err)
	}
}
func peek(t *testing.T, q *Queue) []Item {
	t.Helper()
	items, err := q.Peek(100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestRestartRotationOverflowAndAck(t *testing.T) {
	dir := t.TempDir()
	size := int64(len(fixture(t, "a")) + headerSize)
	c := Config{MaxBytes: 4 * size, SegmentBytes: 2 * size, QuarantineBytes: MaxRecord}
	q := openTest(t, dir, c)
	for _, id := range []string{"a", "b", "c", "d"} {
		appendTest(t, q, id)
	}
	if err := q.Append(fixture(t, "e")); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if _, err := Open(dir, c); err == nil {
		t.Fatal("two owners admitted")
	}
	before := peek(t, q)
	q.Close()
	q = openTest(t, dir, c)
	if q.Stats().Pending != 4 || q.Stats().Loss.Count != 1 || !q.Stats().Degraded {
		t.Fatal(q.Stats())
	}
	after := peek(t, q)
	for i := range before {
		if string(before[i].Window) != string(after[i].Window) {
			t.Fatal("restart changed data")
		}
	}
	if err := q.Ack(after[1:2]); err == nil {
		t.Fatal("non-prefix ACK accepted")
	}
	if err := q.Ack(after[:2]); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Bytes != 2*size {
		t.Fatal("segment not reclaimed", q.Stats())
	}
	appendTest(t, q, "e")
	if got := peek(t, q); len(got) != 3 || got[2].Sequence != 5 {
		t.Fatal(got)
	}
	if err := q.Ack(peek(t, q)); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q = openTest(t, dir, c)
	if q.Stats().Pending != 0 || q.Stats().Bytes != 0 {
		t.Fatal(q.Stats())
	}
	appendTest(t, q, "f")
	if peek(t, q)[0].Sequence != 6 {
		t.Fatal("sequence reused after cleanup")
	}
}
func TestTornTailAndCorruption(t *testing.T) {
	for _, tail := range []int{3, headerSize, headerSize + 5} {
		t.Run(fmt.Sprint(tail), func(t *testing.T) {
			dir := t.TempDir()
			q := openTest(t, dir, DefaultConfig())
			appendTest(t, q, "a")
			appendTest(t, q, "b")
			file := filepath.Join(dir, q.segments[0].name)
			offset := q.entries[1].offset
			q.Close()
			if err := os.Truncate(file, offset+int64(tail)); err != nil {
				t.Fatal(err)
			}
			q = openTest(t, dir, DefaultConfig())
			if q.Stats().Pending != 1 || q.Stats().RecoveredTailBytes != int64(tail) {
				t.Fatal(q.Stats())
			}
			appendTest(t, q, "c")
			if peek(t, q)[1].Sequence != 2 {
				t.Fatal("bad recovered sequence")
			}
		})
	}
	t.Run("checksum", func(t *testing.T) {
		dir := t.TempDir()
		q := openTest(t, dir, DefaultConfig())
		appendTest(t, q, "a")
		file := filepath.Join(dir, q.segments[0].name)
		q.Close()
		data, _ := os.ReadFile(file)
		data[len(data)-2] ^= 1
		os.WriteFile(file, data, 0600)
		if _, err := Open(dir, DefaultConfig()); err == nil {
			t.Fatal("corruption silently discarded")
		}
		got, _ := os.ReadFile(file)
		if len(got) != len(data) {
			t.Fatal("corrupt evidence truncated")
		}
	})
	t.Run("checkpoint", func(t *testing.T) {
		dir := t.TempDir()
		q := openTest(t, dir, DefaultConfig())
		appendTest(t, q, "a")
		q.Ack(peek(t, q))
		q.Close()
		path := filepath.Join(dir, "state.json")
		data, _ := os.ReadFile(path)
		data = []byte(strings.Replace(string(data), `"ack":1`, `"ack":9`, 1))
		os.WriteFile(path, data, 0600)
		if _, err := Open(dir, DefaultConfig()); err == nil {
			t.Fatal("corrupt ACK trusted")
		}
	})
	t.Run("missing segment", func(t *testing.T) {
		dir := t.TempDir()
		size := int64(len(fixture(t, "a")) + headerSize)
		c := Config{4 * size, 2 * size, MaxRecord}
		q := openTest(t, dir, c)
		for _, id := range []string{"a", "b", "c"} {
			appendTest(t, q, id)
		}
		name := q.segments[0].name
		q.Close()
		os.Remove(filepath.Join(dir, name))
		if _, err := Open(dir, c); err == nil {
			t.Fatal("missing unacknowledged prefix accepted")
		}
	})
}
func TestQuarantineSurvivesRestartAndDoesNotAckNeighbors(t *testing.T) {
	dir := t.TempDir()
	q := openTest(t, dir, DefaultConfig())
	for _, id := range []string{"a", "b", "c"} {
		appendTest(t, q, id)
	}
	items := peek(t, q)
	if err := q.Reject(items[1], "invalid window"); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q = openTest(t, dir, DefaultConfig())
	items = peek(t, q)
	if len(items) != 2 || items[0].EventID != "a" || items[1].EventID != "c" {
		t.Fatal(items)
	}
	if err := q.Ack(items[:1]); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Pending != 1 {
		t.Fatal(q.Stats())
	}
	q.config.QuarantineBytes = q.quarantineBytes
	if err := q.Reject(items[1], "full"); err == nil {
		t.Fatal("unbounded quarantine")
	}
	if q.Stats().Pending != 1 {
		t.Fatal("lost rejected record")
	}
	if err := q.Ack(peek(t, q)); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q = openTest(t, dir, DefaultConfig())
	if q.Stats().Pending != 0 || q.Stats().Quarantined != 1 {
		t.Fatal(q.Stats())
	}
}
func TestConcurrentProducerConsumer(t *testing.T) {
	q := openTest(t, t.TempDir(), DefaultConfig())
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 50; i++ {
			if err := q.Append(fixture(t, fmt.Sprint(i))); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	consumed := 0
	deadline := time.Now().Add(10 * time.Second)
	for consumed < 50 && time.Now().Before(deadline) {
		items, err := q.Peek(7, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) > 0 {
			if err = q.Ack(items); err != nil {
				t.Fatal(err)
			}
			consumed += len(items)
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if consumed != 50 || q.Stats().Pending != 0 {
		t.Fatal(consumed, q.Stats())
	}
}
func TestSIGKILLRecovery(t *testing.T) {
	for _, ack := range []string{"0", "1"} {
		t.Run("ack="+ack, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashWriter$")
			cmd.Env = append(os.Environ(), "NETWATCH_TEST_CRASH_DIR="+dir, "NETWATCH_TEST_CRASH_ACK="+ack)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			scanner := bufio.NewScanner(stdout)
			if !scanner.Scan() || scanner.Text() != "durable" {
				t.Fatal("child did not persist data")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			q := openTest(t, dir, DefaultConfig())
			want := 1
			if ack == "1" {
				want = 0
			}
			if q.Stats().Pending != want {
				t.Fatal(q.Stats())
			}
		})
	}
}
func TestCrashWriter(t *testing.T) {
	dir := os.Getenv("NETWATCH_TEST_CRASH_DIR")
	if dir == "" {
		t.Skip("subprocess only")
	}
	q, err := Open(dir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	appendTest(t, q, "crash")
	if os.Getenv("NETWATCH_TEST_CRASH_ACK") == "1" {
		s := q.state
		s.Ack = peek(t, q)[0].Sequence
		if err = q.save(s); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("durable")
	for {
		time.Sleep(time.Hour)
	}
}

func TestQuarantinePreservesNonCanonicalJSON(t *testing.T) {
	dir := t.TempDir()
	q := openTest(t, dir, DefaultConfig())
	appendTest(t, q, "first")
	data := fixture(t, "<noncanonical>")
	var pretty strings.Builder
	// Whitespace and JSON HTML escaping must not change event identity on recovery.
	pretty.WriteString("  ")
	pretty.Write(data)
	pretty.WriteString("  ")
	if err := q.Append([]byte(pretty.String())); err != nil {
		t.Fatal(err)
	}
	if err := q.Reject(peek(t, q)[1], "invalid"); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q = openTest(t, dir, DefaultConfig())
	if q.Stats().Pending != 1 || q.Stats().Quarantined != 1 {
		t.Fatal(q.Stats())
	}
}
func TestRecoveryAllowsGarbageCollectionGapBehindAck(t *testing.T) {
	dir := t.TempDir()
	size := int64(len(fixture(t, "a")) + headerSize)
	c := Config{8 * size, 2 * size, MaxRecord}
	q := openTest(t, dir, c)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		appendTest(t, q, id)
	}
	s := q.state
	s.Ack = 4
	if err := q.save(s); err != nil {
		t.Fatal(err)
	}
	middle := q.segments[1].name
	q.Close()
	if err := os.Remove(filepath.Join(dir, middle)); err != nil {
		t.Fatal(err)
	}
	q = openTest(t, dir, c)
	items := peek(t, q)
	if len(items) != 1 || items[0].EventID != "e" {
		t.Fatal(items)
	}
}
