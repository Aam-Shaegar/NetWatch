package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

func checksum(head, data []byte) uint32 {
	h := crc32.NewIEEE()
	h.Write(head[:16])
	h.Write(data)
	return h.Sum32()
}
func (q *Queue) save(s state) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	data, err = seal(data)
	if err != nil {
		return err
	}
	return atomicFile(q.dir, "state.json", data)
}
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func atomicFile(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}
func durableMkdir(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("spool path is not a directory")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(filepath.Clean(dir))
	if err = durableMkdir(parent); err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return syncDir(parent)
}

type envelope struct {
	Payload json.RawMessage `json:"payload"`
	CRC32   uint32          `json:"crc32"`
}

func seal(data []byte) ([]byte, error) { return json.Marshal(envelope{data, crc32.ChecksumIEEE(data)}) }
func readSealed(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 6*MaxRecord+8193))
	if err != nil {
		return nil, err
	}
	if len(data) > 6*MaxRecord+8192 {
		return nil, fmt.Errorf("oversized spool metadata")
	}
	var saved envelope
	if err = json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}
	if len(saved.Payload) == 0 || crc32.ChecksumIEEE(saved.Payload) != saved.CRC32 {
		return nil, fmt.Errorf("spool metadata checksum mismatch")
	}
	return saved.Payload, nil
}
