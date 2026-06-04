package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// spoolMeta is the on-disk metadata for one durable spool_retry item. Each item
// is two files in the queue dir: <id>.json (this struct) + <id>.data (payload).
type spoolMeta struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`   // target name to deliver to
	Attempts    int       `json:"attempts"` // attempts made so far
	FirstSeen   time.Time `json:"first_seen"`
	NextAttempt time.Time `json:"next_attempt"`
	Deadline    time.Time `json:"deadline"` // zero = no TTL
	Host        string    `json:"host,omitempty"`
	User        string    `json:"user,omitempty"`
	JobName     string    `json:"job_name,omitempty"`
	Queue       string    `json:"queue,omitempty"`
}

// spoolStore is a small crash/restart-safe on-disk queue rooted at
// <spoolDir>/forward-retry. Items are removed only on successful delivery;
// give-ups are moved into the dead/ subdir and kept for the operator.
type spoolStore struct {
	dir string // <spoolDir>/forward-retry
	mu  sync.Mutex
	seq int
}

// newSpoolStore creates the queue directory and its dead-letter subdir.
func newSpoolStore(dir string) (*spoolStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "dead"), 0o755); err != nil {
		return nil, err
	}
	return &spoolStore{dir: dir}, nil
}

func (s *spoolStore) jsonPath(id string) string { return filepath.Join(s.dir, id+".json") }
func (s *spoolStore) dataPath(id string) string { return filepath.Join(s.dir, id+".data") }

// put assigns m.ID if empty (monotonic seq + nanos) and writes the payload then
// the metadata. Writing .data first means a torn write never leaves a .json
// referencing a missing payload (an orphan .data is harmless and skipped).
func (s *spoolStore) put(m *spoolMeta, payload []byte) error {
	s.mu.Lock()
	if m.ID == "" {
		s.seq++
		m.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), s.seq)
	}
	s.mu.Unlock()

	if err := writeFileAtomic(s.dataPath(m.ID), payload, 0o600); err != nil {
		return fmt.Errorf("spool put data: %w", err)
	}
	if err := s.writeMeta(m); err != nil {
		return fmt.Errorf("spool put meta: %w", err)
	}
	return nil
}

// update rewrites the metadata file (e.g. after a failed attempt).
func (s *spoolStore) update(m *spoolMeta) error {
	return s.writeMeta(m)
}

func (s *spoolStore) writeMeta(m *spoolMeta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.jsonPath(m.ID), b, 0o600)
}

// remove deletes both files for an item after successful delivery.
func (s *spoolStore) remove(id string) error {
	jerr := os.Remove(s.jsonPath(id))
	derr := os.Remove(s.dataPath(id))
	if jerr != nil && !os.IsNotExist(jerr) {
		return jerr
	}
	if derr != nil && !os.IsNotExist(derr) {
		return derr
	}
	return nil
}

// deadLetter moves both files into dir/dead/ on give-up; they are kept for the
// operator and never auto-deleted.
func (s *spoolStore) deadLetter(id string) error {
	deadDir := filepath.Join(s.dir, "dead")
	if err := os.MkdirAll(deadDir, 0o755); err != nil {
		return err
	}
	jerr := os.Rename(s.jsonPath(id), filepath.Join(deadDir, id+".json"))
	derr := os.Rename(s.dataPath(id), filepath.Join(deadDir, id+".data"))
	if jerr != nil && !os.IsNotExist(jerr) {
		return jerr
	}
	if derr != nil && !os.IsNotExist(derr) {
		return derr
	}
	return nil
}

// load scans the queue dir for *.json items (skipping dead/), parses them, and
// tolerates corrupt or partial pairs (log + skip), never panicking.
func (s *spoolStore) load() ([]*spoolMeta, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []*spoolMeta
	for _, e := range entries {
		if e.IsDir() {
			continue // skips dead/ and any other subdir
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		b, err := os.ReadFile(s.jsonPath(id))
		if err != nil {
			logWarn("fwd", "spool: skipping unreadable %s: %v", name, err)
			continue
		}
		var m spoolMeta
		if err := json.Unmarshal(b, &m); err != nil {
			logWarn("fwd", "spool: skipping corrupt %s: %v", name, err)
			continue
		}
		if m.ID == "" {
			m.ID = id
		}
		// A .json without its .data is unusable; skip (don't replay a job with
		// no payload).
		if _, err := os.Stat(s.dataPath(m.ID)); err != nil {
			logWarn("fwd", "spool: skipping %s: missing payload: %v", name, err)
			continue
		}
		mm := m
		out = append(out, &mm)
	}
	return out, nil
}

// payload reads the raw <id>.data payload for an item.
func (s *spoolStore) payload(id string) ([]byte, error) {
	return os.ReadFile(s.dataPath(id))
}

// writeFileAtomic writes data to a temp file in the same directory then renames
// it into place, so a reader never observes a partially written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
