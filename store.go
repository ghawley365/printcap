package main

import "sync"

// jobStore keeps the most recent captured jobs in memory (a bounded ring) plus
// running counters, so the dashboard can render without re-reading the disk.
// Raw document bytes are NOT held here — downloads stream from the saved file.
type jobStore struct {
	mu      sync.RWMutex
	max     int
	jobs    []job          // newest last
	total   int            // jobs captured this run
	bytes   int64          // total bytes captured
	byProto map[string]int // per-protocol counts
}

func newJobStore(max int) *jobStore {
	return &jobStore{max: max, byProto: map[string]int{}}
}

func (s *jobStore) add(j *job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *j
	clone.data = nil // never retain payloads in memory
	s.jobs = append(s.jobs, clone)
	if len(s.jobs) > s.max {
		s.jobs = s.jobs[len(s.jobs)-s.max:]
	}
	s.total++
	s.bytes += int64(j.Bytes)
	s.byProto[j.Protocol]++
}

// recent returns up to n jobs, newest first.
func (s *jobStore) recent(n int) []job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]job, 0, len(s.jobs))
	for i := len(s.jobs) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, s.jobs[i])
	}
	return out
}

func (s *jobStore) get(id int) (job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, j := range s.jobs {
		if j.ID == id {
			return j, true
		}
	}
	return job{}, false
}

type storeStats struct {
	Total   int            `json:"total"`
	Bytes   int64          `json:"bytes"`
	ByProto map[string]int `json:"by_protocol"`
}

func (s *jobStore) stats() storeStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bp := make(map[string]int, len(s.byProto))
	for k, v := range s.byProto {
		bp[k] = v
	}
	return storeStats{Total: s.total, Bytes: s.bytes, ByProto: bp}
}
