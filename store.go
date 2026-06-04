package main

import (
	"sort"
	"strings"
	"sync"
)

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

// jobFilter describes a query over the in-memory job ring: free-text search,
// an exact protocol filter, a sort key/direction, and a page window.
type jobFilter struct {
	Q        string // substring match over JobName/User/Host/Source/Protocol (case-insensitive)
	Protocol string // exact protocol filter ("" = all)
	Sort     string // received|bytes|protocol|job_name (default received)
	Desc     bool   // newest/largest first (default true)
	Offset   int
	Limit    int // 0 => default 50
}

// query returns a page of matching jobs (newest-first by default) and the TOTAL
// number that matched (for pagination). Filtering and sorting happen over the
// bounded ring under the read lock.
func (s *jobStore) query(f jobFilter) (page []job, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(strings.TrimSpace(f.Q))
	matched := make([]job, 0, len(s.jobs))
	for _, j := range s.jobs {
		if f.Protocol != "" && j.Protocol != f.Protocol {
			continue
		}
		if q != "" && !jobMatchesText(j, q) {
			continue
		}
		matched = append(matched, j)
	}

	// Sort. "received" is the natural ring order (oldest->newest); we derive it
	// from the job ID, which is monotonic per run.
	sortKey := f.Sort
	if sortKey == "" {
		sortKey = "received"
	}
	less := func(a, b job) bool {
		switch sortKey {
		case "bytes":
			if a.Bytes != b.Bytes {
				return a.Bytes < b.Bytes
			}
		case "protocol":
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
		case "job_name":
			an, bn := strings.ToLower(a.JobName), strings.ToLower(b.JobName)
			if an != bn {
				return an < bn
			}
		}
		// Tie-break (and default "received") by ID, which is monotonic.
		return a.ID < b.ID
	}
	sort.SliceStable(matched, func(i, j int) bool { return less(matched[i], matched[j]) })
	if f.Desc {
		for i, j := 0, len(matched)-1; i < j; i, j = i+1, j-1 {
			matched[i], matched[j] = matched[j], matched[i]
		}
	}

	total = len(matched)
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	off := f.Offset
	if off < 0 {
		off = 0
	}
	if off > total {
		off = total
	}
	end := off + limit
	if end > total {
		end = total
	}
	page = append([]job(nil), matched[off:end]...)
	return page, total
}

// jobMatchesText reports whether q (already lowercased) is a substring of any of
// the job's searchable text fields.
func jobMatchesText(j job, q string) bool {
	for _, f := range []string{j.JobName, j.User, j.Host, j.Source, j.Protocol} {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

// remove drops a job from the ring and returns it (for file cleanup). ok=false
// if absent. Counters are intentionally left unchanged: total/bytes reflect what
// was captured this run, not what currently remains in the ring.
func (s *jobStore) remove(id int) (job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, j := range s.jobs {
		if j.ID == id {
			s.jobs = append(s.jobs[:i], s.jobs[i+1:]...)
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
