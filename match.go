package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

// ForwardCond is the JSON-configurable condition used by both forward rules
// (Task 7) and transform steps (Task 2). All populated fields are ANDed
// together; an empty condition matches every job. It is defined here so this
// package builds and tests standalone; Task 7 reuses this definition.
type ForwardCond struct {
	Protocols   []string `json:"protocols"`
	SourceCIDRs []string `json:"source_cidrs"`
	Users       []string `json:"users"`
	Hosts       []string `json:"hosts"`
	JobName     string   `json:"job_name"`
	Queues      []string `json:"queues"`
	DocFormats  []string `json:"doc_formats"`
	PDLs        []string `json:"pdls"`
	Contains    string   `json:"contains"`
	MinBytes    int      `json:"min_bytes"`
	MaxBytes    int      `json:"max_bytes"`
}

// compiledCond is the precompiled, ready-to-evaluate form of a ForwardCond.
type compiledCond struct {
	protocols  []string
	cidrs      []*net.IPNet
	users      []string
	hosts      []string
	jobName    *textMatcher
	queues     []string
	docFormats []string
	pdls       []string
	contains   *bytesMatcher
	minBytes   int
	maxBytes   int
	empty      bool
}

// textMatcher matches a string value either by shell glob or by regexp.
// A pattern wrapped in /.../ is a regexp; otherwise it is a glob.
type textMatcher struct {
	glob string
	re   *regexp.Regexp
}

func (m *textMatcher) match(s string) bool {
	if m == nil {
		return true
	}
	if m.re != nil {
		return m.re.MatchString(s)
	}
	ok, err := filepath.Match(m.glob, s)
	return err == nil && ok
}

// bytesMatcher matches a byte payload. A /.../ pattern is a regexp; a
// "hex:.." pattern is decoded to literal bytes; anything else is a literal
// substring (case-insensitive).
type bytesMatcher struct {
	lit []byte
	re  *regexp.Regexp
}

func (m *bytesMatcher) match(data []byte) bool {
	if m == nil {
		return true
	}
	if m.re != nil {
		return m.re.Match(data)
	}
	return bytesContains(data, m.lit)
}

// bytesContains reports whether data contains needle, comparing ASCII letters
// case-insensitively.
func bytesContains(data, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(data) {
		return false
	}
	for i := 0; i+len(needle) <= len(data); i++ {
		if containsFold(data[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func compileTextMatcher(pat string) (*textMatcher, error) {
	if pat == "" {
		return nil, nil
	}
	if len(pat) >= 2 && strings.HasPrefix(pat, "/") && strings.HasSuffix(pat, "/") {
		re, err := regexp.Compile(pat[1 : len(pat)-1])
		if err != nil {
			return nil, fmt.Errorf("job_name regex: %w", err)
		}
		return &textMatcher{re: re}, nil
	}
	return &textMatcher{glob: pat}, nil
}

func compileBytesMatcher(pat string) (*bytesMatcher, error) {
	if pat == "" {
		return nil, nil
	}
	if len(pat) >= 2 && strings.HasPrefix(pat, "/") && strings.HasSuffix(pat, "/") {
		re, err := regexp.Compile(pat[1 : len(pat)-1])
		if err != nil {
			return nil, fmt.Errorf("contains regex: %w", err)
		}
		return &bytesMatcher{re: re}, nil
	}
	if strings.HasPrefix(pat, "hex:") {
		b, err := hex.DecodeString(pat[len("hex:"):])
		if err != nil {
			return nil, fmt.Errorf("contains hex: %w", err)
		}
		return &bytesMatcher{lit: b}, nil
	}
	return &bytesMatcher{lit: []byte(pat)}, nil
}

// compileCond precompiles c into a compiledCond, returning an error if any
// CIDR or pattern is malformed.
func compileCond(c ForwardCond) (*compiledCond, error) {
	cc := &compiledCond{
		protocols:  c.Protocols,
		users:      c.Users,
		hosts:      c.Hosts,
		queues:     c.Queues,
		docFormats: c.DocFormats,
		pdls:       c.PDLs,
		minBytes:   c.MinBytes,
		maxBytes:   c.MaxBytes,
	}
	for _, s := range c.SourceCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("source_cidr %q: %w", s, err)
		}
		cc.cidrs = append(cc.cidrs, n)
	}
	jm, err := compileTextMatcher(c.JobName)
	if err != nil {
		return nil, err
	}
	cc.jobName = jm
	bm, err := compileBytesMatcher(c.Contains)
	if err != nil {
		return nil, err
	}
	cc.contains = bm

	cc.empty = len(cc.protocols) == 0 &&
		len(cc.cidrs) == 0 &&
		len(cc.users) == 0 &&
		len(cc.hosts) == 0 &&
		cc.jobName == nil &&
		len(cc.queues) == 0 &&
		len(cc.docFormats) == 0 &&
		len(cc.pdls) == 0 &&
		cc.contains == nil &&
		cc.minBytes == 0 &&
		cc.maxBytes == 0
	return cc, nil
}

// matches reports whether the job (and its payload) satisfies every populated
// field of the condition. An empty condition always matches.
func (c *compiledCond) matches(j *job, data []byte) bool {
	if c == nil || c.empty {
		return true
	}
	if len(c.protocols) > 0 && !containsFoldList(c.protocols, j.Protocol) {
		return false
	}
	if len(c.cidrs) > 0 && !cidrMatch(c.cidrs, j.Source) {
		return false
	}
	if len(c.users) > 0 && !containsFoldList(c.users, j.User) {
		return false
	}
	if len(c.hosts) > 0 && !containsFoldList(c.hosts, j.Host) {
		return false
	}
	if c.jobName != nil && !c.jobName.match(j.JobName) {
		return false
	}
	if len(c.queues) > 0 && !containsFoldList(c.queues, j.Queue) {
		return false
	}
	if len(c.docFormats) > 0 && !containsFoldList(c.docFormats, j.DocFormat) {
		return false
	}
	if len(c.pdls) > 0 && !containsFoldList(c.pdls, j.PDL) {
		return false
	}
	if c.contains != nil && !c.contains.match(data) {
		return false
	}
	if c.minBytes > 0 && len(data) < c.minBytes {
		return false
	}
	if c.maxBytes > 0 && len(data) > c.maxBytes {
		return false
	}
	return true
}

// containsFoldList reports whether want equals any element of list, comparing
// case-insensitively.
func containsFoldList(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// containsFold reports whether a and b are equal as ASCII case-insensitive
// byte slices of the same length.
func containsFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// cidrMatch reports whether the IP portion of src (host or host:port) falls
// within any of the given networks.
func cidrMatch(nets []*net.IPNet, src string) bool {
	host := src
	if h, _, err := net.SplitHostPort(src); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
