package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func sampleAddrs() svcAddrs {
	return svcAddrs{host: "printcap.local", v4: []net.IP{net.IPv4(192, 168, 1, 50)}}
}

func TestAnswersForBrowsePTR(t *testing.T) {
	svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631,
		txt: []string{"txtvers=1"}, subtypes: []string{"_universal"}}}
	recs := answersFor(dnsQuestion{name: "_ipp._tcp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
	if !hasRecord(recs, "_ipp._tcp.local", dnsTypePTR) {
		t.Fatalf("expected browse PTR, got %v", recNames(recs))
	}
	if !hasRecord(recs, "printcap._ipp._tcp.local", dnsTypeSRV) {
		t.Error("expected SRV bundled")
	}
	if !hasRecord(recs, "printcap._ipp._tcp.local", dnsTypeTXT) {
		t.Error("expected TXT bundled")
	}
	if !hasRecord(recs, "printcap.local", dnsTypeA) {
		t.Error("expected A bundled")
	}
}

func TestAnswersForSubtypePTR(t *testing.T) {
	svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631,
		txt: []string{"txtvers=1"}, subtypes: []string{"_universal"}}}
	recs := answersFor(dnsQuestion{name: "_universal._sub._ipp._tcp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
	if !hasRecord(recs, "_universal._sub._ipp._tcp.local", dnsTypePTR) {
		t.Fatalf("expected sub-type PTR, got %v", recNames(recs))
	}
}

func TestAnswersForServiceEnumeration(t *testing.T) {
	svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631, txt: []string{"txtvers=1"}}}
	recs := answersFor(dnsQuestion{name: "_services._dns-sd._udp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
	if !hasRecord(recs, "_services._dns-sd._udp.local", dnsTypePTR) {
		t.Fatalf("expected meta-query PTR, got %v", recNames(recs))
	}
}

func TestAnswersForUnrelatedQuestionEmpty(t *testing.T) {
	svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631, txt: []string{"txtvers=1"}}}
	recs := answersFor(dnsQuestion{name: "_afpovertcp._tcp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
	if len(recs) != 0 {
		t.Fatalf("expected no records, got %v", recNames(recs))
	}
}

func TestUniqueInstance(t *testing.T) {
	if got := uniqueInstance("printcap", map[string]bool{}); got != "printcap" {
		t.Fatalf("free name should be unchanged, got %q", got)
	}
	taken := map[string]bool{"printcap": true}
	if got := uniqueInstance("printcap", taken); got != "printcap (2)" {
		t.Fatalf("got %q, want %q", got, "printcap (2)")
	}
	taken["printcap (2)"] = true
	taken["printcap (3)"] = true
	if got := uniqueInstance("printcap", taken); got != "printcap (4)" {
		t.Fatalf("got %q, want %q", got, "printcap (4)")
	}
}

func TestKnownAnswerSuppression(t *testing.T) {
	svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631,
		txt: []string{"txtvers=1"}}}
	addrs := sampleAddrs()

	// Build a browse query whose answer section already carries the browse PTR
	// the querier knows (RFC 6762 §7.1). buildQuery writes the 12-byte header +
	// one question; we append an answer record and bump ancount.
	ptr := dnsRecord{name: "_ipp._tcp.local", rtype: dnsTypePTR, ttl: ttlDNSSD,
		data: rdataPTR("printcap._ipp._tcp.local")}
	msg := buildQuery("_ipp._tcp.local", dnsTypePTR, false)
	binary.BigEndian.PutUint16(msg[6:], 1) // ancount = 1
	msg = append(msg, encodeRR(ptr)...)

	known := knownAnswers(msg)
	if !hasRecord(known, "_ipp._tcp.local", dnsTypePTR) {
		t.Fatalf("knownAnswers should return the browse PTR, got %v", recNames(known))
	}

	// answersFor would normally bundle PTR + SRV + TXT + A. Filtering through
	// recordKnown must drop the duplicate PTR but keep the rest.
	recs := answersFor(dnsQuestion{name: "_ipp._tcp.local", qtype: dnsTypePTR}, svcs, addrs)
	var kept []dnsRecord
	for _, rec := range recs {
		if !recordKnown(rec, known) {
			kept = append(kept, rec)
		}
	}
	if hasRecord(kept, "_ipp._tcp.local", dnsTypePTR) {
		t.Error("duplicate browse PTR should have been suppressed")
	}
	if !hasRecord(kept, "printcap._ipp._tcp.local", dnsTypeSRV) {
		t.Error("SRV should be kept")
	}
	if !hasRecord(kept, "printcap._ipp._tcp.local", dnsTypeTXT) {
		t.Error("TXT should be kept")
	}
	if !hasRecord(kept, "printcap.local", dnsTypeA) {
		t.Error("A should be kept")
	}
}

func hasRecord(recs []dnsRecord, name string, rtype uint16) bool {
	for _, r := range recs {
		if r.name == name && r.rtype == rtype {
			return true
		}
	}
	return false
}

func recNames(recs []dnsRecord) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r.name)
	}
	return out
}
