package main

import (
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
