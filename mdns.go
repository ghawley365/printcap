package main

import "net"

// temporary: removed in the responder runtime sub-task once *net.UDPConn is used
// directly. The pure answer-selection helpers below reference net only through
// svcAddrs, so without this the import would be unused at this stage.
var _ = net.IPv4

const (
	mdnsAddr4 = "224.0.0.251:5353"
	mdnsAddr6 = "[ff02::fb]:5353"
	metaQuery = "_services._dns-sd._udp.local"
)

// srvAndTxt returns the SRV, TXT, and host A/AAAA records for one service.
func srvAndTxt(s service, a svcAddrs) []dnsRecord {
	recs := []dnsRecord{
		{name: s.instanceName(), rtype: dnsTypeSRV, ttl: ttlDNSSD, flush: true,
			data: rdataSRV(0, 0, s.port, a.host)},
		{name: s.instanceName(), rtype: dnsTypeTXT, ttl: ttlDNSSD, flush: true,
			data: rdataTXT(s.txt)},
	}
	recs = append(recs, hostRecords(a)...)
	return recs
}

func hostRecords(a svcAddrs) []dnsRecord {
	var recs []dnsRecord
	for _, ip := range a.v4 {
		recs = append(recs, dnsRecord{name: a.host, rtype: dnsTypeA, ttl: ttlHost, flush: true, data: rdataA(ip)})
	}
	for _, ip := range a.v6 {
		recs = append(recs, dnsRecord{name: a.host, rtype: dnsTypeAAAA, ttl: ttlHost, flush: true, data: rdataAAAA(ip)})
	}
	return recs
}

// answersFor returns the records that answer one question, or nil if the
// question targets nothing we advertise.
func answersFor(q dnsQuestion, svcs []service, a svcAddrs) []dnsRecord {
	var out []dnsRecord
	matchesType := func(want uint16) bool { return q.qtype == want || q.qtype == dnsTypeANY }

	if q.name == metaQuery && matchesType(dnsTypePTR) {
		for _, s := range svcs {
			out = append(out, dnsRecord{name: metaQuery, rtype: dnsTypePTR, ttl: ttlDNSSD,
				data: rdataPTR(s.browseName())})
		}
		return out
	}

	for _, s := range svcs {
		switch {
		case q.name == s.browseName() && matchesType(dnsTypePTR):
			out = append(out, dnsRecord{name: s.browseName(), rtype: dnsTypePTR, ttl: ttlDNSSD,
				data: rdataPTR(s.instanceName())})
			out = append(out, srvAndTxt(s, a)...)
		case q.name == s.instanceName() && matchesType(dnsTypeSRV):
			out = append(out, srvAndTxt(s, a)...)
		case q.name == s.instanceName() && matchesType(dnsTypeTXT):
			out = append(out, dnsRecord{name: s.instanceName(), rtype: dnsTypeTXT, ttl: ttlDNSSD,
				flush: true, data: rdataTXT(s.txt)})
		case q.name == a.host && (matchesType(dnsTypeA) || matchesType(dnsTypeAAAA)):
			out = append(out, hostRecords(a)...)
		}
		for _, sub := range s.subtypes {
			subName := sub + "._sub." + s.svcType + ".local"
			if q.name == subName && matchesType(dnsTypePTR) {
				out = append(out, dnsRecord{name: subName, rtype: dnsTypePTR, ttl: ttlDNSSD,
					data: rdataPTR(s.instanceName())})
			}
		}
	}
	return out
}
