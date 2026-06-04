package main

import (
	"encoding/xml"
	"strings"
	"sync"
)

// WSPrint (wprt) request wsa:Action values dispatched by wsprintHandle.
const (
	actGetPrinterElements = nsWdpPrint + "/GetPrinterElementsRequest"
	actCreatePrintJob     = nsWdpPrint + "/CreatePrintJobRequest"
	actSendDocument       = nsWdpPrint + "/SendDocumentRequest"
	actGetJobElements     = nsWdpPrint + "/GetJobElementsRequest"

	actGetPrinterElementsResp = nsWdpPrint + "/GetPrinterElementsResponse"
	actCreatePrintJobResp     = nsWdpPrint + "/CreatePrintJobResponse"
	actSendDocumentResp       = nsWdpPrint + "/SendDocumentResponse"
	actGetJobElementsResp     = nsWdpPrint + "/GetJobElementsResponse"
)

// wprtNS is the namespace declaration placed on WSPrint response body elements
// (buildSOAP only declares s/a on the Envelope).
const wprtNS = ` xmlns:wprt="` + nsWdpPrint + `"`

// wsdCaptureJob is the seam used to persist a finished WSD job. Tests override it
// to capture without touching disk.
var wsdCaptureJob = func(j *job) error { return sink.save(j) }

// maxPendingWSDJobs caps the CreatePrintJob→SendDocument correlation map so a
// client that opens jobs without ever sending a document cannot grow it without
// bound. Each entry is only a few small strings; this is a generous ceiling.
const maxPendingWSDJobs = 256

// wsdPendingJob holds the metadata supplied by a CreatePrintJob until the
// matching SendDocument arrives with the document bytes.
type wsdPendingJob struct {
	jobName, user, format string
}

var (
	wsdMu      sync.Mutex
	wsdJobs    = map[int]*wsdPendingJob{}
	wsdNextJob = 0
)

// wsprintHandle is the single dispatch entry for WSPrint (wprt) operations. It
// switches on the WS-Addressing Action, correlates CreatePrintJob -> SendDocument
// by JobId, extracts the MTOM attachment, and captures the job. It never panics
// on malformed input; unknown actions return handled=false so the caller can
// emit ActionNotSupported.
func wsprintHandle(env soapEnvelope, parts map[string][]byte, source string) (resp []byte, handled bool) {
	switch env.Action {
	case actGetPrinterElements:
		return wsprintGetPrinterElements(env), true
	case actCreatePrintJob:
		return wsprintCreatePrintJob(env), true
	case actSendDocument:
		return wsprintSendDocument(env, parts, source), true
	case actGetJobElements:
		return wsprintGetJobElements(env), true
	default:
		return nil, false
	}
}

func wsprintGetPrinterElements(env soapEnvelope) []byte {
	name := cfg.Printer.Name
	if strings.TrimSpace(name) == "" {
		name = "printcap"
	}
	var b strings.Builder
	b.WriteString(`<wprt:GetPrinterElementsResponse` + wprtNS + `>`)
	b.WriteString(`<wprt:PrinterElements><wprt:ElementData Name="wprt:PrinterDescription">`)
	b.WriteString(`<wprt:PrinterDescription><wprt:PrinterName>` + xmlEsc(name) + `</wprt:PrinterName></wprt:PrinterDescription>`)
	b.WriteString(`</wprt:ElementData></wprt:PrinterElements>`)
	b.WriteString(`</wprt:GetPrinterElementsResponse>`)
	return buildSOAP(soapEnvelope{
		Action:    actGetPrinterElementsResp,
		MessageID: wsdMessageID(),
		To:        addrAnonymous,
		RelatesTo: env.MessageID,
		BodyXML:   []byte(b.String()),
	})
}

// cpjRequest is a lenient unmarshal target for CreatePrintJobRequest. Tags use
// local names only, so namespace prefixes are ignored.
type cpjRequest struct {
	JobName string `xml:"PrintJobDescription>JobName"`
	User    string `xml:"PrintJobDescription>JobOriginatingUserName"`
	Format  string `xml:"DocumentDescriptionList>DocumentDescription>Format"`
}

func wsprintCreatePrintJob(env soapEnvelope) []byte {
	var req cpjRequest
	// Ignore parse errors: missing/garbled fields just yield empty strings.
	_ = xml.Unmarshal(env.BodyXML, &req)

	wsdMu.Lock()
	// Bound the pending-job map: a client that opens jobs (CreatePrintJob)
	// without ever sending the document (SendDocument, which deletes the entry)
	// would otherwise grow the map without limit. Evict the oldest pending jobs
	// (lowest IDs — wsdNextJob is monotonic) once we exceed the cap.
	for len(wsdJobs) >= maxPendingWSDJobs {
		oldest := 0
		for id := range wsdJobs {
			if oldest == 0 || id < oldest {
				oldest = id
			}
		}
		delete(wsdJobs, oldest)
	}
	wsdNextJob++
	jobID := wsdNextJob
	wsdJobs[jobID] = &wsdPendingJob{
		jobName: strings.TrimSpace(req.JobName),
		user:    strings.TrimSpace(req.User),
		format:  strings.TrimSpace(req.Format),
	}
	wsdMu.Unlock()

	logInfo("WSD", "CreatePrintJob id=%d job=%q user=%q format=%q", jobID, req.JobName, req.User, req.Format)

	var b strings.Builder
	b.WriteString(`<wprt:CreatePrintJobResponse` + wprtNS + `>`)
	b.WriteString(`<wprt:JobId>` + itoa(jobID) + `</wprt:JobId>`)
	b.WriteString(`</wprt:CreatePrintJobResponse>`)
	return buildSOAP(soapEnvelope{
		Action:    actCreatePrintJobResp,
		MessageID: wsdMessageID(),
		To:        addrAnonymous,
		RelatesTo: env.MessageID,
		BodyXML:   []byte(b.String()),
	})
}

// sdRequest is a lenient unmarshal target for SendDocumentRequest. The
// xop:Include href is captured to resolve the MTOM attachment CID.
type sdRequest struct {
	JobID   string `xml:"JobId"`
	Include struct {
		Href string `xml:"href,attr"`
	} `xml:"Document>Include"`
}

func wsprintSendDocument(env soapEnvelope, parts map[string][]byte, source string) []byte {
	var req sdRequest
	_ = xml.Unmarshal(env.BodyXML, &req)

	jobID := atoiSafe(strings.TrimSpace(req.JobID))

	// Resolve the document bytes from the MTOM parts by CID.
	cid := strings.TrimPrefix(strings.TrimSpace(req.Include.Href), "cid:")
	var docBytes []byte
	if d, ok := parts[cid]; ok {
		docBytes = d
	} else if len(parts) == 1 {
		// Fall back to the sole attachment if the exact CID is absent.
		for _, d := range parts {
			docBytes = d
		}
	}

	// Look up (and consume) the pending job; default to empty if unknown.
	wsdMu.Lock()
	pj := wsdJobs[jobID]
	delete(wsdJobs, jobID)
	wsdMu.Unlock()
	if pj == nil {
		pj = &wsdPendingJob{}
	}

	j := newJob("WSD", source)
	j.JobName = pj.jobName
	j.User = pj.user
	j.DocFormat = pj.format
	j.data = docBytes
	j.Bytes = len(docBytes)
	if err := wsdCaptureJob(j); err != nil {
		logWarn("WSD", "SendDocument capture id=%d: %v", jobID, err)
	}

	var b strings.Builder
	b.WriteString(`<wprt:SendDocumentResponse` + wprtNS + `>`)
	b.WriteString(`<wprt:JobId>` + itoa(jobID) + `</wprt:JobId>`)
	b.WriteString(`</wprt:SendDocumentResponse>`)
	return buildSOAP(soapEnvelope{
		Action:    actSendDocumentResp,
		MessageID: wsdMessageID(),
		To:        addrAnonymous,
		RelatesTo: env.MessageID,
		BodyXML:   []byte(b.String()),
	})
}

func wsprintGetJobElements(env soapEnvelope) []byte {
	var b strings.Builder
	b.WriteString(`<wprt:GetJobElementsResponse` + wprtNS + `>`)
	b.WriteString(`<wprt:JobElements><wprt:ElementData Name="wprt:JobStatus">`)
	b.WriteString(`<wprt:JobStatus><wprt:JobState>Completed</wprt:JobState></wprt:JobStatus>`)
	b.WriteString(`</wprt:ElementData></wprt:JobElements>`)
	b.WriteString(`</wprt:GetJobElementsResponse>`)
	return buildSOAP(soapEnvelope{
		Action:    actGetJobElementsResp,
		MessageID: wsdMessageID(),
		To:        addrAnonymous,
		RelatesTo: env.MessageID,
		BodyXML:   []byte(b.String()),
	})
}

// atoiSafe parses a non-negative integer, returning 0 on any malformed input.
func atoiSafe(s string) int {
	n := 0
	if s == "" {
		return 0
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
