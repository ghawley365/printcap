package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func itoa(n int) string { return strconv.Itoa(n) }

// serveAutoTLS handles a single listener that may receive *either* plaintext
// IPP or TLS. It peeks the first byte without consuming it: 0x16 is the TLS
// record type for a ClientHello (a Handshake record), anything else is treated
// as plaintext HTTP/IPP. This lets one port behave as both IPP and IPPS. The
// loop exits when the Engine closes the listener.
func serveAutoTLS(ln net.Listener, tlsCfg *tls.Config) {
	plainSrv := hardenedServer("", http.HandlerFunc(ippHandler))
	tlsSrv := hardenedServer("", http.HandlerFunc(ippHandler))
	tlsSrv.TLSConfig = tlsCfg

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			// Bound the sniff so a client that connects and sends nothing can't
			// pin this goroutine; then hand control of the deadline to the
			// HTTP server's own timeouts.
			_ = c.SetReadDeadline(time.Now().Add(httpReadHeaderTimeout))
			br := bufio.NewReader(c)
			first, err := br.Peek(1)
			_ = c.SetReadDeadline(time.Time{})
			if err != nil {
				c.Close()
				return
			}
			pc := &peekConn{Conn: c, r: br}
			if first[0] == 0x16 { // TLS Handshake record
				serveOneHTTP(tls.Server(pc, tlsCfg), tlsSrv)
			} else {
				serveOneHTTP(pc, plainSrv)
			}
		}(conn)
	}
}

// serveOneHTTP drives the standard library's HTTP server over a single
// already-accepted connection by handing it a one-shot listener. Serve returns
// (with errOneShotDone) as soon as it asks for a second connection, so the
// Serve goroutine doesn't leak; the in-flight request keeps being handled.
func serveOneHTTP(c net.Conn, srv *http.Server) {
	_ = srv.Serve(&oneShotListener{c: c})
}

// peekConn lets us look at the first byte of a connection (to sniff TLS) and
// then replay it for whichever server takes over.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// errOneShotDone tells http.Server.Serve to stop after the single connection.
var errOneShotDone = errors.New("one-shot listener exhausted")

// oneShotListener returns its single connection once, then errors so the
// http.Server.Serve loop exits cleanly (no leaked goroutine). The in-flight
// connection was already handed to its own serve goroutine and is unaffected.
type oneShotListener struct {
	c    net.Conn
	done bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, errOneShotDone
	}
	l.done = true
	return l.c, nil
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.c.LocalAddr() }

// tlsConfig loads the supplied cert/key, or mints a self-signed one.
func tlsConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	} else {
		cert, err = selfSignedCert()
	}
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// genSelfSigned builds a fresh ECDSA self-signed certificate (DER) and its key.
func genSelfSigned() ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cfg.Printer.Name, Organization: []string{"printcap"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"printcap", "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

// selfSignedCert generates an in-memory ECDSA self-signed certificate.
func selfSignedCert() (tls.Certificate, error) {
	der, key, err := genSelfSigned()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// writeSelfSignedCertFiles writes a new self-signed cert and key as PEM files,
// for operators who want a persistent IPPS certificate they can also import
// into clients. Returns the paths actually written.
func writeSelfSignedCertFiles(certPath, keyPath string) error {
	der, key, err := genSelfSigned()
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}
