package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Leveled, multi-sink logging. One Logger formats each event once and fans it
// out to: the console, a rotating text file, an optional rotating JSON-lines
// file (for file-tailing SIEM shippers), an optional remote syslog server (for
// network collectors), an in-memory ring (for the dashboard), and an optional
// system sink (Windows Event Log when running as a service).

type Level int32

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

var levelNames = []string{"ERROR", "WARN", "INFO", "DEBUG", "TRACE"}

func (l Level) String() string {
	if int(l) >= 0 && int(l) < len(levelNames) {
		return levelNames[l]
	}
	return "?"
}

func parseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error", "err":
		return LevelError
	case "warn", "warning":
		return LevelWarn
	case "debug":
		return LevelDebug
	case "trace", "verbose":
		return LevelTrace
	default:
		return LevelInfo
	}
}

// logEntry is one structured log record (also serialized for the dashboard and
// the JSON-lines sink).
type logEntry struct {
	Time      string `json:"time"`
	Level     string `json:"level"`
	Component string `json:"component"`
	Message   string `json:"message"`
}

// fileSink is an append-only log file with size-based rotation.
type fileSink struct {
	path      string
	f         *os.File
	size      int64
	maxSize   int64
	maxBackup int
}

func newFileSink(path string, maxSizeMB, maxBackup int) *fileSink {
	fs := &fileSink{
		path:      path,
		maxSize:   int64(maxSizeMB) * 1024 * 1024,
		maxBackup: maxBackup,
	}
	if fs.maxSize <= 0 {
		fs.maxSize = 10 * 1024 * 1024
	}
	if fs.maxBackup <= 0 {
		fs.maxBackup = 5
	}
	fs.open()
	return fs
}

func (fs *fileSink) open() {
	if fs.path == "" {
		return
	}
	f, err := os.OpenFile(fs.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	if st, err := f.Stat(); err == nil {
		fs.size = st.Size()
	}
	fs.f = f
}

func (fs *fileSink) write(line string) {
	if fs.f == nil {
		return
	}
	if fs.maxSize > 0 && fs.size+int64(len(line)) > fs.maxSize {
		fs.rotate()
	}
	if fs.f != nil {
		if n, err := fs.f.WriteString(line); err == nil {
			fs.size += int64(n)
		}
	}
}

func (fs *fileSink) rotate() {
	if fs.f != nil {
		fs.f.Close()
		fs.f = nil
	}
	os.Remove(fmt.Sprintf("%s.%d", fs.path, fs.maxBackup))
	for i := fs.maxBackup - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", fs.path, i), fmt.Sprintf("%s.%d", fs.path, i+1))
	}
	os.Rename(fs.path, fs.path+".1")
	if f, err := os.OpenFile(fs.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		fs.f = f
		fs.size = 0
	}
}

func (fs *fileSink) close() {
	if fs != nil && fs.f != nil {
		fs.f.Close()
		fs.f = nil
	}
}

// Logger fans a record out to all enabled sinks.
type Logger struct {
	mu sync.Mutex

	level      Level
	console    bool
	jsonFormat bool // render the primary text file + console as JSON

	text     *fileSink // primary log file
	jsonFile *fileSink // optional separate JSON-lines file

	ring    []logEntry
	ringMax int

	sysSink func(Level, string) // optional (Windows Event Log)
	syslog  *syslogSink         // optional remote syslog
}

// The global logger starts at Trace so anything emitted before configureLogging
// runs (very early startup) is captured. configureLogging then applies cfg.Log
// (also Trace by default — see defaultConfig) plus any -v/-loglevel overrides.
var logger = &Logger{level: LevelTrace, console: true, ringMax: 2000}

// configureLogging (re)builds the global logger from cfg.Log plus verbose flag
// overrides. It is safe to call again (the GUI calls it on save): existing
// sinks are closed first.
func configureLogging() {
	lc := cfg.Log
	lvl := parseLevel(lc.Level)
	if optVerbose == 1 {
		lvl = LevelDebug
	} else if optVerbose >= 2 {
		lvl = LevelTrace
	}
	if optLogLevel != "" {
		lvl = parseLevel(optLogLevel)
	}

	textPath := lc.File
	if textPath == "" {
		textPath = defaultLogPath()
	}

	logger.mu.Lock()
	// Close any previously-open sinks.
	logger.text.close()
	logger.jsonFile.close()
	if logger.syslog != nil {
		logger.syslog.close()
		logger.syslog = nil
	}

	logger.level = lvl
	logger.console = lc.Console
	logger.jsonFormat = strings.EqualFold(lc.Format, "json")
	logger.ringMax = 2000
	logger.text = newFileSink(textPath, lc.MaxSizeMB, lc.MaxBackups)
	if lc.JSONFile != "" {
		logger.jsonFile = newFileSink(lc.JSONFile, lc.MaxSizeMB, lc.MaxBackups)
	} else {
		logger.jsonFile = nil
	}
	if lc.Syslog.Enabled && lc.Syslog.Address != "" {
		logger.syslog = newSyslogSink(lc.Syslog)
	}
	logger.mu.Unlock()
}

// defaultLogPath puts the log alongside the captures, in a "logs" subfolder of
// the capture directory, so all run artifacts live together. The subfolder is
// created here (configureLogging runs before the engine's ensureStorageDirs, so
// the directory must exist by the time the first line is written). Falls back to
// the executable directory if the logs subfolder can't be created.
func defaultLogPath() string {
	dir := logDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		exe, eerr := os.Executable()
		if eerr != nil {
			return "printcap.log"
		}
		return filepath.Join(filepath.Dir(exe), "printcap.log")
	}
	return filepath.Join(dir, "printcap.log")
}

// SetLevel changes the active level at runtime without rebuilding the logger
// (used by the dashboard's live log-level control).
func (l *Logger) SetLevel(lv Level) {
	l.mu.Lock()
	l.level = lv
	l.mu.Unlock()
}

func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// LogFilePath returns the active primary log file path (for downloads).
func (l *Logger) LogFilePath() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.text != nil {
		return l.text.path
	}
	return ""
}

// logf formats and dispatches a record if level permits.
func (l *Logger) logf(level Level, comp, format string, args ...interface{}) {
	l.mu.Lock()
	if level > l.level {
		l.mu.Unlock()
		return
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	now := time.Now()
	e := logEntry{
		Time:      now.Format("2006-01-02 15:04:05.000"),
		Level:     level.String(),
		Component: comp,
		Message:   msg,
	}
	textLine := fmt.Sprintf("%s %-5s [%s] %s\n", e.Time, e.Level, comp, msg)
	jsonLine := jsonEntryLine(e)

	primary := textLine
	if l.jsonFormat {
		primary = jsonLine
	}
	if l.text != nil {
		l.text.write(primary)
	}
	if l.jsonFile != nil {
		l.jsonFile.write(jsonLine)
	}
	if l.console {
		fmt.Fprint(os.Stderr, primary)
	}
	l.ring = append(l.ring, e)
	if len(l.ring) > l.ringMax {
		l.ring = l.ring[len(l.ring)-l.ringMax:]
	}
	sysSink := l.sysSink
	syslog := l.syslog
	l.mu.Unlock()

	// Network / system sinks outside the lock (they may block).
	if sysSink != nil && level <= LevelWarn {
		sysSink(level, fmt.Sprintf("[%s] %s", comp, msg))
	}
	if syslog != nil {
		syslog.send(e, level)
	}
}

func jsonEntryLine(e logEntry) string {
	b, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return string(b) + "\n"
}

// recent returns up to n recent entries (newest first) at or above minLevel.
func (l *Logger) recent(n int, minLevel Level) []logEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]logEntry, 0, n)
	for i := len(l.ring) - 1; i >= 0 && len(out) < n; i-- {
		if levelOf(l.ring[i].Level) <= minLevel {
			out = append(out, l.ring[i])
		}
	}
	return out
}

func levelOf(name string) Level {
	for i, n := range levelNames {
		if n == name {
			return Level(i)
		}
	}
	return LevelInfo
}

// --- remote syslog sink --------------------------------------------------------

// syslogSink ships records to a remote syslog server over UDP or TCP, framed as
// RFC 3164 (BSD) or RFC 5424. Implemented directly over net.Conn because the
// standard library's log/syslog is Unix-only.
type syslogSink struct {
	network  string
	address  string
	facility int
	rfc5424  bool
	appName  string
	hostname string

	mu   sync.Mutex
	conn net.Conn
}

func newSyslogSink(c SyslogConf) *syslogSink {
	host, _ := os.Hostname()
	if host == "" {
		host = "printcap"
	}
	app := c.AppName
	if app == "" {
		app = "printcap"
	}
	netw := strings.ToLower(c.Network)
	if netw != "tcp" {
		netw = "udp"
	}
	s := &syslogSink{
		network:  netw,
		address:  c.Address,
		facility: c.Facility,
		rfc5424:  c.RFC5424,
		appName:  app,
		hostname: host,
	}
	s.dial()
	return s
}

func (s *syslogSink) dial() {
	c, err := net.DialTimeout(s.network, s.address, 3*time.Second)
	if err != nil {
		s.conn = nil
		return
	}
	s.conn = c
}

// syslogSeverity maps our levels to syslog severities (RFC 5424 §6.2.1).
func syslogSeverity(l Level) int {
	switch l {
	case LevelError:
		return 3 // err
	case LevelWarn:
		return 4 // warning
	case LevelInfo:
		return 6 // info
	default:
		return 7 // debug (debug + trace)
	}
}

func (s *syslogSink) send(e logEntry, level Level) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		s.dial()
		if s.conn == nil {
			return
		}
	}
	pri := s.facility*8 + syslogSeverity(level)
	now := time.Now()
	var line string
	if s.rfc5424 {
		// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
		line = fmt.Sprintf("<%d>1 %s %s %s - - - [%s] %s\n",
			pri, now.Format(time.RFC3339), s.hostname, s.appName, e.Component, e.Message)
	} else {
		// RFC 3164: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG: MSG
		line = fmt.Sprintf("<%d>%s %s %s: [%s] %s\n",
			pri, now.Format("Jan _2 15:04:05"), s.hostname, s.appName, e.Component, e.Message)
	}
	if _, err := s.conn.Write([]byte(line)); err != nil {
		s.conn.Close()
		s.conn = nil // force a redial on the next record
	}
}

func (s *syslogSink) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
}

// --- package-level convenience -------------------------------------------------

func logErr(comp, f string, a ...interface{})   { logger.logf(LevelError, comp, f, a...) }
func logWarn(comp, f string, a ...interface{})  { logger.logf(LevelWarn, comp, f, a...) }
func logInfo(comp, f string, a ...interface{})  { logger.logf(LevelInfo, comp, f, a...) }
func logDebug(comp, f string, a ...interface{}) { logger.logf(LevelDebug, comp, f, a...) }
func logTrace(comp, f string, a ...interface{}) { logger.logf(LevelTrace, comp, f, a...) }

// logProto logs protocol-level detail. With cfg.Log.Protocol enabled it is
// emitted at INFO (always visible); otherwise it sits at DEBUG.
func logProto(comp, f string, a ...interface{}) {
	if cfg != nil && cfg.Log.Protocol {
		logger.logf(LevelInfo, comp, f, a...)
	} else {
		logger.logf(LevelDebug, comp, f, a...)
	}
}

// stdLogWriter adapts the standard library logger into our logger so any stray
// log.Print lands in the same sinks (tagged as the "log" component).
type stdLogWriter struct{}

func (stdLogWriter) Write(p []byte) (int, error) {
	logger.logf(LevelInfo, "log", "%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
