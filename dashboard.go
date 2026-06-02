package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// dashboardHandler builds the live web UI and its JSON API on its own HTTP mux
// so it never collides with the IPP endpoint.
func dashboardHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", dashIndex)
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/api/jobs", apiJobs)
	mux.HandleFunc("/api/config", apiConfig)
	mux.HandleFunc("/api/job", apiJobData)
	mux.HandleFunc("/api/logs", apiLogs)
	mux.HandleFunc("/api/logfile", apiLogFile)
	return mux
}

// apiLogFile streams the active log file as a download.
func apiLogFile(w http.ResponseWriter, r *http.Request) {
	path := logger.LogFilePath()
	if path == "" {
		http.Error(w, "no log file configured", http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "log file not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
	http.ServeContent(w, r, filepath.Base(path), time.Time{}, f)
}

// apiLogs returns recent log entries (newest first), optionally filtered by a
// minimum level (?level=info|debug|trace) and capped by ?n=.
func apiLogs(w http.ResponseWriter, r *http.Request) {
	n := atoiDefault(r.URL.Query().Get("n"), 200)
	if n <= 0 || n > 2000 {
		n = 200
	}
	min := LevelTrace // default: everything currently buffered
	if lv := r.URL.Query().Get("level"); lv != "" {
		min = parseLevel(lv)
	}
	writeJSON(w, logger.recent(n, min))
}

func dashHost() string {
	if cfg.Bind == "0.0.0.0" || cfg.Bind == "" || cfg.Bind == "::" {
		return "localhost"
	}
	return cfg.Bind
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func apiStats(w http.ResponseWriter, r *http.Request) {
	type listener struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}
	ls := []listener{
		{"Raw/9100", cfg.Ports.Raw9100},
		{"LPR", cfg.Ports.LPR},
		{"IPP", cfg.Ports.IPP},
		{"IPPS", cfg.Ports.IPPS},
		{"IPP/IPPS (auto)", cfg.Ports.AutoTLS},
		{"SNMP", snmpPortIfEnabled()},
		{"Dashboard", cfg.Ports.Dashboard},
	}
	writeJSON(w, map[string]interface{}{
		"stats":     store.stats(),
		"listeners": ls,
		"printer": map[string]string{
			"name":           cfg.Printer.Name,
			"make_and_model": cfg.Printer.MakeAndModel,
			"location":       cfg.Printer.Location,
			"serial":         cfg.Printer.Serial,
		},
		"save_mode": cfg.Save,
	})
}

func snmpPortIfEnabled() int {
	if cfg.SNMP.Enabled {
		return cfg.Ports.SNMP
	}
	return 0
}

func apiJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, store.recent(200))
}

func apiConfig(w http.ResponseWriter, r *http.Request) {
	// Return a copy with secrets redacted — the dashboard is unauthenticated,
	// so it must not leak the SNMP community string or key material paths.
	writeJSON(w, redactedConfig())
}

// redactedConfig returns a shallow copy of the active config with all secret
// material removed: the SNMP community string, SNMPv3 USM passphrases, and TLS
// key/cert file paths. Safe to expose over the unauthenticated dashboard.
func redactedConfig() *Config {
	c := *cfg
	if c.SNMP.Community != "" {
		c.SNMP.Community = "***"
	}
	if len(c.SNMP.Users) > 0 {
		us := make([]SNMPUser, len(c.SNMP.Users))
		copy(us, c.SNMP.Users)
		for i := range us {
			if us[i].AuthPass != "" {
				us[i].AuthPass = "***"
			}
			if us[i].PrivPass != "" {
				us[i].PrivPass = "***"
			}
		}
		c.SNMP.Users = us
	}
	c.TLS.CertFile = ""
	c.TLS.KeyFile = ""
	return &c
}

// apiJobData streams a captured spool file back to the browser as a download.
func apiJobData(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	j, ok := store.get(id)
	if !ok || j.SavedAs == "" {
		http.Error(w, "no saved data for that job", http.StatusNotFound)
		return
	}
	// SavedAs is a filename we generated; join to the output dir and confirm it
	// stays inside it (defense in depth against traversal).
	path := filepath.Join(cfg.OutDir, filepath.Base(j.SavedAs))
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(j.SavedAs)+"\"")
	http.ServeContent(w, r, j.SavedAs, time.Time{}, f)
}

func dashIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>printcap dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif; background:#0d1117; color:#e6edf3; }
  header { padding:16px 24px; background:#161b22; border-bottom:1px solid #30363d; display:flex; align-items:baseline; gap:16px; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; }
  header .sub { color:#8b949e; font-size:13px; }
  header .dot { color:#3fb950; }
  main { padding:24px; max-width:1200px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:24px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:14px 16px; }
  .card .k { color:#8b949e; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .card .v { font-size:24px; font-weight:600; margin-top:4px; }
  .row { display:flex; gap:24px; flex-wrap:wrap; align-items:flex-start; }
  .panel { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; margin-bottom:24px; flex:1; min-width:280px; }
  .panel h2 { font-size:14px; margin:0 0 12px; color:#8b949e; text-transform:uppercase; letter-spacing:.04em; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #21262d; white-space:nowrap; }
  th { color:#8b949e; font-weight:600; font-size:12px; text-transform:uppercase; }
  tbody tr:hover { background:#1c2128; }
  .tag { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px; font-weight:600; }
  .t9100{background:#1f6feb33;color:#79c0ff} .tLPR{background:#a371f733;color:#d2a8ff}
  .tIPP{background:#3fb95033;color:#7ee787} .tIPPS{background:#db61a233;color:#ff9bce}
  a.dl { color:#58a6ff; text-decoration:none; } a.dl:hover{text-decoration:underline;}
  .muted{color:#8b949e;} .mono{font-family:ui-monospace,Menlo,Consolas,monospace;}
  .pill { font-size:12px; padding:2px 8px; border:1px solid #30363d; border-radius:999px; margin-right:6px; display:inline-block; }
  .on{border-color:#238636;color:#3fb950;} .off{color:#8b949e;}
  .empty{ color:#8b949e; padding:24px; text-align:center; }
  .logbox{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; line-height:1.45;
    background:#010409; border:1px solid #21262d; border-radius:6px; padding:10px 12px;
    max-height:320px; overflow:auto; white-space:pre-wrap; }
  .lg-ERROR{color:#ff7b72;} .lg-WARN{color:#e3b341;} .lg-INFO{color:#adbac7;}
  .lg-DEBUG{color:#6e7681;} .lg-TRACE{color:#545d68;}
  .lg-comp{color:#58a6ff;}
</style>
</head>
<body>
<header>
  <h1>printcap <span class="dot">●</span></h1>
  <span class="sub" id="printer"></span>
  <span class="sub" style="margin-left:auto" id="listeners"></span>
</header>
<main>
  <div class="cards" id="cards"></div>
  <div class="panel">
    <h2>Captured jobs <span class="muted" id="jobcount"></span></h2>
    <div id="jobs"></div>
  </div>
  <div class="panel">
    <h2>Live log
      <select id="loglevel" style="margin-left:8px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;padding:2px 6px;">
        <option value="info">info</option>
        <option value="warn">warn+</option>
        <option value="error">error</option>
        <option value="debug">debug</option>
        <option value="trace">trace</option>
      </select>
      <a class="dl" href="api/logfile" style="margin-left:12px;font-size:13px;">⤓ download full log</a>
    </h2>
    <div id="logs" class="logbox"></div>
  </div>
</main>
<script>
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtBytes = n => n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(2)+' MB';
const protoClass = p => 't'+p.replace(/[^A-Za-z0-9]/g,'');

async function refresh(){
  try {
    const [s,j] = await Promise.all([fetch('api/stats').then(r=>r.json()), fetch('api/jobs').then(r=>r.json())]);
    document.getElementById('printer').textContent = s.printer.name+' — '+s.printer.make_and_model+'  ·  save='+s.save_mode;
    document.getElementById('listeners').innerHTML = s.listeners.filter(l=>l.port>0)
      .map(l=>'<span class="pill on">'+esc(l.name)+':'+l.port+'</span>').join('');
    const bp = s.stats.by_protocol||{};
    const cards = [['Total jobs',s.stats.total],['Total data',fmtBytes(s.stats.bytes)]]
      .concat(Object.keys(bp).sort().map(k=>[k,bp[k]]));
    document.getElementById('cards').innerHTML = cards.map(c=>
      '<div class="card"><div class="k">'+esc(c[0])+'</div><div class="v">'+esc(c[1])+'</div></div>').join('');
    document.getElementById('jobcount').textContent = j.length?('· '+j.length+' shown'):'';
    if(!j.length){ document.getElementById('jobs').innerHTML='<div class="empty">No jobs captured yet. Send a print job to one of the ports above.</div>'; return; }
    let rows = j.map(x=>'<tr>'
      +'<td class="muted mono">'+esc(x.received)+'</td>'
      +'<td><span class="tag '+protoClass(x.protocol)+'">'+esc(x.protocol)+'</span></td>'
      +'<td class="mono">'+esc(x.source)+'</td>'
      +'<td>'+esc(x.user||'—')+'</td>'
      +'<td>'+esc(x.host||'—')+'</td>'
      +'<td>'+esc(x.job_name||'—')+'</td>'
      +'<td class="muted">'+esc(x.document_format||'—')+'</td>'
      +'<td>'+fmtBytes(x.bytes)+'</td>'
      +'<td>'+(x.saved_as?'<a class="dl" href="api/job?id='+x.id+'">download</a>':'<span class="muted">—</span>')+'</td>'
      +'</tr>').join('');
    document.getElementById('jobs').innerHTML =
      '<table><thead><tr><th>Received</th><th>Proto</th><th>Source</th><th>User</th><th>Host</th><th>Job</th><th>Format</th><th>Size</th><th></th></tr></thead><tbody>'+rows+'</tbody></table>';
  } catch(e){ /* transient; retry next tick */ }
}
async function refreshLogs(){
  try {
    const lvl = document.getElementById('loglevel').value;
    const rows = await fetch('api/logs?n=300&level='+lvl).then(r=>r.json());
    if(!rows || !rows.length){ document.getElementById('logs').innerHTML='<span class="muted">No log entries at this level yet.</span>'; return; }
    // newest first from API; show oldest-at-top for readability
    document.getElementById('logs').innerHTML = rows.slice().reverse().map(e=>
      '<div class="lg-'+esc(e.level)+'">'+esc(e.time)+' '+esc(e.level.padEnd(5))
      +' <span class="lg-comp">['+esc(e.component)+']</span> '+esc(e.message)+'</div>').join('');
  } catch(e){}
}
refresh(); refreshLogs();
setInterval(refresh, 2000);
setInterval(refreshLogs, 2000);
document.getElementById('loglevel').addEventListener('change', refreshLogs);
</script>
</body>
</html>`
