package main

// dashboardHTML is the entire single-page admin console: inline CSS + JS, no
// external assets, no frameworks. It drives the JSON API in dashboard.go and
// receives live stats over the /api/events SSE stream.
const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>printcap admin</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --border:#30363d; --line:#21262d;
    --fg:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --good:#3fb950; --bad:#f85149;
    --inbg:#0d1117;
  }
  [data-theme="light"]{
    --bg:#f6f8fa; --panel:#ffffff; --border:#d0d7de; --line:#e6e9ee;
    --fg:#1f2328; --muted:#636c76; --accent:#0969da; --good:#1a7f37; --bad:#cf222e;
    --inbg:#ffffff;
  }
  *{box-sizing:border-box;}
  body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);}
  header{padding:14px 24px;background:var(--panel);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px;flex-wrap:wrap;}
  header h1{font-size:18px;margin:0;}
  header .sub{color:var(--muted);font-size:13px;}
  header .spacer{margin-left:auto;}
  button,select,input{font:inherit;color:var(--fg);background:var(--inbg);border:1px solid var(--border);border-radius:6px;padding:5px 10px;}
  button{cursor:pointer;}
  button:hover{border-color:var(--accent);}
  button.danger:hover{border-color:var(--bad);color:var(--bad);}
  main{padding:24px;max-width:1280px;margin:0 auto;}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px;}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px 16px;}
  .card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;}
  .card .v{font-size:24px;font-weight:600;margin-top:4px;}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:24px;}
  .panel h2{font-size:14px;margin:0 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;}
  table{width:100%;border-collapse:collapse;}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap;}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;}
  th.sortable{cursor:pointer;user-select:none;}
  th.sortable:hover{color:var(--fg);}
  tbody tr{cursor:pointer;}
  tbody tr:hover{background:var(--line);}
  .tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;background:var(--line);color:var(--accent);}
  a.dl{color:var(--accent);text-decoration:none;} a.dl:hover{text-decoration:underline;}
  .muted{color:var(--muted);} .mono{font-family:ui-monospace,Menlo,Consolas,monospace;}
  .controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px;}
  .controls .grow{flex:1;min-width:160px;}
  .lstat{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--line);}
  .lstat:last-child{border-bottom:none;}
  .ind{width:10px;height:10px;border-radius:50%;flex:0 0 auto;}
  .ind.up{background:var(--good);} .ind.down{background:var(--bad);}
  .lstat .nm{font-weight:600;min-width:90px;}
  .lstat .pt{color:var(--muted);min-width:60px;}
  .lstat .sp{margin-left:auto;}
  .empty{color:var(--muted);padding:24px;text-align:center;}
  .logbox{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.45;background:var(--inbg);border:1px solid var(--line);border-radius:6px;padding:10px 12px;max-height:320px;overflow:auto;white-space:pre-wrap;}
  .lg-ERROR{color:var(--bad);} .lg-WARN{color:#e3b341;} .lg-INFO{color:var(--fg);}
  .lg-DEBUG{color:var(--muted);} .lg-TRACE{color:var(--muted);} .lg-comp{color:var(--accent);}
  .pager{display:flex;gap:8px;align-items:center;margin-top:12px;flex-wrap:wrap;}
  .pager .info{color:var(--muted);}
  .overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:flex-start;justify-content:center;padding:40px 16px;overflow:auto;z-index:10;}
  .overlay.show{display:flex;}
  .modal{background:var(--panel);border:1px solid var(--border);border-radius:10px;max-width:820px;width:100%;padding:20px 24px;}
  .modal h3{margin:0 0 12px;}
  .modal .close{float:right;}
  .kv{display:grid;grid-template-columns:160px 1fr;gap:4px 14px;margin-bottom:14px;}
  .kv .k{color:var(--muted);}
  .kv .v{word-break:break-word;white-space:normal;}
  .dlp{color:var(--bad);font-weight:600;}
  .preview{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:var(--inbg);border:1px solid var(--line);border-radius:6px;padding:10px 12px;max-height:300px;overflow:auto;white-space:pre-wrap;}
  @media(max-width:600px){.kv{grid-template-columns:1fr;}}
</style>
</head>
<body>
<header>
  <h1>printcap</h1>
  <span class="sub" id="printer"></span>
  <span class="spacer"></span>
  <button id="refreshBtn" title="manual refresh">Refresh</button>
  <button id="themeBtn" title="toggle theme">Theme</button>
</header>
<main>
  <div class="cards" id="cards"></div>

  <div class="panel">
    <h2>Listeners</h2>
    <div id="listeners"></div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <button id="engStart">Start engine</button>
      <button id="engRestart">Restart engine</button>
      <button id="engStop" class="danger">Stop engine</button>
      <span class="muted" style="align-self:center;">Restart/Stop briefly drops this dashboard.</span>
    </div>
  </div>

  <div class="panel">
    <h2>Captured jobs <span class="muted" id="jobcount"></span></h2>
    <div class="controls">
      <input id="q" class="grow" placeholder="search job, user, host, source, protocol…">
      <select id="proto"><option value="">all protocols</option></select>
      <select id="pageSize">
        <option value="25">25 / page</option>
        <option value="50" selected>50 / page</option>
        <option value="100">100 / page</option>
        <option value="200">200 / page</option>
      </select>
      <a class="dl" id="expCsv" href="#">⤓ CSV</a>
      <a class="dl" id="expJson" href="#">⤓ JSON</a>
    </div>
    <div id="jobs"></div>
    <div class="pager">
      <button id="prev">‹ Prev</button>
      <button id="next">Next ›</button>
      <span class="info" id="pageInfo"></span>
    </div>
  </div>

  <div class="panel">
    <h2>Live log
      <select id="loglevel" style="margin-left:8px;">
        <option value="error">error</option>
        <option value="warn">warn+</option>
        <option value="info" selected>info</option>
        <option value="debug">debug</option>
        <option value="trace">trace</option>
      </select>
      <a class="dl" href="api/logfile" style="margin-left:12px;font-size:13px;">⤓ download full log</a>
    </h2>
    <div id="logs" class="logbox"></div>
  </div>
  <div class="muted" style="text-align:center;font-size:12px;">printcap admin console</div>
</main>

<div class="overlay" id="overlay"><div class="modal" id="modal"></div></div>

<script>
var esc = function(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};
var fmtBytes = function(n){n=Number(n)||0;return n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(2)+' MB';};

var state={q:'',proto:'',sort:'received',order:'desc',offset:0,limit:50,total:0,jobs:[]};

// ---- theme ----
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);}
var theme=localStorage.getItem('pc_theme')||'dark';
applyTheme(theme);
document.getElementById('themeBtn').onclick=function(){
  theme=(theme==='dark')?'light':'dark';localStorage.setItem('pc_theme',theme);applyTheme(theme);
};

// ---- query string helper for current filter ----
function filterQS(){
  var p=new URLSearchParams();
  if(state.q)p.set('q',state.q);
  if(state.proto)p.set('protocol',state.proto);
  p.set('sort',state.sort);p.set('order',state.order);
  return p;
}

// ---- stats / cards / listeners (from SSE or fetch) ----
function renderStats(s){
  if(!s)return;
  var bp=(s.stats&&s.stats.by_protocol)||{};
  var cards=[['Total jobs',(s.stats&&s.stats.total)||0],['Total data',fmtBytes(s.stats&&s.stats.bytes)]]
    .concat(Object.keys(bp).sort().map(function(k){return [k,bp[k]];}));
  document.getElementById('cards').innerHTML=cards.map(function(c){
    return '<div class="card"><div class="k">'+esc(c[0])+'</div><div class="v">'+esc(c[1])+'</div></div>';}).join('');
  // protocol filter options
  var sel=document.getElementById('proto');var cur=sel.value;
  var opts='<option value="">all protocols</option>'+Object.keys(bp).sort().map(function(k){
    return '<option value="'+esc(k)+'">'+esc(k)+'</option>';}).join('');
  if(sel.dataset.sig!==opts){sel.innerHTML=opts;sel.value=cur;sel.dataset.sig=opts;}
  if(s.listeners)renderListeners(s.listeners);
}

function renderListeners(ls){
  document.getElementById('listeners').innerHTML=ls.map(function(l){
    var up=l.up?'up':'down';
    var btn=l.disabled
      ? '<button data-name="'+esc(l.name)+'" data-en="true">Enable</button>'
      : '<button class="danger" data-name="'+esc(l.name)+'" data-en="false">Disable</button>';
    return '<div class="lstat"><span class="ind '+up+'"></span>'
      +'<span class="nm">'+esc(l.name)+'</span>'
      +'<span class="pt">'+(l.port>0?(':'+l.port):'—')+'</span>'
      +'<span class="muted">'+(l.disabled?'disabled':(l.up?'listening':'down'))+'</span>'
      +'<span class="sp">'+btn+'</span></div>';
  }).join('');
  Array.prototype.forEach.call(document.querySelectorAll('#listeners button'),function(b){
    b.onclick=function(){
      var name=b.getAttribute('data-name');var en=b.getAttribute('data-en');
      if(!confirm((en==='true'?'Enable':'Disable')+' '+name+'? The engine will bounce and the dashboard may briefly drop.'))return;
      fetch('api/listener?name='+encodeURIComponent(name)+'&enabled='+en,{method:'POST',headers:{'X-Requested-With':'printcap'}});
    };
  });
}

function loadStatsOnce(){fetch('api/stats').then(function(r){return r.json();}).then(function(s){
  if(s.printer)document.getElementById('printer').textContent=s.printer.name+' — '+s.printer.make_and_model+'  ·  save='+s.save_mode;
}).catch(function(){});
  fetch('api/listeners').then(function(r){return r.json();}).then(renderListeners).catch(function(){});
}

// ---- jobs table ----
function loadJobs(){
  var p=filterQS();p.set('offset',state.offset);p.set('limit',state.limit);
  fetch('api/jobs?'+p.toString()).then(function(r){return r.json();}).then(function(d){
    state.jobs=d.jobs||[];state.total=d.total||0;renderJobs();
  }).catch(function(){});
}

function sortArrow(col){return state.sort===col?(state.order==='desc'?' ▼':' ▲'):'';}

function renderJobs(){
  var j=state.jobs;
  document.getElementById('jobcount').textContent=state.total?('· '+state.total+' total'):'';
  if(!j.length){
    document.getElementById('jobs').innerHTML='<div class="empty">No jobs match. Send a print job to one of the listeners above.</div>';
  } else {
    var head='<table><thead><tr>'
      +'<th class="sortable" data-c="received">Received'+sortArrow('received')+'</th>'
      +'<th class="sortable" data-c="protocol">Proto'+sortArrow('protocol')+'</th>'
      +'<th>Source</th><th>User</th><th>Host</th>'
      +'<th class="sortable" data-c="job_name">Job'+sortArrow('job_name')+'</th>'
      +'<th>Format</th>'
      +'<th class="sortable" data-c="bytes">Size'+sortArrow('bytes')+'</th>'
      +'<th></th></tr></thead><tbody>';
    var rows=j.map(function(x){
      return '<tr data-id="'+x.id+'">'
        +'<td class="muted mono">'+esc(x.received)+'</td>'
        +'<td><span class="tag">'+esc(x.protocol)+'</span></td>'
        +'<td class="mono">'+esc(x.source)+'</td>'
        +'<td>'+esc(x.user||'—')+'</td>'
        +'<td>'+esc(x.host||'—')+'</td>'
        +'<td>'+esc(x.job_name||'—')+(x.dlp_matches&&x.dlp_matches.length?' <span class="dlp">⚑DLP</span>':'')+'</td>'
        +'<td class="muted">'+esc(x.document_format||'—')+'</td>'
        +'<td>'+fmtBytes(x.bytes)+'</td>'
        +'<td>'+(x.saved_as?'<a class="dl" href="api/job?id='+x.id+'" onclick="event.stopPropagation()">download</a> ':'')
          +'<button class="danger" data-del="'+x.id+'" onclick="event.stopPropagation()">del</button></td>'
        +'</tr>';
    }).join('');
    document.getElementById('jobs').innerHTML=head+rows+'</tbody></table>';
    Array.prototype.forEach.call(document.querySelectorAll('th.sortable'),function(th){
      th.onclick=function(){
        var c=th.getAttribute('data-c');
        if(state.sort===c){state.order=(state.order==='desc')?'asc':'desc';}else{state.sort=c;state.order='desc';}
        state.offset=0;loadJobs();
      };
    });
    Array.prototype.forEach.call(document.querySelectorAll('tr[data-id]'),function(tr){
      tr.onclick=function(){openDetail(tr.getAttribute('data-id'));};
    });
    Array.prototype.forEach.call(document.querySelectorAll('button[data-del]'),function(b){
      b.onclick=function(e){e.stopPropagation();
        var id=b.getAttribute('data-del');
        if(!confirm('Delete job '+id+' and its files? This cannot be undone.'))return;
        fetch('api/jobdelete?id='+id,{method:'POST',headers:{'X-Requested-With':'printcap'}}).then(function(){loadJobs();});
      };
    });
  }
  var from=state.total?state.offset+1:0;var to=Math.min(state.offset+state.limit,state.total);
  document.getElementById('pageInfo').textContent='showing '+from+'–'+to+' of '+state.total;
  document.getElementById('prev').disabled=state.offset<=0;
  document.getElementById('next').disabled=state.offset+state.limit>=state.total;
  var qs=filterQS();
  document.getElementById('expCsv').href='api/export?format=csv&'+qs.toString();
  document.getElementById('expJson').href='api/export?format=json&'+qs.toString();
}

// ---- detail modal ----
function row(k,v){return '<div class="k">'+esc(k)+'</div><div class="v">'+v+'</div>';}
function openDetail(id){
  var x=null;for(var i=0;i<state.jobs.length;i++){if(String(state.jobs[i].id)===String(id)){x=state.jobs[i];break;}}
  if(!x)return;
  var kv='';
  kv+=row('Received',esc(x.received));
  kv+=row('Protocol',esc(x.protocol));
  kv+=row('Source',esc(x.source));
  kv+=row('User',esc(x.user||'—'));
  kv+=row('Host',esc(x.host||'—'));
  kv+=row('Queue',esc(x.queue||'—'));
  kv+=row('Document format',esc(x.document_format||'—'));
  kv+=row('PDL',esc(x.pdl||'—'));
  kv+=row('Code page',esc(x.code_page||'—'));
  kv+=row('Decoded as',esc(x.decoded_as||'—'));
  kv+=row('Bytes',fmtBytes(x.bytes)+' ('+esc(x.bytes)+')');
  kv+=row('Saved as',esc(x.saved_as||'—'));
  if(x.dlp_matches&&x.dlp_matches.length)
    kv+=row('DLP matches','<span class="dlp">'+x.dlp_matches.map(esc).join(', ')+'</span>');
  if(x.forwards&&x.forwards.length){
    var fw=x.forwards.map(function(f){
      return esc(f.target)+' ['+esc(f.transport)+' '+esc(f.address)+'] → '+esc(f.status)
        +(f.error?(' ('+esc(f.error)+')'):'');}).join('<br>');
    kv+=row('Forwards',fw);
  }
  var html='<button class="close" id="modalClose">✕ close</button>'
    +'<h3>Job '+esc(x.id)+' <span class="tag">'+esc(x.protocol)+'</span></h3>'
    +'<div class="kv">'+kv+'</div>'
    +(x.saved_as?('<div class="muted" style="margin-bottom:6px;">Preview (first 64 KiB):</div><div class="preview" id="prev">loading…</div>'
      +'<div style="margin-top:10px;"><a class="dl" href="api/job?id='+x.id+'">⤓ download full spool</a></div>')
      :'<div class="muted">No saved spool for this job.</div>');
  document.getElementById('modal').innerHTML=html;
  document.getElementById('overlay').classList.add('show');
  document.getElementById('modalClose').onclick=closeDetail;
  if(x.saved_as){
    fetch('api/jobpreview?id='+x.id).then(function(r){return r.text();}).then(function(t){
      var el=document.getElementById('prev');if(!el)return;
      if(/[\x00-\x08\x0e-\x1f]/.test(t.slice(0,2000)))
        el.innerHTML='<span class="muted">(binary data — '+esc(t.length)+' bytes shown; download to inspect)</span>\n'+esc(t.slice(0,2000));
      else el.textContent=t;
    }).catch(function(){});
  }
}
function closeDetail(){document.getElementById('overlay').classList.remove('show');}
document.getElementById('overlay').onclick=function(e){if(e.target===this)closeDetail();};
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeDetail();});

// ---- logs ----
function refreshLogs(){
  var lvl=document.getElementById('loglevel').value;
  fetch('api/logs?n=300&level='+lvl).then(function(r){return r.json();}).then(function(rows){
    if(!rows||!rows.length){document.getElementById('logs').innerHTML='<span class="muted">No log entries at this level yet.</span>';return;}
    document.getElementById('logs').innerHTML=rows.slice().reverse().map(function(e){
      return '<div class="lg-'+esc(e.level)+'">'+esc(e.time)+' '+esc((e.level+'     ').slice(0,5))
        +' <span class="lg-comp">['+esc(e.component)+']</span> '+esc(e.message)+'</div>';}).join('');
  }).catch(function(){});
}
document.getElementById('loglevel').addEventListener('change',function(){
  // set the server's live level to match what we want to view, then refresh
  fetch('api/loglevel?level='+encodeURIComponent(this.value),{method:'POST',headers:{'X-Requested-With':'printcap'}}).catch(function(){});
  refreshLogs();
});

// ---- controls wiring ----
document.getElementById('q').addEventListener('input',function(){state.q=this.value;state.offset=0;
  clearTimeout(window._qt);window._qt=setTimeout(loadJobs,250);});
document.getElementById('proto').addEventListener('change',function(){state.proto=this.value;state.offset=0;loadJobs();});
document.getElementById('pageSize').addEventListener('change',function(){state.limit=parseInt(this.value,10)||50;state.offset=0;loadJobs();});
document.getElementById('prev').onclick=function(){state.offset=Math.max(0,state.offset-state.limit);loadJobs();};
document.getElementById('next').onclick=function(){if(state.offset+state.limit<state.total){state.offset+=state.limit;loadJobs();}};
document.getElementById('refreshBtn').onclick=function(){loadStatsOnce();loadJobs();refreshLogs();};
document.getElementById('engStart').onclick=function(){if(confirm('Start the engine?'))fetch('api/control?action=start',{method:'POST',headers:{'X-Requested-With':'printcap'}});};
document.getElementById('engRestart').onclick=function(){if(confirm('Restart the engine? The dashboard will briefly drop.'))fetch('api/control?action=restart',{method:'POST',headers:{'X-Requested-With':'printcap'}});};
document.getElementById('engStop').onclick=function(){if(confirm('Stop the engine? The dashboard will drop and not come back until restarted.'))fetch('api/control?action=stop',{method:'POST',headers:{'X-Requested-With':'printcap'}});};

// ---- live SSE ----
function startSSE(){
  if(!window.EventSource){setInterval(function(){loadStatsOnce();},3000);return;}
  var es=new EventSource('api/events');
  es.onmessage=function(ev){try{renderStats(JSON.parse(ev.data));}catch(e){}};
  es.onerror=function(){/* browser auto-reconnects */};
}

loadStatsOnce();loadJobs();refreshLogs();startSSE();
setInterval(refreshLogs,3000);
</script>
</body>
</html>`
