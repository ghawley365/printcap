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
  fieldset.setgrp{border:1px solid var(--border);border-radius:8px;margin:0 0 14px;padding:10px 14px 4px;}
  fieldset.setgrp legend{color:var(--accent);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:0 6px;}
  .setrow{display:grid;grid-template-columns:230px 1fr;gap:6px 14px;align-items:center;margin-bottom:8px;}
  .setrow>label{color:var(--muted);font-size:13px;word-break:break-word;}
  .setrow input[type=text],.setrow input[type=number]{width:100%;}
  .setrow input[type=checkbox]{width:16px;height:16px;}
  textarea.setjson{width:100%;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:var(--inbg);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:8px;resize:vertical;}
  .setmsg{white-space:pre-wrap;margin-top:10px;padding:8px 12px;border-radius:6px;font-size:13px;}
  .setmsg.ok{background:rgba(63,185,80,.12);color:var(--good);} .setmsg.err{background:rgba(248,81,73,.12);color:var(--bad);}
  .lstat .reason{color:var(--bad);font-size:12px;flex-basis:100%;padding-left:20px;}
  table.cap td{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;white-space:nowrap;}
  table.cap tr[data-a]{cursor:pointer;}
  table.cap tr[data-a]:hover td{background:var(--line);}
  tr.cap-reset td{color:var(--bad);font-weight:600;}
  tr.cap-error td{color:#e3b341;font-weight:600;}
  tr.cap-syn td{color:var(--good);}
  tr.cap-fin td{color:var(--muted);}
  tr.cap-other td{color:var(--muted);}
  .caplegend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;margin:0 0 10px;}
  .caplegend span{display:inline-flex;align-items:center;gap:5px;}
  .caplegend i{width:10px;height:10px;border-radius:2px;display:inline-block;}
  @media(max-width:600px){.kv,.setrow{grid-template-columns:1fr;}}
</style>
</head>
<body>
<header>
  <h1>printcap</h1>
  <span class="sub" id="printer"></span>
  <span class="spacer"></span>
  <button id="captureBtn" title="view captured packets">Captures</button>
  <button id="settingsBtn" title="edit all settings">Settings</button>
  <button id="refreshBtn" title="manual refresh">Refresh</button>
  <button id="themeBtn" title="toggle theme">Theme</button>
</header>
<main>
  <div class="cards" id="cards"></div>

  <div class="panel" id="settingsPanel" style="display:none;">
    <h2>Settings <span class="muted" id="settingsHint">— every config field; secrets show as *** (leave them to keep the stored value)</span></h2>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <button id="setSave">Save</button>
      <button id="setSaveRestart">Save &amp; restart engine</button>
      <button id="setReload">Reload</button>
      <button id="setClose" class="danger">Close</button>
      <span class="muted" style="align-self:center;">Saving while running restarts the engine and briefly drops this dashboard.</span>
    </div>
    <div id="settingsForm"><div class="empty">Loading settings…</div></div>
    <div id="setMsg"></div>
  </div>

  <div class="panel" id="capturePanel" style="display:none;">
    <h2>Network capture <span class="muted" id="capInfo"></span></h2>
    <div class="caplegend">
      <span><i style="background:var(--bad)"></i>reset (RST)</span>
      <span><i style="background:#e3b341"></i>ICMP error</span>
      <span><i style="background:var(--good)"></i>SYN (connect)</span>
      <span><i style="background:var(--muted)"></i>FIN / other</span>
      <span><i style="background:var(--fg)"></i>data</span>
      <span class="muted">· click a TCP row to follow/reassemble its stream</span>
    </div>
    <div class="controls">
      <input id="capQ" class="grow" placeholder="filter by IP, port, flag, info…">
      <select id="capClass">
        <option value="">all packets</option>
        <option value="reset">resets (RST)</option>
        <option value="error">ICMP errors</option>
        <option value="syn">SYN (connect)</option>
        <option value="fin">FIN (close)</option>
        <option value="data">data</option>
        <option value="other">other</option>
      </select>
      <select id="capProto">
        <option value="">all protocols</option>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
        <option value="icmp">ICMP</option>
      </select>
      <select id="capPageSize">
        <option value="200">200 / page</option>
        <option value="500" selected>500 / page</option>
        <option value="1000">1000 / page</option>
      </select>
      <button id="capRefresh">Refresh</button>
      <a class="dl" id="capDl" href="api/capturefile">⤓ pcap</a>
    </div>
    <div id="capTable"><div class="empty">Loading capture…</div></div>
    <div class="pager">
      <button id="capPrev">‹ Prev</button>
      <button id="capNext">Next ›</button>
      <span class="info" id="capPageInfo"></span>
    </div>
  </div>

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
      +'<span class="sp">'+btn+'</span>'
      +(l.reason?'<span class="reason">⚠ '+esc(l.reason)+'</span>':'')+'</div>';
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

// ---- network capture viewer ----
var capState={q:'',cls:'',proto:'',offset:0,limit:500,matched:0};
function loadCapture(){
  var p=new URLSearchParams();
  if(capState.q)p.set('q',capState.q);
  if(capState.cls)p.set('class',capState.cls);
  if(capState.proto)p.set('proto',capState.proto);
  p.set('offset',capState.offset);p.set('limit',capState.limit);
  fetch('api/capture?'+p.toString()).then(function(r){return r.json();}).then(function(d){
    capState.matched=d.matched||0;renderCapture(d);
  }).catch(function(e){document.getElementById('capTable').innerHTML='<div class="empty">Failed to load capture: '+esc(e)+'</div>';});
}
function renderCapture(d){
  var info=document.getElementById('capInfo');
  if(!d.total_parsed){
    info.textContent='— '+esc(d.file||'no capture file')+' (empty; run intercept mode to capture traffic)';
  }else{
    info.textContent='— '+esc(d.file)+' · '+d.total_parsed+' packets parsed'+(d.truncated?' (capped)':'')+' · '+d.matched+' match filter';
  }
  var ps=d.packets||[];
  if(!ps.length){
    document.getElementById('capTable').innerHTML='<div class="empty">No packets match this filter.</div>';
  }else{
    var head='<table class="cap"><thead><tr><th>#</th><th>Time</th><th>Proto</th><th>Source</th><th>Destination</th><th>Len</th><th>Info</th></tr></thead><tbody>';
    var rows=ps.map(function(x){
      var follow=(x.proto==='TCP'&&x.src&&x.dst)?(' data-a="'+esc(x.src)+'" data-b="'+esc(x.dst)+'" title="click: follow TCP stream"'):'';
      return '<tr class="cap-'+esc(x.class)+'"'+follow+'>'
        +'<td>'+x.no+'</td><td>'+esc(x.time)+'</td><td>'+esc(x.proto)+'</td>'
        +'<td>'+esc(x.src||'—')+'</td><td>'+esc(x.dst||'—')+'</td>'
        +'<td>'+esc(x.len)+'</td><td>'+esc(x.info)+'</td></tr>';
    }).join('');
    document.getElementById('capTable').innerHTML=head+rows+'</tbody></table>';
    Array.prototype.forEach.call(document.querySelectorAll('#capTable tr[data-a]'),function(tr){
      tr.onclick=function(){openStream(tr.getAttribute('data-a'),tr.getAttribute('data-b'));};
    });
  }
  var from=capState.matched?capState.offset+1:0;var to=Math.min(capState.offset+capState.limit,capState.matched);
  document.getElementById('capPageInfo').textContent='showing '+from+'–'+to+' of '+capState.matched;
  document.getElementById('capPrev').disabled=capState.offset<=0;
  document.getElementById('capNext').disabled=capState.offset+capState.limit>=capState.matched;
}
document.getElementById('captureBtn').onclick=function(){
  var p=document.getElementById('capturePanel');
  if(p.style.display==='none'){p.style.display='';capState.offset=0;loadCapture();p.scrollIntoView({behavior:'smooth'});}
  else{p.style.display='none';}
};
document.getElementById('capQ').addEventListener('input',function(){capState.q=this.value;capState.offset=0;
  clearTimeout(window._cqt);window._cqt=setTimeout(loadCapture,250);});
document.getElementById('capClass').addEventListener('change',function(){capState.cls=this.value;capState.offset=0;loadCapture();});
document.getElementById('capProto').addEventListener('change',function(){capState.proto=this.value;capState.offset=0;loadCapture();});
document.getElementById('capPageSize').addEventListener('change',function(){capState.limit=parseInt(this.value,10)||500;capState.offset=0;loadCapture();});
document.getElementById('capRefresh').onclick=loadCapture;
document.getElementById('capPrev').onclick=function(){capState.offset=Math.max(0,capState.offset-capState.limit);loadCapture();};
document.getElementById('capNext').onclick=function(){if(capState.offset+capState.limit<capState.matched){capState.offset+=capState.limit;loadCapture();}};

// ---- follow TCP stream (reassembly) ----
function hexdump(b64){
  if(!b64) return '<span class="muted">(no data this direction)</span>';
  var bin; try{bin=atob(b64);}catch(e){return '(decode error)';}
  var max=8192,n=Math.min(bin.length,max),out=[];
  for(var i=0;i<n;i+=16){
    var hex='',asc='';
    for(var j=0;j<16;j++){
      if(i+j<n){var c=bin.charCodeAt(i+j);hex+=('0'+c.toString(16)).slice(-2)+' ';asc+=(c>=32&&c<127)?bin[i+j]:'.';}
      else{hex+='   ';}
    }
    out.push(('00000000'+i.toString(16)).slice(-8)+'  '+hex+' '+esc(asc));
  }
  var s=out.join('\n');
  if(bin.length>max)s+='\n… '+(bin.length-max)+' more bytes (download the pcap for the full stream)';
  return s;
}
function openStream(a,b){
  fetch('api/capture/stream?a='+encodeURIComponent(a)+'&b='+encodeURIComponent(b))
  .then(function(r){return r.json();}).then(function(d){
    var html='<button class="close" id="modalClose">✕ close</button>'
      +'<h3>Follow TCP stream</h3>'
      +'<div class="muted">'+esc(a)+' ⇄ '+esc(b)+(d.capped?' · capped at 256 KiB/direction':'')+'</div>';
    if(!d.a_to_b_len&&!d.b_to_a_len){
      html+='<div class="empty">No reassembled payload for this flow (it may be control-only, or the data packets were not captured).</div>';
    }else{
      html+='<div style="margin-top:12px;color:var(--accent);font-weight:600;">▶ '+esc(a)+' → '+esc(b)+' (client → server, '+(d.a_to_b_len||0)+' bytes)</div>';
      html+='<div class="preview">'+hexdump(d.a_to_b)+'</div>';
      html+='<div style="margin-top:12px;color:var(--good);font-weight:600;">◀ '+esc(b)+' → '+esc(a)+' (server → client, '+(d.b_to_a_len||0)+' bytes)</div>';
      html+='<div class="preview">'+hexdump(d.b_to_a)+'</div>';
    }
    document.getElementById('modal').innerHTML=html;
    document.getElementById('overlay').classList.add('show');
    document.getElementById('modalClose').onclick=closeDetail;
  }).catch(function(e){setSettingsMsg&&0;alert('Follow stream failed: '+e);});
}

// ---- settings editor (full config parity) ----
// A schema-free recursive renderer: nested objects become grouped fieldsets,
// scalars become typed inputs (checkbox/number/text), and arrays / deep maps
// become JSON textareas (mirroring how the native GUI edits list/map blocks).
var origCfg=null;
function elc(tag){return document.createElement(tag);}
function labelFor(k){return k;}

function node(path,label,v){
  if(v!==null&&typeof v==='object'&&!Array.isArray(v)){
    var fs=elc('fieldset');fs.className='setgrp';
    var lg=elc('legend');lg.textContent=label;fs.appendChild(lg);
    Object.keys(v).forEach(function(k){fs.appendChild(node(path?path+'.'+k:k,k,v[k]));});
    return fs;
  }
  var row=elc('div');row.className='setrow';
  var lab=elc('label');lab.textContent=label;lab.title=path;row.appendChild(lab);
  var ctrl;
  if(v!==null&&typeof v==='object'){ // array → JSON textarea
    ctrl=elc('textarea');ctrl.className='setjson';
    var txt=JSON.stringify(v,null,2);
    ctrl.rows=Math.min(14,Math.max(2,txt.split('\n').length));ctrl.value=txt;ctrl.dataset.json='1';
  }else if(typeof v==='boolean'){
    ctrl=elc('input');ctrl.type='checkbox';ctrl.checked=v;
  }else if(typeof v==='number'){
    ctrl=elc('input');ctrl.type='number';ctrl.value=v;
  }else{
    ctrl=elc('input');ctrl.type='text';ctrl.value=(v==null?'':v);
  }
  ctrl.dataset.path=path;row.appendChild(ctrl);return row;
}

function buildSettingsForm(cfg){
  var root=elc('div');
  Object.keys(cfg).forEach(function(k){root.appendChild(node(k,k,cfg[k]));});
  return root;
}

function loadSettings(){
  setSettingsMsg('',false);
  var host=document.getElementById('settingsForm');
  host.innerHTML='<div class="empty">Loading settings…</div>';
  fetch('api/settings').then(function(r){return r.json();}).then(function(cfg){
    origCfg=cfg;host.innerHTML='';host.appendChild(buildSettingsForm(cfg));
  }).catch(function(e){host.innerHTML='<div class="empty">Failed to load settings: '+esc(e)+'</div>';});
}

function setPath(obj,path,val){
  var parts=path.split('.');var o=obj;
  for(var i=0;i<parts.length-1;i++){
    if(o[parts[i]]==null||typeof o[parts[i]]!=='object'){o[parts[i]]={};}
    o=o[parts[i]];
  }
  o[parts[parts.length-1]]=val;
}

function collectSettings(){
  if(!origCfg)throw 'settings not loaded';
  var out=JSON.parse(JSON.stringify(origCfg));
  var ctrls=document.getElementById('settingsForm').querySelectorAll('[data-path]');
  for(var i=0;i<ctrls.length;i++){
    var c=ctrls[i],p=c.dataset.path,val;
    if(c.dataset.json==='1'){
      try{val=JSON.parse(c.value);}catch(e){throw 'Invalid JSON in "'+p+'": '+e.message;}
    }else if(c.type==='checkbox'){val=c.checked;}
    else if(c.type==='number'){val=(c.value===''?0:Number(c.value));}
    else{val=c.value;}
    setPath(out,p,val);
  }
  return out;
}

function setSettingsMsg(msg,isErr){
  var el=document.getElementById('setMsg');
  if(!msg){el.innerHTML='';return;}
  el.className='setmsg '+(isErr?'err':'ok');el.textContent=msg;
}

function saveSettings(restart){
  var body;
  try{body=collectSettings();}catch(e){setSettingsMsg(String(e),true);return;}
  setSettingsMsg('Saving…',false);
  fetch('api/settings?restart='+(restart?'true':'false'),{
    method:'POST',headers:{'X-Requested-With':'printcap','Content-Type':'application/json'},body:JSON.stringify(body)
  }).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
  .then(function(res){
    if(!res.ok||!res.d.ok){
      var errs=(res.d&&res.d.errors)?res.d.errors.join('\n'):'save rejected';
      setSettingsMsg('NOT saved — fix these and try again:\n'+errs,true);return;
    }
    var m='Saved to disk.'+(restart?' Engine restarting — this dashboard may drop briefly, then reload.':' (Not applied to the running engine until restart.)');
    if(res.d.warnings&&res.d.warnings.length)m+='\n\nWarnings:\n'+res.d.warnings.join('\n');
    setSettingsMsg(m,false);
  }).catch(function(e){setSettingsMsg('Request failed: '+e+' (if you restarted, the dashboard is bouncing — wait a moment and refresh)',true);});
}

document.getElementById('settingsBtn').onclick=function(){
  var p=document.getElementById('settingsPanel');
  if(p.style.display==='none'){p.style.display='';loadSettings();p.scrollIntoView({behavior:'smooth'});}
  else{p.style.display='none';}
};
document.getElementById('setReload').onclick=loadSettings;
document.getElementById('setClose').onclick=function(){document.getElementById('settingsPanel').style.display='none';};
document.getElementById('setSave').onclick=function(){saveSettings(false);};
document.getElementById('setSaveRestart').onclick=function(){
  if(confirm('Save and restart the engine? The dashboard will briefly drop.'))saveSettings(true);
};

loadStatsOnce();loadJobs();refreshLogs();startSSE();
setInterval(refreshLogs,3000);
</script>
</body>
</html>`
