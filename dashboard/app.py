import os,sys,time,argparse,threading,pickle
import numpy as np
sys.path.insert(0,os.path.join(os.path.dirname(__file__),'..'))
from config import ALERT_THRESHOLD,FEATURE_NAMES,MODELS_DIR,FEATURE_WINDOW

try:
    from flask import Flask,jsonify,render_template_string,request
except ImportError:
    print("[ERROR] pip install flask");sys.exit(1)

from src.models.detector      import RansomwareDetector
from src.alerts.alert_manager import AlertManager
from src.response.incident_responder import IncidentResponder

try:
    from src.detection.honeypot import HoneypotSystem
    _HP=True
except: _HP=False

app=Flask(__name__)
_detector=None;_honeypot=None;_am=None;_responder=None
_all_models={};_running=True

def _load_all_models():
    for nm in ['randomforest','xgboost','svm','neuralnetwork']:
        p=os.path.join(MODELS_DIR,f'{nm}.pkl')
        if os.path.exists(p):
            try:
                with open(p,'rb') as f: obj=pickle.load(f)
                if hasattr(obj,'predict_proba'): _all_models[nm]=obj
            except: pass

_last_fkey=None;_last_ms={}
def _score_all(feats):
    global _last_fkey,_last_ms
    if not feats: return {}
    key=hash(tuple(round(f,1) for f in feats))
    if key==_last_fkey: return _last_ms
    _last_fkey=key
    X=np.array(feats).reshape(1,-1); scores={}
    for nm,m in _all_models.items():
        try: scores[nm]=round(float(m.predict_proba(X)[0,1]),4)
        except: scores[nm]=0.0
    _last_ms=scores; return scores

_W={'xgboost':.35,'randomforest':.30,'neuralnetwork':.20,'svm':.15}
def _ensemble(ms):
    if not ms: return {'e':0.,'cons':'—','v':0,'t':0}
    tw=sum(_W.get(k,.2) for k in ms)
    ws=sum(ms[k]*_W.get(k,.2) for k in ms)
    e=round(ws/tw if tw else 0,4)
    ab=sum(1 for s in ms.values() if s>=ALERT_THRESHOLD)
    t=len(ms)
    return {'e':e,'cons':'AGREE' if ab==t else('DISAGREE' if ab==0 else 'SPLIT'),'v':ab,'t':t}

def _explain(feats,score):
    if score<.5 or not feats: return {}
    fd=dict(zip(FEATURE_NAMES,feats))
    D={'file_rename_count':10,'avg_entropy':7.2,'extension_change_count':5,
       'write_ops_per_sec':15,'high_entropy_ratio':.6,'file_modify_count':15}
    sigs=[]
    for f,th in D.items():
        v=fd.get(f,0)
        if v>th: sigs.append({'feature':f,'value':round(v,2),'pct':round(min(v/th*20,100),1)})
    sigs.sort(key=lambda x:-x['pct'])
    parts=[]
    for s in sigs[:3]:
        f,v=s['feature'],s['value']
        if f=='file_rename_count':    parts.append(f"{v:.0f} renames")
        elif f=='avg_entropy':        parts.append(f"entropy {v:.2f}b")
        elif f=='extension_change_count': parts.append(f"{v:.0f} ext changes")
        elif f=='write_ops_per_sec':  parts.append(f"{v:.1f} writes/s")
        elif f=='high_entropy_ratio': parts.append(f"{v*100:.0f}% high-entropy")
    return {'top':sigs[:5],'summary':'Triggered by: '+'; '.join(parts)+'.' if parts else 'Anomalous pattern.'}

def _on_canary(a):
    if _am: _am.dispatch(a)

HTML=r"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RansomShield AI v2</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
:root{
  --bg:#070d18;--c:#0c1422;--c2:#101d30;--bd:#192840;
  --tx:#d8e4f0;--mu:#4a5f7a;--ac:#2979f5;
  --ok:#14c47a;--wa:#e8a000;--da:#e83535;--cr:#c42020;--pu:#9945e8;
  --r:10px;
}
html,body{height:100%;overflow:hidden;}
body{background:var(--bg);color:var(--tx);font-family:'Segoe UI',system-ui,sans-serif;
     display:flex;flex-direction:column;}

/* ── CRITICAL ── */
@keyframes cb{0%,100%{background:#070d18}50%{background:#180404}}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.78)}}
@keyframes fadeIn{from{background:#1a0404}to{background:transparent}}
body.crit{animation:cb .85s infinite;}

/* ── HEADER ── */
.hdr{flex-shrink:0;background:var(--c);border-bottom:1px solid var(--bd);
     padding:7px 16px;display:flex;align-items:center;gap:9px;}
.logo{font-size:.85rem;font-weight:700;display:flex;align-items:center;gap:6px;}
.li{width:22px;height:22px;background:var(--ac);border-radius:5px;
    display:flex;align-items:center;justify-content:center;font-size:11px;}
.v2{background:var(--pu);color:#fff;font-size:.55rem;padding:1px 4px;border-radius:3px;font-weight:700;}
.ld{width:6px;height:6px;border-radius:50%;background:var(--ok);box-shadow:0 0 4px var(--ok);}
.ld:not(.p){animation:pulse 1.5s infinite;}.ld.p{background:var(--wa);box-shadow:0 0 4px var(--wa);}
.clk{font-size:.68rem;color:var(--mu);}
.hr2{margin-left:auto;display:flex;align-items:center;gap:5px;}
.hb{background:var(--c2);border:1px solid var(--bd);color:var(--mu);padding:4px 10px;
    border-radius:6px;cursor:pointer;font-size:.67rem;font-family:inherit;transition:all .18s;}
.hb:hover{color:var(--tx);border-color:var(--ac);}.hb.on{color:var(--ac);border-color:var(--ac);}
.chip{padding:4px 10px;border-radius:999px;font-size:.68rem;font-weight:700;letter-spacing:.04em;transition:all .3s;}
.ok{background:#082012;color:var(--ok);border:1px solid #0d3a1e;}
.low{background:#181100;color:#f5bc24;border:1px solid #8a3c00;}
.med{background:#180c00;color:#f88c24;border:1px solid #902d0a;}
.hi{background:#180303;color:#f46060;border:1px solid #8a1616;}
.cr{background:var(--cr);color:#fff;border:1px solid var(--da);animation:pulse .55s infinite;}

/* ── PHASE ── */
.ph{flex-shrink:0;background:var(--c);border-bottom:1px solid var(--bd);
    padding:5px 16px;display:flex;align-items:center;}
.pstep{display:flex;align-items:center;flex:1;}
.pnode{display:flex;flex-direction:column;align-items:center;gap:1px;min-width:80px;}
.pdot{width:9px;height:9px;border-radius:50%;border:2px solid var(--bd);background:var(--bg);transition:all .4s;}
.plbl{font-size:.53rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;text-align:center;transition:color .4s;}
.ptm{font-size:.5rem;color:var(--mu);}
.pline{flex:1;height:1.5px;background:var(--bd);transition:background .4s;}

/* ── SCROLL BODY ── */
.scroll{flex:1;overflow-y:auto;overflow-x:hidden;padding:8px 14px;
        display:flex;flex-direction:column;gap:8px;}
.scroll::-webkit-scrollbar{width:5px;}
.scroll::-webkit-scrollbar-track{background:var(--bg);}
.scroll::-webkit-scrollbar-thumb{background:var(--bd);border-radius:3px;}

/* ── HONEYPOT BAR ── */
.hp{border-radius:var(--r);padding:7px 12px;display:flex;align-items:center;gap:10px;
    flex-shrink:0;transition:all .4s;}
.hp.safe{background:#040e08;border:1px solid #0b321a;}
.hp.warn{background:#160303;border:1px solid #881212;}
@keyframes hb{0%,100%{opacity:1}50%{opacity:.4}}
.hp.warn{animation:hb .8s infinite;}
.hpico{font-size:1.2rem;flex-shrink:0;}
.hptx{flex:1;min-width:0;}
.hptitle{font-size:.74rem;font-weight:700;}
.hpdet{font-size:.63rem;color:var(--mu);display:flex;gap:10px;flex-wrap:wrap;margin-top:1px;}
.dot{width:5px;height:5px;border-radius:50%;display:inline-block;margin-right:2px;flex-shrink:0;}
.hpmsg{font-size:.62rem;color:var(--mu);max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}

/* ── KPI ROW ── */
.krow{display:grid;grid-template-columns:140px repeat(5,1fr);gap:7px;flex-shrink:0;}
.gc{background:var(--c);border:1px solid var(--bd);border-radius:var(--r);
    padding:9px;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.gw{position:relative;width:100px;height:100px;}
.gw svg{transform:rotate(-90deg);}
.gtr{fill:none;stroke:#172438;stroke-width:9;stroke-linecap:round;}
.gfl{fill:none;stroke-width:9;stroke-linecap:round;stroke-dasharray:270;
     stroke-dashoffset:270;transition:stroke-dashoffset .5s,stroke .4s;}
.gtx{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;}
.gsc{font-size:1.3rem;font-weight:800;line-height:1;}.glb{font-size:.52rem;color:var(--mu);letter-spacing:.09em;}
.gtag{font-size:.54rem;color:var(--mu);margin-top:5px;text-transform:uppercase;letter-spacing:.06em;}
.kpi{background:var(--c);border:1px solid var(--bd);border-radius:var(--r);
     padding:9px 11px;border-left:3px solid var(--bd);transition:border-color .4s;}
.kpi.bl{border-left-color:var(--ac);}.kpi.rd{border-left-color:var(--da);}
.kpi.gn{border-left-color:var(--ok);}.kpi.wn{border-left-color:var(--wa);}.kpi.pu{border-left-color:var(--pu);}
.kl{font-size:.57rem;color:var(--mu);text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px;}
.kv{font-size:1.35rem;font-weight:800;line-height:1;}.ks{font-size:.58rem;color:var(--mu);margin-top:1px;}

/* ── MID ROW ── */
.mid{display:grid;grid-template-columns:1fr 230px;gap:7px;}
.panel{background:var(--c);border:1px solid var(--bd);border-radius:var(--r);padding:10px 12px;}
.ptitle{font-size:.58rem;color:var(--mu);text-transform:uppercase;letter-spacing:.08em;margin-bottom:7px;}
.chtop{display:flex;align-items:center;gap:4px;flex-wrap:wrap;margin-bottom:7px;}
.rb{background:var(--c2);border:1px solid var(--bd);color:var(--mu);padding:2px 7px;
    border-radius:4px;cursor:pointer;font-size:.6rem;font-family:inherit;transition:all .13s;}
.rb:hover,.rb.a{background:var(--ac);color:#fff;border-color:var(--ac);}
.pb{background:var(--c2);border:1px solid var(--bd);color:var(--mu);padding:2px 5px;
    border-radius:4px;cursor:pointer;font-size:.65rem;font-family:inherit;min-width:22px;transition:all .13s;}
.pb:hover{color:var(--tx);border-color:var(--ac);}
.pb.lv{background:#082012;color:var(--ok);border-color:#0d3a1e;}
.sep{width:1px;height:12px;background:var(--bd);}
.ch-wrap{position:relative;height:120px;}
#hs{-webkit-appearance:none;width:100%;height:2px;border-radius:1px;margin-top:5px;
    background:linear-gradient(to right,var(--ac) 0%,var(--bd) 0%);cursor:pointer;outline:none;}
#hs::-webkit-slider-thumb{-webkit-appearance:none;width:11px;height:11px;border-radius:50%;
    background:var(--ac);cursor:pointer;border:2px solid var(--bg);}
.pstrip{margin-top:4px;height:4px;border-radius:2px;background:var(--bd);overflow:hidden;display:flex;}

/* MODEL SCORES */
.mr{margin-bottom:6px;}.mr:last-child{margin-bottom:0;}
.mh{display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;}
.mn{font-size:.63rem;color:var(--mu);}.mv{font-size:.67rem;font-weight:700;}
.mt{height:5px;background:var(--bd);border-radius:3px;overflow:hidden;}
.mf{height:100%;border-radius:3px;transition:width .5s,background .4s;}
.mfoot{display:flex;justify-content:space-between;align-items:center;
       margin-top:7px;padding-top:6px;border-top:1px solid var(--bd);}
.cons{font-size:.6rem;padding:2px 7px;border-radius:999px;font-weight:700;}
.cons.AGREE{background:#082012;color:var(--ok);}
.cons.SPLIT{background:#181100;color:#f5bc24;}
.cons.DISAGREE{background:#180303;color:#f46060;}

/* ── BOTTOM ROW ── */
.bot{display:grid;grid-template-columns:185px 1fr 255px;gap:7px;}

/* SIGNALS */
.si{margin-bottom:6px;}.si:last-child{margin-bottom:0;}
.sr{display:flex;justify-content:space-between;margin-bottom:2px;}
.sn{font-size:.6rem;color:var(--mu);}.sv{font-size:.63rem;font-weight:700;}
.str{height:4px;background:var(--bd);border-radius:2px;overflow:hidden;}
.sf{height:100%;border-radius:2px;transition:width .5s,background .3s;}

/* ALERT TABLE */
.tw{overflow-x:auto;overflow-y:auto;max-height:160px;}
table{width:100%;border-collapse:collapse;white-space:nowrap;}
th{font-size:.55rem;color:var(--mu);text-transform:uppercase;letter-spacing:.06em;
   padding:4px 7px;border-bottom:1px solid var(--bd);text-align:left;
   background:var(--c2);position:sticky;top:0;}
td{padding:5px 7px;font-size:.68rem;border-bottom:1px solid #09131f;}
tr:last-child td{border-bottom:none;}
tr.fl td{animation:fadeIn .8s;}
.badge{display:inline-block;padding:1px 5px;border-radius:999px;font-size:.57rem;font-weight:700;}
.badge.OK{background:#082012;color:var(--ok);}
.badge.LOW{background:#181100;color:#f5bc24;}
.badge.MEDIUM{background:#180c00;color:#f88c24;}
.badge.HIGH{background:#180303;color:#f46060;}
.badge.CRITICAL{background:var(--cr);color:#fff;}
.badge.HONEYPOT{background:#6e1fb8;color:#fff;}
.empty{text-align:center;color:var(--mu);padding:12px;font-size:.68rem;}

/* SHAP under table */
.shap{margin-top:8px;border-top:1px solid var(--bd);padding-top:7px;display:none;}
.shap-title{font-size:.56rem;color:var(--mu);text-transform:uppercase;letter-spacing:.07em;margin-bottom:5px;}
.sh-row{display:flex;align-items:center;gap:5px;margin-bottom:4px;}
.sh-nm{font-size:.58rem;color:var(--mu);width:108px;flex-shrink:0;
       white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sh-bw{flex:1;height:4px;background:var(--bd);border-radius:2px;overflow:hidden;}
.sh-bf{height:100%;border-radius:2px;transition:width .5s;background:#e83535;}
.sh-pc{font-size:.58rem;color:#f46060;width:28px;text-align:right;flex-shrink:0;}
.sh-sum{font-size:.62rem;color:var(--mu);line-height:1.45;margin-top:5px;padding:5px 7px;
        background:var(--c2);border-radius:5px;border-left:2px solid var(--ac);}

/* RESPONSE */
.rg{display:grid;grid-template-columns:1fr 1fr;gap:5px;margin-bottom:6px;}
.ab{background:var(--c2);border:1px solid var(--bd);color:var(--tx);padding:6px 3px;
    border-radius:6px;cursor:pointer;font-size:.6rem;font-family:inherit;
    text-align:center;transition:all .18s;display:flex;flex-direction:column;align-items:center;gap:1px;}
.ab:hover{border-color:var(--ac);}.ab .ai{font-size:.85rem;}
.ab.d{border-color:#881212;color:#f46060;}.ab.d:hover{background:#180303;}
.ab.r{border-color:#0d3a1e;color:var(--ok);}.ab.r:hover{background:#082012;}
.ns{font-size:.6rem;padding:3px 7px;border-radius:4px;text-align:center;margin-bottom:5px;transition:all .3s;}
.ns.c{background:#082012;color:var(--ok);}.ns.i{background:#180303;color:#f46060;}
.rl{max-height:80px;overflow-y:auto;display:flex;flex-direction:column;gap:3px;}
.ri{font-size:.58rem;padding:3px 6px;border-radius:4px;border-left:2px solid var(--bd);}
.ri.success{border-color:var(--ok);background:#060e08;}.ri.failed{border-color:var(--da);background:#160303;}
.ri.skipped{border-color:var(--mu);background:#0b1320;}.ri.warning{border-color:var(--wa);background:#141000;}
.rn{font-weight:600;color:var(--tx);font-size:.6rem;}.rm{color:var(--mu);font-size:.57rem;margin-top:1px;}
.rt{color:var(--mu);font-size:.55rem;float:right;}
</style>
</head>
<body>

<!-- HEADER -->
<div class="hdr">
  <div class="logo"><div class="li">🛡</div>RansomShield AI<span class="v2">v2</span></div>
  <div class="ld" id="ld"></div>
  <span id="ll" style="font-size:.62rem;color:var(--ok);font-weight:600">LIVE</span>
  <span class="clk" id="clk"></span>
  <div class="hr2">
    <button class="hb" id="sb" onclick="togS()">🔔 Sound</button>
    <button class="hb" onclick="expCSV()">⬇ Export</button>
    <span class="chip ok" id="chip">● MONITORING</span>
  </div>
</div>

<!-- PHASE -->
<div class="ph">
  <div class="pstep"><div class="pnode">
    <div class="pdot" id="ph0" style="color:var(--ok)"></div>
    <div class="plbl" id="pl0">SAFE</div><div class="ptm" id="pt0"></div>
  </div><div class="pline" id="pln0"></div></div>
  <div class="pstep"><div class="pnode">
    <div class="pdot" id="ph1" style="color:#f5bc24"></div>
    <div class="plbl" id="pl1">LOW RISK</div><div class="ptm" id="pt1"></div>
  </div><div class="pline" id="pln1"></div></div>
  <div class="pstep"><div class="pnode">
    <div class="pdot" id="ph2" style="color:#f88c24"></div>
    <div class="plbl" id="pl2">SUSPICIOUS</div><div class="ptm" id="pt2"></div>
  </div><div class="pline" id="pln2"></div></div>
  <div class="pstep"><div class="pnode">
    <div class="pdot" id="ph3" style="color:#f46060"></div>
    <div class="plbl" id="pl3">UNDER ATTACK</div><div class="ptm" id="pt3"></div>
  </div><div class="pline" id="pln3"></div></div>
  <div style="flex:0"><div class="pnode">
    <div class="pdot" id="ph4" style="color:var(--ok)"></div>
    <div class="plbl" id="pl4">CONTAINED</div><div class="ptm" id="pt4"></div>
  </div></div>
</div>

<!-- SCROLLABLE BODY -->
<div class="scroll">

  <!-- HONEYPOT -->
  <div class="hp safe" id="hpb">
    <div class="hpico">🍯</div>
    <div class="hptx">
      <div class="hptitle" id="hptitle">Honeypot Canaries — Active</div>
      <div class="hpdet">
        <span><span class="dot" style="background:var(--ok)"></span><span id="hpI">0 intact</span></span>
        <span><span class="dot" style="background:var(--mu)"></span><span id="hpT">0 total</span></span>
        <span><span class="dot" style="background:var(--da)"></span><span id="hpTr">0 triggered</span></span>
      </div>
    </div>
    <span class="hpmsg" id="hpmsg">AAA_* decoy files — any ransomware touch = instant alert</span>
  </div>

  <!-- KPI -->
  <div class="krow">
    <div class="gc">
      <div class="gw">
        <svg width="100" height="100" viewBox="0 0 100 100">
          <circle class="gtr" cx="50" cy="50" r="43"/>
          <circle class="gfl" id="gfl" cx="50" cy="50" r="43"/>
        </svg>
        <div class="gtx"><div class="gsc" id="gsc">—</div><div class="glb">THREAT</div></div>
      </div>
      <div class="gtag">Ensemble Score</div>
    </div>
    <div class="kpi bl"><div class="kl">Current Score</div><div class="kv" id="ksc">—</div><div class="ks" id="kss">Waiting...</div></div>
    <div class="kpi rd"><div class="kl">Alerts Fired</div><div class="kv" id="kal">0</div><div class="ks" id="kas">No alerts</div></div>
    <div class="kpi gn"><div class="kl">Session Peak</div><div class="kv" id="kpk">0.000</div><div class="ks" id="kpt">—</div></div>
    <div class="kpi pu"><div class="kl">Detection Latency</div><div class="kv" id="klat">—</div><div class="ks">Time to detect</div></div>
    <div class="kpi wn"><div class="kl">Consensus</div><div class="kv" id="kcon">—</div><div class="ks" id="kvot">0/0 agree</div></div>
  </div>

  <!-- MID: Chart + Models -->
  <div class="mid">
    <div class="panel">
      <div class="chtop">
        <span class="ptitle" style="margin:0">Threat Timeline</span>
        <button class="rb a" onclick="setR(60,this)">1m</button>
        <button class="rb" onclick="setR(300,this)">5m</button>
        <button class="rb" onclick="setR(600,this)">10m</button>
        <button class="rb" onclick="setR(99999,this)">All</button>
        <div class="sep"></div>
        <button class="pb" onclick="panL()">◀◀</button>
        <button class="pb" onclick="pan(-30)">◀</button>
        <button class="pb" onclick="pan(30)">▶</button>
        <button class="pb lv" id="lvbtn" onclick="goLive()">▶▶ LIVE</button>
      </div>
      <div class="ch-wrap"><canvas id="ch"></canvas></div>
      <input type="range" id="hs" min="0" max="0" value="0" oninput="onSlider(this.value)">
      <div class="pstrip" id="pstrip"></div>
    </div>
    <div class="panel">
      <div class="ptitle">4 Model Scores</div>
      <div id="msc"><div class="empty" style="padding:6px;font-size:.65rem">Loading...</div></div>
    </div>
  </div>

  <!-- BOTTOM: Signals + Alerts + Response -->
  <div class="bot">

    <!-- Signals -->
    <div class="panel">
      <div class="ptitle">Signal Breakdown</div>
      <div id="sigs"></div>
    </div>

    <!-- Alert Table -->
    <div class="panel">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px;">
        <div class="ptitle" style="margin:0">Recent Alerts</div>
        <span style="font-size:.6rem;color:var(--mu)" id="acnt">0 alerts</span>
      </div>
      <div class="tw">
        <table>
          <thead><tr>
            <th>Time</th><th>Score</th><th>Type</th><th>Level</th>
            <th>Renames</th><th>Entropy</th><th>W/s</th>
          </tr></thead>
          <tbody id="tb"><tr><td colspan="7" class="empty">Monitoring...</td></tr></tbody>
        </table>
      </div>
      <div class="shap" id="shapDiv">
        <div class="shap-title">🔍 Why This Alert?</div>
        <div id="shapCnt"></div>
      </div>
    </div>

    <!-- Response -->
    <div class="panel">
      <div class="ptitle">🚨 Response Center</div>
      <div class="ns c" id="nsSt">🌐 Network: CONNECTED</div>
      <div class="rg">
        <button class="ab d" onclick="act('evidence')"><span class="ai">📋</span>Evidence</button>
        <button class="ab d" onclick="act('process')"><span class="ai">💀</span>Kill Process</button>
        <button class="ab d" onclick="act('network')"><span class="ai">🔌</span>Isolate Net</button>
        <button class="ab d" onclick="act('quarantine')"><span class="ai">📦</span>Quarantine</button>
        <button class="ab r" onclick="act('network_restore')"><span class="ai">🔓</span>Restore Net</button>
        <button class="ab" onclick="actAll()"><span class="ai">⚡</span>RESPOND ALL</button>
      </div>
      <div style="font-size:.57rem;color:var(--mu);margin-bottom:4px;text-transform:uppercase;letter-spacing:.07em">Response Log</div>
      <div class="rl" id="rlog"><div class="empty" style="padding:4px">No actions yet</div></div>
    </div>

  </div>
</div><!-- /scroll -->

<script>
const T={{ threshold }};
const H={labels:[],scores:[],aidx:[]};
let vSz=60,panOff=0,isLv=true,maxSc=0,maxT='';
let lastAl=0,sndOn=false,ac2=null,atkT=null,detT=null;
const phT=[null,null,null,null,null];
const phC=['var(--ok)','#f5bc24','#f88c24','#f46060','var(--ok)'];
const cMap={OK:'ok',LOW:'low',MEDIUM:'med',HIGH:'hi',CRITICAL:'cr'};

// ── CHART ─────────────────────────────────────────────────────────────────────
const myChart=new Chart(document.getElementById('ch'),{
  type:'line',
  data:{labels:[],datasets:[
    {label:'Threat Score',data:[],fill:true,borderColor:'#2979f5',
     backgroundColor:'rgba(41,121,245,0.07)',borderWidth:2,
     tension:.35,pointRadius:0,pointHoverRadius:4},
    {label:'Threshold ('+T+')',data:[],fill:false,
     borderColor:'rgba(232,53,53,.5)',borderDash:[5,4],
     pointRadius:0,borderWidth:1.2}
  ]},
  options:{
    responsive:true,maintainAspectRatio:false,animation:false,
    interaction:{intersect:false,mode:'index'},
    scales:{
      y:{min:0,max:1,grid:{color:'rgba(25,40,64,.9)'},
         ticks:{color:'#4a5f7a',font:{size:9},callback:v=>v.toFixed(1)}},
      x:{grid:{color:'rgba(7,13,24,.9)'},
         ticks:{color:'#4a5f7a',font:{size:8},maxTicksLimit:6,maxRotation:0}}
    },
    plugins:{
      legend:{labels:{color:'#6a7f9a',boxWidth:9,font:{size:9},padding:10}},
      tooltip:{backgroundColor:'#0c1422',borderColor:'#192840',borderWidth:1,
        titleColor:'#d8e4f0',bodyColor:'#6a7f9a',padding:7}
    }
  }
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
function sc(s){return s>=.9?'#c42020':s>=.75?'#e83535':s>=.65?'#e87520':s>=.5?'#e8a000':'#14c47a';}
function getVS(){const n=H.labels.length;
  if(isLv)return Math.max(0,n-vSz);
  return Math.max(0,Math.min(n-vSz,n-vSz-panOff));}
function rChart(){
  const s=getVS(),n=H.labels.length,e=Math.min(n,s+vSz);
  const vl=H.labels.slice(s,e),vs=H.scores.slice(s,e);
  myChart.data.labels=vl;
  myChart.data.datasets[0].data=vs;
  myChart.data.datasets[0].borderColor=vs.length?sc(vs[vs.length-1]):'#2979f5';
  myChart.data.datasets[1].data=vs.map(()=>T);
  myChart.update();
  const sl=document.getElementById('hs'),mx=Math.max(0,n-vSz);
  sl.max=mx;sl.value=mx-panOff;
  const pct=mx>0?(mx-panOff)/mx*100:100;
  sl.style.background=`linear-gradient(to right,var(--ac) ${pct}%,var(--bd) ${pct}%)`;
  const clr=v=>v>=.7?'#e83535':v>=.5?'#e8a000':v>=.4?'#e8c000':'#14c47a';
  document.getElementById('pstrip').innerHTML=vs.map(v=>
    `<div style="flex:1;background:${clr(v)};opacity:.7"></div>`).join('');
}
function setR(n,btn){vSz=n;isLv=true;panOff=0;
  document.querySelectorAll('.rb').forEach(b=>b.classList.remove('a'));
  btn.classList.add('a');rChart();}
function pan(d){isLv=false;panOff=Math.max(0,Math.min(H.labels.length-vSz,panOff-d));setLUI(false);rChart();}
function panL(){isLv=false;panOff=Math.max(0,H.labels.length-vSz);setLUI(false);rChart();}
function goLive(){isLv=true;panOff=0;setLUI(true);rChart();}
function onSlider(v){const mx=Math.max(0,H.labels.length-vSz);
  panOff=mx-parseInt(v);isLv=panOff<=0;setLUI(isLv);rChart();}
function setLUI(lv){
  document.getElementById('ld').classList.toggle('p',!lv);
  document.getElementById('ll').textContent=lv?'LIVE':'PAUSED';
  document.getElementById('ll').style.color=lv?'var(--ok)':'var(--wa)';
  document.getElementById('lvbtn').classList.toggle('lv',lv);}
function updPhase(score){
  let cur=0;
  if(score>=.9)cur=4;else if(score>=.7)cur=3;else if(score>=.5)cur=2;else if(score>=.4)cur=1;
  for(let i=0;i<=4;i++){
    const dot=document.getElementById('ph'+i);
    const lbl=document.getElementById('pl'+i);
    const ln=document.getElementById('pln'+i);
    const done=i<cur,active=i===cur;
    if(!phT[i]&&(active||done)){phT[i]=new Date().toLocaleTimeString();document.getElementById('pt'+i).textContent=phT[i];}
    dot.style.background=done||active?phC[i]:'var(--bg)';
    dot.style.borderColor=done||active?phC[i]:'var(--bd)';
    lbl.style.color=active?phC[i]:done?phC[i]:'var(--mu)';
    lbl.style.fontWeight=active?'700':'400';
    if(ln)ln.style.background=done?phC[i]:'var(--bd)';}}
function trackLat(score){
  const now=Date.now();
  if(score>=.5&&!atkT)atkT=now;
  if(score>=T&&!detT&&atkT){detT=now;
    document.getElementById('klat').textContent=((detT-atkT)/1000).toFixed(1)+'s';
    document.getElementById('klat').style.color='var(--da)';}
  if(score<.4){atkT=null;detT=null;document.getElementById('klat').textContent='—';}}
function togS(){sndOn=!sndOn;const b=document.getElementById('sb');
  b.textContent=sndOn?'🔔 ON':'🔔 Sound';b.classList.toggle('on',sndOn);if(sndOn)beep(440,80);}
function beep(f=880,d=200){if(!sndOn)return;
  try{if(!ac2)ac2=new AudioContext();const o=ac2.createOscillator(),g=ac2.createGain();
    o.connect(g);g.connect(ac2.destination);o.frequency.value=f;
    g.gain.setValueAtTime(.25,ac2.currentTime);
    g.gain.exponentialRampToValueAtTime(.001,ac2.currentTime+d/1000);
    o.start();o.stop(ac2.currentTime+d/1000);}catch(e){}}
function expCSV(){
  const rows=[['Time','Score','Type','Level','Renames','Entropy','WriteOps_s']];
  document.querySelectorAll('#tb tr[data-ts]').forEach(r=>{
    rows.push([...r.querySelectorAll('td')].map(td=>td.textContent.trim()));});
  if(rows.length<2){alert('No alerts yet.');return;}
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(rows.map(r=>r.join(',')).join('\n'));
  a.download='ransomshield_'+Date.now()+'.csv';a.click();}
setInterval(()=>document.getElementById('clk').textContent=new Date().toLocaleTimeString(),1000);
document.getElementById('clk').textContent=new Date().toLocaleTimeString();
const SIGS=[
  {k:'file_rename_count',n:'Renames',mx:60,th:10},
  {k:'avg_entropy',n:'Entropy',mx:8,th:7.2},
  {k:'extension_change_count',n:'Ext changes',mx:40,th:8},
  {k:'write_ops_per_sec',n:'Writes/sec',mx:80,th:15},
  {k:'high_entropy_ratio',n:'High-ent %',mx:1,th:.6},
  {k:'cpu_percent',n:'CPU %',mx:100,th:70},
];

// ── MAIN REFRESH ──────────────────────────────────────────────────────────────
async function refresh(){
  let d;try{d=await(await fetch('/api/status')).json();}catch(e){return;}
  const score=d.score??0,level=d.level??'OK',feats=d.features??{};
  const alerts=d.alerts??[],alCnt=d.alert_count??0;
  const ms=d.model_scores??{},cons=d.consensus??'—';
  const vcnt=d.vote_count??0,tot=d.total_models??0;
  const now=new Date().toLocaleTimeString();

  H.labels.push(now);H.scores.push(score);
  if(alCnt>lastAl){H.aidx.push(H.labels.length-1);beep(level==='CRITICAL'?1200:880,300);lastAl=alCnt;}
  if(isLv)rChart();

  // Gauge
  const off=270*(1-Math.min(score,1));
  document.getElementById('gfl').style.strokeDashoffset=off;
  document.getElementById('gfl').style.stroke=sc(score);
  document.getElementById('gsc').textContent=score.toFixed(3);
  document.getElementById('gsc').style.color=sc(score);

  // Chip
  const chip=document.getElementById('chip');
  chip.className='chip '+(cMap[level]||'ok');
  chip.textContent=level==='OK'?'● MONITORING':'🚨 '+level;
  document.body.classList.toggle('crit',level==='CRITICAL');

  // KPIs
  document.getElementById('ksc').textContent=score.toFixed(3);
  document.getElementById('ksc').style.color=sc(score);
  document.getElementById('kss').textContent=level==='OK'?'Normal':'⚠️ '+level;
  document.getElementById('kal').textContent=alCnt;
  if(alCnt>0){const la=alerts[alerts.length-1];document.getElementById('kas').textContent='Last: '+new Date(la.ts*1000).toLocaleTimeString();}
  if(score>maxSc){maxSc=score;maxT=now;
    document.getElementById('kpk').textContent=score.toFixed(3);
    document.getElementById('kpk').style.color=sc(score);
    document.getElementById('kpt').textContent='At '+now;}
  document.getElementById('kcon').textContent=cons;
  document.getElementById('kcon').style.color=cons==='AGREE'?'var(--da)':cons==='SPLIT'?'var(--wa)':'var(--ok)';
  document.getElementById('kvot').textContent=vcnt+'/'+tot+' agree';
  document.getElementById('acnt').textContent=alCnt+' alerts';
  updPhase(score);trackLat(score);

  // Model scores
  if(Object.keys(ms).length){
    document.getElementById('msc').innerHTML=
      Object.entries(ms).map(([nm,sv])=>{
        const pct=Math.min(100,sv*100),hot=sv>=T;
        return`<div class="mr"><div class="mh">
          <span class="mn">${nm}</span>
          <span class="mv" style="color:${hot?'#f46060':'var(--tx)'}">${sv.toFixed(3)}</span>
        </div><div class="mt">
          <div class="mf" style="width:${pct}%;background:${hot?'var(--da)':'var(--ac)'}"></div>
        </div></div>`;}).join('')+
      `<div class="mfoot">
        <span class="cons ${cons}">${cons}</span>
        <span style="font-size:.57rem;color:var(--mu)">${vcnt}/${tot} above threshold</span>
      </div>`;}

  // Signals
  document.getElementById('sigs').innerHTML=SIGS.map(sg=>{
    const v=feats[sg.k]??0,pct=Math.min(100,(v/sg.mx)*100),hot=v>=sg.th;
    const fmt=sg.mx<=1?v.toFixed(2):sg.mx===8?v.toFixed(2):v.toFixed(0);
    return`<div class="si"><div class="sr">
      <span class="sn">${sg.n}</span>
      <span class="sv" style="color:${hot?'#f46060':'var(--tx)'}">${fmt}</span>
    </div><div class="str">
      <div class="sf" style="width:${pct}%;background:${hot?'var(--da)':'var(--ac)'}"></div>
    </div></div>`;}).join('');

  // Alert table
  const tb=document.getElementById('tb');
  if(!alerts.length){tb.innerHTML='<tr><td colspan="7" class="empty">Monitoring...</td></tr>';}
  else{
    const pT=tb.querySelector('tr[data-ts]')?.dataset?.ts;
    tb.innerHTML=[...alerts].reverse().slice(0,20).map((a,i)=>{
      const f=a.features??{},t=new Date(a.ts*1000).toLocaleTimeString();
      const isHP=a.type==='HONEYPOT';
      return`<tr class="${i===0&&t!==pT?'fl':''}" data-ts="${t}">
        <td style="color:var(--mu)">${t}</td>
        <td style="color:${sc(a.score)};font-weight:700">${a.score.toFixed(3)}</td>
        <td>${isHP?'<span class="badge HONEYPOT">🍯 CANARY</span>':'<span style="font-size:.6rem;color:var(--mu)">ML</span>'}</td>
        <td><span class="badge ${a.level}">${a.level}</span></td>
        <td>${(f.file_rename_count??0).toFixed?.(0)??0}</td>
        <td style="color:${(f.avg_entropy??0)>=7.2?'#f46060':'inherit'}">${(f.avg_entropy??0).toFixed?.(2)??'—'}</td>
        <td>${(f.write_ops_per_sec??0).toFixed?.(1)??0}</td>
      </tr>`;}).join('');}

  // SHAP
  const exp=d.explanation??{};
  if(score>=.5&&exp.top?.length){
    const sd=document.getElementById('shapDiv');sd.style.display='';
    const mp=Math.max(...exp.top.map(x=>x.pct),1);
    document.getElementById('shapCnt').innerHTML=
      exp.top.map(x=>`<div class="sh-row">
        <span class="sh-nm" title="${x.feature}">${x.feature.replace(/_/g,' ')}</span>
        <div class="sh-bw"><div class="sh-bf" style="width:${Math.min(100,x.pct/mp*100)}%"></div></div>
        <span class="sh-pc">${x.pct.toFixed(0)}%</span>
      </div>`).join('')+
      (exp.summary?`<div class="sh-sum">${exp.summary}</div>`:'');
  }else{document.getElementById('shapDiv').style.display='none';}

  // Honeypot
  const hp=d.honeypot||{};
  if(hp.total){
    document.getElementById('hpI').textContent=hp.intact+' intact';
    document.getElementById('hpT').textContent=hp.total+' total';
    document.getElementById('hpTr').textContent=(hp.triggered||0)+' triggered';
    if(hp.triggered>0){
      document.getElementById('hpb').className='hp warn';
      document.getElementById('hptitle').textContent='🚨 CANARY TRIGGERED! Ransomware Confirmed!';
      const la=hp.alerts?.length?hp.alerts[hp.alerts.length-1]:null;
      if(la)document.getElementById('hpmsg').textContent=la.message;
    }else if(hp.compromised>0){
      document.getElementById('hpb').className='hp warn';
      document.getElementById('hptitle').textContent='⚠️ '+hp.compromised+' Canaries Compromised!';
    }else{
      document.getElementById('hpb').className='hp safe';
      document.getElementById('hptitle').textContent='Honeypot Canaries — All Intact ('+hp.intact+'/'+hp.total+')';
    }}

  fetchRL();
}

async function fetchRL(){
  let d;try{d=await(await fetch('/api/response_log')).json();}catch(e){return;}
  document.getElementById('nsSt').textContent=d.network_isolated?'🔌 Network: ISOLATED':'🌐 Network: CONNECTED';
  document.getElementById('nsSt').className='ns '+(d.network_isolated?'i':'c');
  const log=d.log||[];
  if(!log.length){document.getElementById('rlog').innerHTML='<div class="empty" style="padding:4px">No actions yet</div>';return;}
  document.getElementById('rlog').innerHTML=[...log].reverse().map(r=>
    `<div class="ri ${r.status}"><span class="rt">${r.time_str}</span>
     <div class="rn">${r.name}</div><div class="rm">${r.message}</div></div>`).join('');}

async function act(a){
  try{await fetch('/api/respond',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({actions:[a]})});fetchRL();}catch(e){alert('Failed: '+e);}}
async function actAll(){
  if(!confirm('Execute ALL response actions?'))return;
  for(const a of['evidence','process','network','quarantine','affected_files'])await act(a);
  fetchRL();}

refresh();
setInterval(refresh,1500);
</script>
</body></html>"""

@app.route('/')
def index(): return render_template_string(HTML,threshold=ALERT_THRESHOLD)

@app.route('/api/status')
def api_status():
    if not _detector: return jsonify({'error':'not ready'})
    hist   = list(_detector.score_history)
    latest = hist[-1] if hist else {}
    am_sum = _am.summary() if _am else {}
    feats  = list(latest.get('features',{}).values()) if latest.get('features') else []
    ms     = _score_all(feats)
    ev     = _ensemble(ms)
    score  = ev['e'] if ms else latest.get('score',0)
    expl   = _explain(feats,score)
    hp_st  = _honeypot.status() if _honeypot else {}
    return jsonify({
        'score':       round(score,4),
        'level':       latest.get('level','OK'),
        'features':    latest.get('features',{}),
        'readings':    am_sum.get('total_readings',0),
        'alert_count': am_sum.get('total_alerts',0),
        'alerts':      list(_detector.alert_log)[-30:],
        'model_scores':ms,
        'consensus':   ev['cons'],
        'vote_count':  ev['v'],
        'total_models':ev['t'],
        'explanation': expl,
        'honeypot':    hp_st,
    })

@app.route('/api/response_log')
def api_resp_log():
    if not _responder: return jsonify({'log':[],'network_isolated':False})
    return jsonify({'log':list(_responder.action_log),'network_isolated':_responder.network_isolated})

@app.route('/api/respond',methods=['POST'])
def api_respond():
    if not _responder: return jsonify({'error':'not ready'})
    data=request.get_json(force=True); actions=data.get('actions',['evidence'])
    hist=list(_detector.score_history) if _detector else []
    alert=hist[-1] if hist else {'score':0,'level':'OK','features':{}}
    if 'network_restore' in actions:
        r=_responder.restore_network(); return jsonify({'ok':True,'results':[r.to_dict()]})
    results=_responder.respond(alert,actions=actions)
    return jsonify({'ok':True,'results':[r.to_dict() for r in results]})

def main():
    global _detector,_honeypot,_am,_responder,_running
    parser=argparse.ArgumentParser()
    parser.add_argument('--watch',required=True)
    parser.add_argument('--model',default=None)
    parser.add_argument('--port',type=int,default=5000)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--no-honeypot',action='store_true')
    parser.add_argument('--backup',nargs='*',default=[])
    args=parser.parse_args()

    print("\n[1/4] Loading models...")
    _load_all_models()
    print(f"      {len(_all_models)} models loaded")

    print("[2/4] Starting detector...")
    _am=AlertManager();_am.start()
    _responder=IncidentResponder(args.watch,backup_paths=args.backup)
    _detector=RansomwareDetector(args.watch,args.model,_am.dispatch)
    _detector.load_model();_detector.start()

    print("[3/4] Honeypot...")
    if not args.no_honeypot and _HP:
        try:
            _honeypot=HoneypotSystem([args.watch])
            _honeypot.plant(alert_callback=lambda a:_am.dispatch(a)).start()
            print(f"      {_honeypot.status()['total']} canaries planted")
        except Exception as e: print(f"      WARN: {e}")

    _running=True
    print(f"[4/4] Dashboard: http://{args.host}:{args.port}")
    print(f"      Watch: {args.watch} | Models: {len(_all_models)}\n")
    app.run(host=args.host,port=args.port,debug=False,threaded=True)

if __name__=='__main__':
    main()