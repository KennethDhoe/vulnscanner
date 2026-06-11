#!/usr/bin/env python3
"""
webserver.py — VulnScanner web UI
Drive everything from the browser: start scan, watch live logs,
view results, download report, shut down.
"""

import json
import os
import glob
import subprocess
import threading
import time
from flask import Flask, Response, jsonify, send_file, render_template_string

SCAN_DIR    = os.environ.get("SCAN_DIR",    "/tmp/scan_output")
REPORT_PATH = os.environ.get("REPORT_PATH", "/tmp/security_report.xlsx")
INSTALL_DIR = os.environ.get("INSTALL_DIR", "/opt/syft-grype-report")
PORT        = int(os.environ.get("PORT", 5000))

app = Flask(__name__)

# ── Shared state ──────────────────────────────────────────────────────────────
state = {
    "log":     [],
    "done":    False,
    "running": False,
    "error":   False,
    "stage":   "idle",   # idle | meta | syft | grype | containers | report | done
}
state_lock = threading.Lock()

STAGES = {
    "idle":       ("Idle",                   0),
    "meta":       ("Collecting host info",   5),
    "syft":       ("Building SBOM (Syft)",  20),
    "grype":      ("Scanning vulns (Grype)", 55),
    "containers": ("Scanning containers",   70),
    "report":     ("Generating report",     90),
    "done":       ("Complete",             100),
}

def set_stage(s):
    with state_lock:
        state["stage"] = s
        label, pct = STAGES.get(s, ("Running", 50))
        state["log"].append(f"__STAGE__{s}__{pct}__{label}")

# ── Data helpers ──────────────────────────────────────────────────────────────
def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def load_host_meta():
    meta = {}
    path = os.path.join(SCAN_DIR, "host_meta.txt")
    if not os.path.exists(path):
        return meta
    with open(path) as f:
        for line in f:
            k, _, v = line.strip().partition("=")
            meta[k] = v
    return meta

def parse_vulns(vuln_json, source="host"):
    if not vuln_json or "matches" not in vuln_json:
        return []
    vulns = []
    for m in vuln_json["matches"]:
        v   = m.get("vulnerability", {})
        art = m.get("artifact", {})
        fix = v.get("fix", {})
        vulns.append({
            "source":   source,
            "cve":      v.get("id", ""),
            "severity": v.get("severity", "Unknown"),
            "cvss":     next((s.get("metrics", {}).get("baseScore", "")
                              for s in v.get("cvss", [])
                              if s.get("metrics", {}).get("baseScore")), ""),
            "package":  art.get("name", ""),
            "version":  art.get("version", ""),
            "fix":      ", ".join(fix.get("versions", [])) if fix else "",
            "desc":     v.get("description", "")[:150],
        })
    return vulns

def get_summary():
    meta       = load_host_meta()
    host_vj    = load_json(os.path.join(SCAN_DIR, "host_vulns.json"))
    host_sbom  = load_json(os.path.join(SCAN_DIR, "host_sbom.json"))
    host_pkgs  = len(host_sbom.get("artifacts", [])) if host_sbom else 0
    host_vulns = parse_vulns(host_vj, "host")

    container_vulns = []
    containers      = []
    containers_dir  = os.path.join(SCAN_DIR, "containers")
    if os.path.isdir(containers_dir):
        for sbom_path in glob.glob(os.path.join(containers_dir, "*_sbom.json")):
            base      = sbom_path.replace("_sbom.json", "")
            img_name  = os.path.basename(base).replace("___", "/", 1).replace("___", ":")
            vj        = load_json(base + "_vulns.json")
            vulns     = parse_vulns(vj, img_name)
            sbom      = load_json(sbom_path)
            pkg_count = len(sbom.get("artifacts", [])) if sbom else 0
            container_vulns += vulns
            containers.append({
                "image":    img_name,
                "packages": pkg_count,
                "vulns":    len(vulns),
                "critical": sum(1 for v in vulns if v["severity"] == "Critical"),
                "high":     sum(1 for v in vulns if v["severity"] == "High"),
            })

    all_vulns = host_vulns + container_vulns
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}

    return {
        "meta":       meta,
        "host_pkgs":  host_pkgs,
        "containers": containers,
        "vulns":      sorted(all_vulns, key=lambda v: (sev_order.get(v["severity"], 99), v["package"])),
        "counts": {
            "total":    len(all_vulns),
            "critical": sum(1 for v in all_vulns if v["severity"] == "Critical"),
            "high":     sum(1 for v in all_vulns if v["severity"] == "High"),
            "medium":   sum(1 for v in all_vulns if v["severity"] == "Medium"),
            "low":      sum(1 for v in all_vulns if v["severity"] == "Low"),
        }
    }

# ── Scan runner ───────────────────────────────────────────────────────────────
def run_scan():
    venv_python = os.path.join(INSTALL_DIR, "venv", "bin", "python3")
    os.makedirs(SCAN_DIR, exist_ok=True)

    # Stage keywords to detect from output
    stage_triggers = {
        "Collecting host metadata":  "meta",
        "Scanning host filesystem":  "syft",
        "Scanning host SBOM":        "grype",
        "Docker detected":           "containers",
        "Scanning images":           "containers",
        "Generating report":         "report",
    }

    def stream_cmd(cmd):
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for raw in proc.stdout:
            line = raw.rstrip()
            if not line:
                continue
            # Detect stage from output
            for trigger, stage in stage_triggers.items():
                if trigger.lower() in line.lower():
                    set_stage(stage)
                    break
            with state_lock:
                state["log"].append(line)
        proc.wait()
        return proc.returncode

    set_stage("meta")

    rc1 = stream_cmd(["bash", os.path.join(INSTALL_DIR, "scan.sh"), SCAN_DIR])
    if rc1 != 0:
        with state_lock:
            state["log"].append(f"[✗] scan.sh failed (exit {rc1})")
            state["error"] = True

    if not state["error"]:
        set_stage("report")
        rc2 = stream_cmd([venv_python,
                          os.path.join(INSTALL_DIR, "generate_report.py"),
                          SCAN_DIR, REPORT_PATH])
        if rc2 != 0:
            with state_lock:
                state["log"].append(f"[✗] generate_report.py failed (exit {rc2})")
                state["error"] = True

    set_stage("done")
    with state_lock:
        state["done"]    = True
        state["running"] = False
        if not state["error"]:
            state["log"].append("[✓] All done. Report is ready for download.")
        else:
            state["log"].append("[✗] Scan finished with errors. Check log above.")

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/start", methods=["POST"])
def start_scan():
    with state_lock:
        if state["running"]:
            return jsonify({"error": "Scan already running"}), 409
        state["log"]     = []
        state["done"]    = False
        state["running"] = True
        state["error"]   = False
        state["stage"]   = "idle"
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/status")
def status():
    with state_lock:
        return jsonify({
            "running": state["running"],
            "done":    state["done"],
            "error":   state["error"],
            "stage":   state["stage"],
        })

@app.route("/stream")
def stream():
    def generate():
        sent = 0
        try:
            yield ": connected\n\n"
            while True:
                with state_lock:
                    lines = state["log"][sent:]
                    sent += len(lines)
                    done  = state["done"]
                for line in lines:
                    yield f"data: {line.replace(chr(10), ' ')}\n\n"
                if done and not lines:
                    yield "event: done\ndata: \n\n"
                    break
                yield ": ping\n\n"
                time.sleep(0.5)
        except GeneratorExit:
            pass  # client disconnected cleanly
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})

@app.route("/summary")
def summary():
    return jsonify(get_summary())

@app.route("/download")
def download():
    if not os.path.exists(REPORT_PATH):
        return "Report not ready", 404
    return send_file(REPORT_PATH, as_attachment=True,
                     download_name=os.path.basename(REPORT_PATH))

@app.route("/shutdown", methods=["POST"])
def shutdown_server():
    def _stop():
        time.sleep(1)
        os._exit(0)
    threading.Thread(target=_stop, daemon=True).start()
    return "ok"

# ── UI ────────────────────────────────────────────────────────────────────────
PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnScanner</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:Arial,sans-serif;background:#0f1117;color:#e0e0e0;font-size:13px}

  header{
    background:#1a1f2e;border-bottom:2px solid #1F4E79;
    padding:14px 24px;display:flex;align-items:center;justify-content:space-between;
    position:sticky;top:0;z-index:10;
  }
  header h1{font-size:17px;color:#4fa3e0;font-weight:700;letter-spacing:.03em}
  header .sub{font-size:11px;color:#666;margin-top:2px}

  .container{max-width:1300px;margin:0 auto;padding:24px}

  /* Home */
  .home{
    display:flex;flex-direction:column;align-items:center;
    justify-content:center;min-height:72vh;text-align:center;gap:16px;
  }
  .home h2{font-size:22px;color:#4fa3e0}
  .home p{color:#666;max-width:480px;line-height:1.7;font-size:12px}
  .host-card{
    background:#1a1f2e;border:1px solid #2a3044;border-radius:8px;
    padding:12px 24px;font-size:12px;color:#aaa;
  }
  .host-card span{color:#4fa3e0;font-weight:700}

  /* Progress */
  .progress-wrap{margin-bottom:20px}
  .progress-stages{
    display:flex;justify-content:space-between;
    margin-bottom:8px;font-size:10px;color:#444;
    text-transform:uppercase;letter-spacing:.04em;
  }
  .progress-stages .ps{
    flex:1;text-align:center;padding:4px 2px;
    border-radius:3px;transition:color .3s,background .3s;
  }
  .progress-stages .ps.active{color:#4fa3e0;background:#1a2a3a}
  .progress-stages .ps.complete{color:#4caf50}
  .progress-bar-bg{
    background:#1a1f2e;border-radius:20px;height:8px;
    border:1px solid #2a3044;overflow:hidden;
  }
  .progress-bar-fill{
    height:100%;border-radius:20px;
    background:linear-gradient(90deg,#1F4E79,#4fa3e0);
    transition:width .6s ease;width:0%;
  }
  .progress-label{
    text-align:right;font-size:10px;color:#555;margin-top:4px;
  }

  /* Buttons */
  .btn{
    display:inline-flex;align-items:center;gap:6px;
    padding:10px 22px;border-radius:6px;font-size:13px;
    font-weight:700;cursor:pointer;border:none;text-decoration:none;
    transition:background .15s, opacity .15s;
  }
  .btn:disabled{opacity:.4;cursor:not-allowed}
  .btn-primary{background:#1F4E79;color:#fff}
  .btn-primary:hover:not(:disabled){background:#2a6099}
  .btn-success{background:#1a3a1a;color:#4caf50;border:1px solid #4caf50}
  .btn-success:hover{background:#1f4a1f}
  .btn-danger{background:#2a1010;color:#e05555;border:1px solid #e05555}
  .btn-danger:hover{background:#3a1515}
  .btn-ghost{background:transparent;color:#666;border:1px solid #2a3044}
  .btn-ghost:hover{background:#1a1f2e;color:#aaa}
  .btn-sm{padding:5px 12px;font-size:11px}

  /* Stats */
  .stats{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
  .stat{
    flex:1;min-width:90px;background:#1a1f2e;
    border:1px solid #2a3044;border-radius:6px;padding:12px 14px;text-align:center;
  }
  .stat .val{font-size:24px;font-weight:700}
  .stat .lbl{font-size:10px;color:#666;text-transform:uppercase;margin-top:2px}
  .stat.c-crit .val{color:#e05555}
  .stat.c-high .val{color:#e07755}
  .stat.c-med  .val{color:#e0a855}
  .stat.c-low  .val{color:#e0d455}
  .stat.c-blue .val{color:#4fa3e0}
  .stat.c-grey .val{color:#aaa}

  /* Log */
  .log-wrap{background:#0d1117;border:1px solid #2a3044;border-radius:6px;margin-bottom:20px}
  .log-header{
    padding:8px 14px;border-bottom:1px solid #2a3044;
    display:flex;align-items:center;justify-content:space-between;
  }
  .log-header span{font-size:11px;color:#555;text-transform:uppercase;letter-spacing:.04em}
  .log-box{
    padding:12px 14px;font-family:monospace;font-size:11.5px;
    height:280px;overflow-y:auto;line-height:1.7;
  }
  .log-box .l{color:#888}
  .log-box .l.ok  {color:#4caf50}
  .log-box .l.warn{color:#ff9800}
  .log-box .l.err {color:#e05555}
  .log-box .l.stage{color:#4fa3e0;font-weight:700;margin:4px 0}

  /* Badge */
  .badge{
    display:inline-block;padding:2px 9px;border-radius:20px;
    font-size:10px;font-weight:700;text-transform:uppercase;
  }
  .b-idle   {background:#1e1e1e;color:#555}
  .b-running{background:#1a3a5c;color:#4fa3e0}
  .b-done   {background:#1a3a1a;color:#4caf50}
  .b-error  {background:#3a1010;color:#e05555}

  h2{font-size:12px;color:#4fa3e0;text-transform:uppercase;letter-spacing:.05em;
     margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #2a3044}
  .section{margin-bottom:28px}

  table{width:100%;border-collapse:collapse;font-size:12px}
  th{
    background:#1a1f2e;color:#666;font-size:10px;text-transform:uppercase;
    letter-spacing:.04em;padding:7px 10px;text-align:left;border-bottom:1px solid #2a3044;
    position:sticky;top:56px;
  }
  td{padding:6px 10px;border-bottom:1px solid #161b27;vertical-align:top}
  tr:hover td{background:#1a1f2e}
  .desc-cell{color:#666;font-size:11px;max-width:280px}

  .sev{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700}
  .sev-Critical  {background:#3a0000;color:#e05555;border:1px solid #e05555}
  .sev-High      {background:#3a1500;color:#e07755;border:1px solid #e07755}
  .sev-Medium    {background:#3a2800;color:#e0a855;border:1px solid #e0a855}
  .sev-Low       {background:#3a3500;color:#e0d455;border:1px solid #e0d455}
  .sev-Negligible{background:#1e1e1e;color:#555;border:1px solid #333}
  .sev-Unknown   {background:#1e1e1e;color:#444;border:1px solid #2a2a2a}

  .toolbar{display:flex;gap:10px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
  input[type=text]{
    background:#1a1f2e;border:1px solid #2a3044;color:#e0e0e0;
    padding:6px 12px;border-radius:4px;font-size:12px;width:240px;
  }
  input[type=text]::placeholder{color:#444}
  select{
    background:#1a1f2e;border:1px solid #2a3044;color:#aaa;
    padding:6px 10px;border-radius:4px;font-size:12px;
  }

  .tabs{display:flex;gap:2px;margin-bottom:20px;border-bottom:1px solid #2a3044}
  .tab{
    padding:8px 16px;font-size:12px;font-weight:700;cursor:pointer;
    color:#666;border-bottom:2px solid transparent;margin-bottom:-1px;
    text-transform:uppercase;letter-spacing:.04em;
  }
  .tab:hover{color:#aaa}
  .tab.active{color:#4fa3e0;border-bottom-color:#4fa3e0}
  .tab-content{display:none}
  .tab-content.active{display:block}

  .overlay{
    display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);
    z-index:100;align-items:center;justify-content:center;
  }
  .overlay.show{display:flex}
  .modal{
    background:#1a1f2e;border:1px solid #2a3044;border-radius:8px;
    padding:28px 32px;max-width:380px;text-align:center;
  }
  .modal h3{color:#e05555;margin-bottom:8px;font-size:15px}
  .modal p{color:#888;font-size:12px;margin-bottom:20px;line-height:1.6}
  .modal-btns{display:flex;gap:10px;justify-content:center}

  #screen-scan{display:none}
</style>
</head>
<body>

<header>
  <div>
    <h1>🔍 VulnScanner</h1>
    <div class="sub" id="hdr-host">Ready</div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="badge b-idle" id="status-badge">Idle</span>
    <button class="btn btn-danger btn-sm" onclick="showShutdown()">Shut down</button>
  </div>
</header>

<!-- ── Home ─────────────────────────────────────────────────────────────── -->
<div id="screen-home" class="container">
  <div class="home">
    <div class="host-card" id="home-hostinfo">Loading...</div>
    <h2>Ready to scan</h2>
    <p>Scans the host filesystem and Docker images using Syft + Grype,
       then generates a filterable vulnerability report.</p>
    <button class="btn btn-primary" id="start-btn"
            onclick="startScan()" style="font-size:15px;padding:14px 36px">
      ▶&nbsp; Start Scan
    </button>
    <button class="btn btn-ghost btn-sm" id="results-btn"
            onclick="showResults()" style="display:none">
      View last results →
    </button>
  </div>
</div>

<!-- ── Scan screen ───────────────────────────────────────────────────────── -->
<div id="screen-scan" class="container">

  <!-- Progress -->
  <div class="progress-wrap section">
    <div class="progress-stages" id="stage-row">
      <div class="ps" id="ps-meta">Host Info</div>
      <div class="ps" id="ps-syft">SBOM</div>
      <div class="ps" id="ps-grype">Vulns</div>
      <div class="ps" id="ps-containers">Containers</div>
      <div class="ps" id="ps-report">Report</div>
      <div class="ps" id="ps-done">Done</div>
    </div>
    <div class="progress-bar-bg">
      <div class="progress-bar-fill" id="prog-fill"></div>
    </div>
    <div class="progress-label" id="prog-label">Starting...</div>
  </div>

  <!-- Log -->
  <div class="section">
    <div class="log-wrap">
      <div class="log-header">
        <span>Live output</span>
        <button class="btn btn-ghost btn-sm"
                onclick="toggleAutoscroll()" id="autoscroll-btn">Autoscroll: ON</button>
      </div>
      <div class="log-box" id="log-box">
        <span style="color:#333">Waiting for output...</span>
      </div>
    </div>
  </div>

  <!-- Results (shown after done) -->
  <div id="results-panel" style="display:none">
    <div class="stats">
      <div class="stat c-grey"><div class="val" id="s-pkgs">—</div><div class="lbl">Host Pkgs</div></div>
      <div class="stat c-blue"><div class="val" id="s-total">—</div><div class="lbl">Total Vulns</div></div>
      <div class="stat c-crit"><div class="val" id="s-crit">—</div><div class="lbl">Critical</div></div>
      <div class="stat c-high"><div class="val" id="s-high">—</div><div class="lbl">High</div></div>
      <div class="stat c-med" ><div class="val" id="s-med">—</div><div class="lbl">Medium</div></div>
      <div class="stat c-low" ><div class="val" id="s-low">—</div><div class="lbl">Low</div></div>
    </div>

    <div class="toolbar">
      <a class="btn btn-success" href="/download">⬇ Download Excel Report</a>
      <button class="btn btn-ghost btn-sm" onclick="showHome()">← New scan</button>
    </div>

    <div class="tabs">
      <div class="tab active" onclick="switchTab('vulns')">Vulnerabilities</div>
      <div class="tab" onclick="switchTab('containers')">Containers</div>
    </div>

    <div class="tab-content active" id="tab-vulns">
      <div class="toolbar">
        <input type="text" id="filter-input" placeholder="Filter CVE, package, severity...">
        <select id="sev-filter" onchange="applyFilter()">
          <option value="">All severities</option>
          <option>Critical</option><option>High</option>
          <option>Medium</option><option>Low</option>
        </select>
        <span id="vuln-count" style="color:#555;font-size:11px"></span>
      </div>
      <table>
        <thead><tr>
          <th>CVE / ID</th><th>Severity</th><th>CVSS</th>
          <th>Package</th><th>Version</th><th>Fix</th><th>Source</th><th>Description</th>
        </tr></thead>
        <tbody id="vuln-body"></tbody>
      </table>
    </div>

    <div class="tab-content" id="tab-containers">
      <table>
        <thead><tr>
          <th>Image</th><th>Packages</th><th>Vulns</th><th>Critical</th><th>High</th>
        </tr></thead>
        <tbody id="container-body"></tbody>
      </table>
    </div>
  </div>

</div>

<!-- Shutdown modal -->
<div class="overlay" id="shutdown-overlay">
  <div class="modal">
    <h3>Shut down the server?</h3>
    <p>This stops the web UI. Re-run <code>scan-and-report</code> to start it again.</p>
    <div class="modal-btns">
      <button class="btn btn-danger" onclick="doShutdown()">Yes, shut down</button>
      <button class="btn btn-ghost" onclick="hideShutdown()">Cancel</button>
    </div>
  </div>
</div>

<script>
let allVulns   = [];
let autoscroll = true;
let evtSource  = null;

const STAGE_ORDER = ['meta','syft','grype','containers','report','done'];

// ── Init ─────────────────────────────────────────────────────────────────────
window.onload = () => {
  document.getElementById('home-hostinfo').innerHTML =
    'Host: <span>' + location.hostname + '</span>';
  fetch('/status').then(r => r.json()).then(d => {
    if (d.running) {
      // Scan already in progress — jump straight to scan screen and resume polling
      document.getElementById('screen-home').style.display = 'none';
      document.getElementById('screen-scan').style.display = 'block';
      document.getElementById('results-panel').style.display = 'none';
      document.getElementById('log-box').innerHTML = '';
      setBadge('running');
      setProgress(d.stage || 'syft', getStagePercent(d.stage), getStageName(d.stage));
      connectStream();
    } else if (d.done) {
      // Previous scan finished — show results button
      document.getElementById('results-btn').style.display = 'block';
      setBadge('done');
    }
  });
};

function getStagePercent(stage) {
  const map = {idle:0,meta:5,syft:20,grype:55,containers:70,report:90,done:100};
  return map[stage] || 10;
}
function getStageName(stage) {
  const map = {idle:'Idle',meta:'Collecting host info',syft:'Building SBOM',
               grype:'Scanning vulnerabilities',containers:'Scanning containers',
               report:'Generating report',done:'Complete'};
  return map[stage] || 'Running';
}

// ── Screen switching ─────────────────────────────────────────────────────────
function showHome() {
  document.getElementById('screen-home').style.display = 'block';
  document.getElementById('screen-scan').style.display = 'none';
}
function showResults() {
  document.getElementById('screen-home').style.display = 'none';
  document.getElementById('screen-scan').style.display = 'block';
  document.getElementById('results-panel').style.display = 'block';
  loadSummary();
}

// ── Start scan ───────────────────────────────────────────────────────────────
function startScan() {
  document.getElementById('start-btn').disabled = true;
  document.getElementById('screen-home').style.display = 'none';
  document.getElementById('screen-scan').style.display = 'block';
  document.getElementById('results-panel').style.display = 'none';
  document.getElementById('log-box').innerHTML = '';
  lastLineIdx = 0;
  setProgress('idle', 0, 'Starting scan...');
  setBadge('running');

  fetch('/start', {method:'POST'})
    .then(r => r.json())
    .then(d => {
      if (d.error) { alert(d.error); showHome(); return; }
      connectStream();
    })
    .catch(e => { alert('Failed to start: ' + e); showHome(); });
}

// ── SSE ───────────────────────────────────────────────────────────────────────
function connectStream() {
  if (evtSource) evtSource.close();
  evtSource = new EventSource('/stream');

  evtSource.onmessage = (e) => {
    const line = e.data;
    if (!line) return;

    if (line.startsWith('__STAGE__')) {
      const parts = line.split('__').filter(Boolean);
      const stage = parts[1];
      const pct   = parseInt(parts[2]);
      const label = parts[3];
      setProgress(stage, pct, label);
      appendLog('▶ ' + label, 'stage');
      return;
    }

    appendLog(line);
  };

  evtSource.addEventListener('done', () => {
    evtSource.close();
    fetch('/status').then(r => r.json()).then(d => {
      if (d.error) {
        setBadge('error');
        setProgress('done', 100, 'Finished with errors');
      } else {
        setBadge('done');
        setProgress('done', 100, 'Complete');
        document.getElementById('results-panel').style.display = 'block';
        loadSummary();
      }
      document.getElementById('start-btn').disabled = false;
    });
  });

  evtSource.onerror = () => {
    setTimeout(() => {
      fetch('/status').then(r => r.json()).then(d => {
        if (d.running) connectStream();
      }).catch(() => {});
    }, 2000);
  };
}

function appendLog(text, cls) {
  const box = document.getElementById('log-box');
  const d   = document.createElement('div');
  d.className = 'l' + (cls ? ' ' + cls :
    text.startsWith('[✓]') ? ' ok'   :
    text.startsWith('[!]') ? ' warn' :
    text.startsWith('[✗]') ? ' err'  : '');
  d.textContent = text;
  box.appendChild(d);
  if (autoscroll) box.scrollTop = box.scrollHeight;
}

// ── Progress ─────────────────────────────────────────────────────────────────
function setProgress(stage, pct, label) {
  document.getElementById('prog-fill').style.width  = pct + '%';
  document.getElementById('prog-label').textContent = label + (pct < 100 ? '...' : '');

  STAGE_ORDER.forEach(s => {
    const el = document.getElementById('ps-' + s);
    if (!el) return;
    const idx     = STAGE_ORDER.indexOf(s);
    const current = STAGE_ORDER.indexOf(stage);
    el.classList.remove('active','complete');
    if (idx < current)       el.classList.add('complete');
    else if (idx === current) el.classList.add('active');
  });
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function setBadge(state) {
  const el  = document.getElementById('status-badge');
  const map = {
    idle:    ['b-idle',    'Idle'],
    running: ['b-running', 'Scanning'],
    done:    ['b-done',    'Done'],
    error:   ['b-error',   'Error'],
  };
  el.className = 'badge ' + map[state][0];
  el.textContent = map[state][1];
}

// ── Autoscroll ────────────────────────────────────────────────────────────────
function toggleAutoscroll() {
  autoscroll = !autoscroll;
  document.getElementById('autoscroll-btn').textContent =
    'Autoscroll: ' + (autoscroll ? 'ON' : 'OFF');
}

// ── Summary ───────────────────────────────────────────────────────────────────
function loadSummary() {
  fetch('/summary').then(r => r.json()).then(d => {
    document.getElementById('hdr-host').textContent =
      (d.meta.hostname||'') + '  ·  ' + (d.meta.os||'');
    document.getElementById('s-pkgs').textContent  = d.host_pkgs;
    document.getElementById('s-total').textContent = d.counts.total;
    document.getElementById('s-crit').textContent  = d.counts.critical;
    document.getElementById('s-high').textContent  = d.counts.high;
    document.getElementById('s-med').textContent   = d.counts.medium;
    document.getElementById('s-low').textContent   = d.counts.low;

    allVulns = d.vulns;
    applyFilter();

    const cb = document.getElementById('container-body');
    cb.innerHTML = d.containers.length ? '' :
      '<tr><td colspan="5" style="color:#555;font-style:italic;padding:10px">No containers found.</td></tr>';
    d.containers.forEach(c => {
      cb.innerHTML += `<tr>
        <td><code>${c.image}</code></td>
        <td>${c.packages}</td><td>${c.vulns}</td>
        <td style="color:${c.critical?'#e05555':'#555'}">${c.critical}</td>
        <td style="color:${c.high?'#e07755':'#555'}">${c.high}</td>
      </tr>`;
    });
  });
}

// ── Filter ────────────────────────────────────────────────────────────────────
function applyFilter() {
  const q   = document.getElementById('filter-input').value.toLowerCase();
  const sev = document.getElementById('sev-filter').value;
  const filtered = allVulns.filter(v =>
    (!sev || v.severity === sev) &&
    (!q   || v.cve.toLowerCase().includes(q) ||
             v.package.toLowerCase().includes(q) ||
             v.severity.toLowerCase().includes(q) ||
             v.source.toLowerCase().includes(q))
  );
  const tb = document.getElementById('vuln-body');
  tb.innerHTML = '';
  filtered.forEach(v => {
    tb.innerHTML += `<tr>
      <td><strong>${v.cve}</strong></td>
      <td><span class="sev sev-${v.severity}">${v.severity}</span></td>
      <td>${v.cvss||'—'}</td>
      <td>${v.package}</td><td>${v.version}</td>
      <td>${v.fix||'<span style="color:#444">—</span>'}</td>
      <td style="color:#555;font-size:11px">${v.source}</td>
      <td class="desc-cell">${v.desc}</td>
    </tr>`;
  });
  document.getElementById('vuln-count').textContent =
    filtered.length + ' of ' + allVulns.length + ' vulnerabilities';
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('filter-input').addEventListener('input', applyFilter);
});

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(name) {
  ['vulns','containers'].forEach(id => {
    document.querySelector(`[onclick="switchTab('${id}')"]`)
            .classList.toggle('active', id === name);
    document.getElementById('tab-'+id).classList.toggle('active', id === name);
  });
}

// ── Shutdown ──────────────────────────────────────────────────────────────────
function showShutdown()  { document.getElementById('shutdown-overlay').classList.add('show') }
function hideShutdown()  { document.getElementById('shutdown-overlay').classList.remove('show') }
function doShutdown() {
  fetch('/shutdown', {method:'POST'}).finally(() => {
    document.body.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:center;' +
      'height:100vh;font-family:Arial;color:#4caf50;font-size:16px;background:#0f1117">' +
      'Server stopped. You can close this tab.</div>';
  });
}
</script>
</body>
</html>"""

if __name__ == "__main__":
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "localhost"

    print(f"\n{'='*48}")
    print(f"  VulnScanner ready")
    print(f"  Open: http://{ip}:{PORT}")
    print(f"{'='*48}\n")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
