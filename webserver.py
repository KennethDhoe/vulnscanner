#!/usr/bin/env python3
"""
webserver.py — VulnScanner web UI
Drive everything from the browser: start scan, watch live logs,
view results, browse scan history, download reports, shut down.
"""

import json
import os
import glob
import shutil
import subprocess
import threading
import time
from datetime import datetime
from flask import Flask, Response, jsonify, send_file, render_template_string

SCAN_BASE   = os.environ.get("SCAN_BASE",   "/var/lib/vulnscanner/scans")
INSTALL_DIR = os.environ.get("INSTALL_DIR", "/opt/syft-grype-report")
PORT        = int(os.environ.get("PORT", 5000))
MAX_SCANS   = 5

app = Flask(__name__)

# ── Shared state ──────────────────────────────────────────────────────────────
state = {
    "log":     [],
    "done":    False,
    "running": False,
    "error":   False,
    "stage":   "idle",
    "scan_id": None,
}
state_lock = threading.Lock()

STAGES = {
    "idle":       ("Idle",                    0),
    "meta":       ("Collecting host info",    5),
    "syft":       ("Building SBOM (Syft)",   20),
    "grype":      ("Scanning vulns (Grype)", 55),
    "containers": ("Scanning containers",    70),
    "report":     ("Generating report",      90),
    "done":       ("Complete",              100),
}

def set_stage(s):
    with state_lock:
        state["stage"] = s
        label, pct = STAGES.get(s, ("Running", 50))
        state["log"].append(f"__STAGE__{s}__{pct}__{label}")

# ── Scan storage helpers ──────────────────────────────────────────────────────
def scan_dir(scan_id):
    return os.path.join(SCAN_BASE, scan_id)

def report_path(scan_id):
    return os.path.join(scan_dir(scan_id), "report.xlsx")

def new_scan_id():
    return datetime.now().strftime("%Y-%m-%d_%H-%M")

def list_scans():
    if not os.path.isdir(SCAN_BASE):
        return []
    scans = []
    for d in sorted(os.listdir(SCAN_BASE), reverse=True):
        full = os.path.join(SCAN_BASE, d)
        if not os.path.isdir(full):
            continue
        meta   = load_host_meta(full)
        vulns  = load_json(os.path.join(full, "host_vulns.json"))
        counts = count_vulns(vulns)
        # also count container vulns
        cdir = os.path.join(full, "containers")
        if os.path.isdir(cdir):
            for vp in glob.glob(os.path.join(cdir, "*_vulns.json")):
                cv = load_json(vp)
                c  = count_vulns(cv)
                for k in counts:
                    counts[k] += c[k]
        scans.append({
            "id":       d,
            "label":    d.replace("_", " ").replace("-", "/", 2),
            "hostname": meta.get("hostname", "—"),
            "os":       meta.get("os", "—"),
            "has_report": os.path.exists(report_path(d)),
            "counts":   counts,
        })
    return scans

def count_vulns(vuln_json):
    empty = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    if not vuln_json or "matches" not in vuln_json:
        return empty
    c = empty.copy()
    for m in vuln_json["matches"]:
        sev = m.get("vulnerability", {}).get("severity", "Unknown")
        c["total"] += 1
        k = sev.lower()
        if k in c:
            c[k] += 1
    return c

def prune_old_scans():
    if not os.path.isdir(SCAN_BASE):
        return
    dirs = sorted(os.listdir(SCAN_BASE))
    while len(dirs) > MAX_SCANS:
        shutil.rmtree(os.path.join(SCAN_BASE, dirs.pop(0)), ignore_errors=True)

# ── Data helpers ──────────────────────────────────────────────────────────────
def load_json(path):
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def load_host_meta(scan_dir_path=None):
    if scan_dir_path is None:
        scan_dir_path = scan_dir(state["scan_id"]) if state["scan_id"] else ""
    meta = {}
    path = os.path.join(scan_dir_path, "host_meta.txt")
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

def get_summary(sid=None):
    if sid is None:
        sid = state["scan_id"]
    sd        = scan_dir(sid)
    meta      = load_host_meta(sd)
    host_vj   = load_json(os.path.join(sd, "host_vulns.json"))
    host_sbom = load_json(os.path.join(sd, "host_sbom.json"))
    host_pkgs = len(host_sbom.get("artifacts", [])) if host_sbom else 0
    host_vulns = parse_vulns(host_vj, "host")

    container_vulns = []
    containers      = []
    cdir = os.path.join(sd, "containers")
    if os.path.isdir(cdir):
        for sbom_path in glob.glob(os.path.join(cdir, "*_sbom.json")):
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
        "scan_id":    sid,
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
def run_scan(sid):
    venv_python = os.path.join(INSTALL_DIR, "venv", "bin", "python3")
    sd          = scan_dir(sid)
    os.makedirs(sd, exist_ok=True)

    stage_triggers = {
        "Collecting host metadata":  "meta",
        "Scanning host filesystem":  "syft",
        "Scanning host SBOM":        "grype",
        "Docker detected":           "containers",
        "Scanning images":           "containers",
        "Generating report":         "report",
    }

    def stream_cmd(cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        for raw in proc.stdout:
            line = raw.rstrip()
            if not line:
                continue
            for trigger, stage in stage_triggers.items():
                if trigger.lower() in line.lower():
                    set_stage(stage)
                    break
            with state_lock:
                state["log"].append(line)
        proc.wait()
        return proc.returncode

    set_stage("meta")
    rc1 = stream_cmd(["bash", os.path.join(INSTALL_DIR, "scan.sh"), sd])
    if rc1 != 0:
        with state_lock:
            state["log"].append(f"[✗] scan.sh failed (exit {rc1})")
            state["error"] = True

    if not state["error"]:
        set_stage("report")
        rc2 = stream_cmd([venv_python,
                          os.path.join(INSTALL_DIR, "generate_report.py"),
                          sd, report_path(sid)])
        if rc2 != 0:
            with state_lock:
                state["log"].append(f"[✗] generate_report.py failed (exit {rc2})")
                state["error"] = True

    prune_old_scans()
    set_stage("done")
    with state_lock:
        state["done"]    = True
        state["running"] = False
        if not state["error"]:
            state["log"].append("[✓] Scan complete. Report ready for download.")
        else:
            state["log"].append("[✗] Scan finished with errors.")

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/start", methods=["POST"])
def start_scan():
    with state_lock:
        if state["running"]:
            return jsonify({"error": "Scan already running"}), 409
        sid = new_scan_id()
        state["log"]     = []
        state["done"]    = False
        state["running"] = True
        state["error"]   = False
        state["stage"]   = "idle"
        state["scan_id"] = sid
    threading.Thread(target=run_scan, args=(sid,), daemon=True).start()
    return jsonify({"ok": True, "scan_id": sid})

@app.route("/status")
def status():
    with state_lock:
        return jsonify({
            "running": state["running"],
            "done":    state["done"],
            "error":   state["error"],
            "stage":   state["stage"],
            "scan_id": state["scan_id"],
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
                    time.sleep(0.5)
                    break
                yield ": ping\n\n"
                time.sleep(0.5)
        except GeneratorExit:
            pass
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})

@app.route("/summary")
def summary():
    sid = state.get("scan_id")
    if not sid:
        return jsonify({"error": "No scan yet"}), 404
    return jsonify(get_summary(sid))

@app.route("/summary/<scan_id>")
def summary_by_id(scan_id):
    if not os.path.isdir(scan_dir(scan_id)):
        return jsonify({"error": "Not found"}), 404
    return jsonify(get_summary(scan_id))

@app.route("/history")
def history():
    return jsonify(list_scans())

@app.route("/download")
def download_latest():
    sid = state.get("scan_id")
    if not sid or not os.path.exists(report_path(sid)):
        return "Report not ready", 404
    return send_file(report_path(sid), as_attachment=True,
                     download_name=f"vulnscan_{sid}.xlsx")

@app.route("/download/<scan_id>")
def download_by_id(scan_id):
    p = report_path(scan_id)
    if not os.path.exists(p):
        return "Report not found", 404
    return send_file(p, as_attachment=True,
                     download_name=f"vulnscan_{scan_id}.xlsx")

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
  .nav{display:flex;gap:6px;align-items:center}
  .nav-btn{
    padding:5px 14px;border-radius:4px;font-size:11px;font-weight:700;
    cursor:pointer;border:1px solid #2a3044;background:transparent;
    color:#888;text-transform:uppercase;letter-spacing:.04em;
  }
  .nav-btn:hover{background:#1a1f2e;color:#aaa}
  .nav-btn.active{background:#1F4E79;color:#fff;border-color:#1F4E79}

  .container{max-width:1300px;margin:0 auto;padding:24px}
  .screen{display:none}
  .screen.active{display:block}

  /* Home */
  .home{
    display:flex;flex-direction:column;align-items:center;
    justify-content:center;min-height:65vh;text-align:center;gap:16px;
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
  .progress-label{text-align:right;font-size:10px;color:#555;margin-top:4px}

  /* Buttons */
  .btn{
    display:inline-flex;align-items:center;gap:6px;
    padding:10px 22px;border-radius:6px;font-size:13px;
    font-weight:700;cursor:pointer;border:none;text-decoration:none;
    transition:background .15s,opacity .15s;
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
  .log-box .l.ok   {color:#4caf50}
  .log-box .l.warn {color:#ff9800}
  .log-box .l.err  {color:#e05555}
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
    letter-spacing:.04em;padding:7px 10px;text-align:left;
    border-bottom:1px solid #2a3044;position:sticky;top:56px;
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

  /* History cards */
  .history-grid{display:flex;flex-direction:column;gap:10px}
  .history-card{
    background:#1a1f2e;border:1px solid #2a3044;border-radius:6px;
    padding:14px 18px;display:flex;align-items:center;gap:16px;
    cursor:pointer;transition:border-color .15s;
  }
  .history-card:hover{border-color:#1F4E79}
  .history-card .hc-id{font-size:13px;font-weight:700;color:#4fa3e0;min-width:140px}
  .history-card .hc-host{font-size:11px;color:#666;flex:1}
  .history-card .hc-counts{display:flex;gap:10px}
  .history-card .hc-pill{
    padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;
  }
  .pill-crit{background:#3a0000;color:#e05555;border:1px solid #e05555}
  .pill-high{background:#3a1500;color:#e07755;border:1px solid #e07755}
  .pill-med {background:#3a2800;color:#e0a855;border:1px solid #e0a855}
  .pill-low {background:#3a3500;color:#e0d455;border:1px solid #e0d455}
  .history-card .hc-actions{display:flex;gap:6px}
  .empty-history{color:#555;font-style:italic;padding:20px 0;text-align:center}

  /* Modal */
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
</style>
</head>
<body>

<header>
  <div>
    <h1>🔍 VulnScanner</h1>
    <div class="sub" id="hdr-host">Ready</div>
  </div>
  <div class="nav">
    <button class="nav-btn active" id="nav-home"    onclick="showScreen('home')">Home</button>
    <button class="nav-btn"        id="nav-scan"    onclick="showScreen('scan')">Scan</button>
    <button class="nav-btn"        id="nav-history" onclick="showScreen('history');loadHistory()">History</button>
    <span class="badge b-idle" id="status-badge" style="margin-left:8px">Idle</span>
    <button class="btn btn-danger btn-sm" onclick="showShutdown()">Shut down</button>
  </div>
</header>

<!-- ── Home ─────────────────────────────────────────────────────────────────── -->
<div id="screen-home" class="screen active container">
  <div class="home">
    <div class="host-card" id="home-hostinfo">Loading...</div>
    <h2>Ready to scan</h2>
    <p>Scans the host filesystem and Docker images using Syft + Grype,
       then generates a filterable vulnerability report.</p>
    <button class="btn btn-primary" id="start-btn"
            onclick="startScan()" style="font-size:15px;padding:14px 36px">
      ▶&nbsp; Start Scan
    </button>
  </div>
</div>

<!-- ── Scan ──────────────────────────────────────────────────────────────────── -->
<div id="screen-scan" class="screen container">

  <div class="progress-wrap section">
    <div class="progress-stages">
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
    <div class="progress-label" id="prog-label">Waiting...</div>
  </div>

  <div class="section">
    <div class="log-wrap">
      <div class="log-header">
        <span>Live output</span>
        <button class="btn btn-ghost btn-sm"
                onclick="toggleAutoscroll()" id="autoscroll-btn">Autoscroll: ON</button>
      </div>
      <div class="log-box" id="log-box"></div>
    </div>
  </div>

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
      <a class="btn btn-success" id="dl-btn" href="/download">⬇ Download Excel Report</a>
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

<!-- ── History ───────────────────────────────────────────────────────────────── -->
<div id="screen-history" class="screen container">
  <div class="section">
    <h2>Scan History <span style="color:#555;font-weight:400;text-transform:none">(last 5)</span></h2>
    <div class="history-grid" id="history-grid">
      <div class="empty-history">Loading...</div>
    </div>
  </div>

  <!-- History detail (shown when a scan is clicked) -->
  <div id="history-detail" style="display:none">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <button class="btn btn-ghost btn-sm" onclick="closeHistoryDetail()">← Back</button>
      <span id="detail-title" style="color:#4fa3e0;font-weight:700"></span>
      <a class="btn btn-success btn-sm" id="detail-dl-btn" href="#">⬇ Download</a>
    </div>
    <div class="stats">
      <div class="stat c-grey"><div class="val" id="hs-pkgs">—</div><div class="lbl">Host Pkgs</div></div>
      <div class="stat c-blue"><div class="val" id="hs-total">—</div><div class="lbl">Total Vulns</div></div>
      <div class="stat c-crit"><div class="val" id="hs-crit">—</div><div class="lbl">Critical</div></div>
      <div class="stat c-high"><div class="val" id="hs-high">—</div><div class="lbl">High</div></div>
      <div class="stat c-med" ><div class="val" id="hs-med">—</div><div class="lbl">Medium</div></div>
      <div class="stat c-low" ><div class="val" id="hs-low">—</div><div class="lbl">Low</div></div>
    </div>
    <div class="tabs">
      <div class="tab active" onclick="switchHistoryTab('vulns')">Vulnerabilities</div>
      <div class="tab" onclick="switchHistoryTab('containers')">Containers</div>
    </div>
    <div class="tab-content active" id="htab-vulns">
      <div class="toolbar">
        <input type="text" id="hfilter-input" placeholder="Filter CVE, package, severity...">
        <select id="hsev-filter" onchange="applyHistoryFilter()">
          <option value="">All severities</option>
          <option>Critical</option><option>High</option>
          <option>Medium</option><option>Low</option>
        </select>
        <span id="hvuln-count" style="color:#555;font-size:11px"></span>
      </div>
      <table>
        <thead><tr>
          <th>CVE / ID</th><th>Severity</th><th>CVSS</th>
          <th>Package</th><th>Version</th><th>Fix</th><th>Source</th><th>Description</th>
        </tr></thead>
        <tbody id="hvuln-body"></tbody>
      </table>
    </div>
    <div class="tab-content" id="htab-containers">
      <table>
        <thead><tr>
          <th>Image</th><th>Packages</th><th>Vulns</th><th>Critical</th><th>High</th>
        </tr></thead>
        <tbody id="hcontainer-body"></tbody>
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
      <button class="btn btn-ghost"  onclick="hideShutdown()">Cancel</button>
    </div>
  </div>
</div>

<script>
let allVulns      = [];
let historyVulns  = [];
let autoscroll    = true;
let evtSource     = null;

const STAGE_ORDER = ['meta','syft','grype','containers','report','done'];

// ── Init ──────────────────────────────────────────────────────────────────────
window.onload = () => {
  document.getElementById('home-hostinfo').innerHTML =
    'Host: <span>' + location.hostname + '</span>';
  fetch('/status').then(r => r.json()).then(d => {
    if (d.running) {
      showScreen('scan');
      setBadge('running');
      setProgress(d.stage||'syft', getStagePercent(d.stage), getStageName(d.stage));
      connectStream();
    } else if (d.done) {
      setBadge('done');
    }
  });
};

// ── Screens ───────────────────────────────────────────────────────────────────
function showScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('screen-' + name).classList.add('active');
  document.getElementById('nav-' + name).classList.add('active');
}

// ── Start scan ────────────────────────────────────────────────────────────────
function startScan() {
  document.getElementById('start-btn').disabled = true;
  showScreen('scan');
  document.getElementById('results-panel').style.display = 'none';
  document.getElementById('log-box').innerHTML = '';
  setProgress('idle', 0, 'Starting...');
  setBadge('running');

  fetch('/start', {method:'POST'})
    .then(r => r.json())
    .then(d => {
      if (d.error) { alert(d.error); showScreen('home'); return; }
      connectStream();
    })
    .catch(e => { alert('Failed to start: ' + e); showScreen('home'); });
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
      setProgress(parts[1], parseInt(parts[2]), parts[3]);
      appendLog('▶ ' + parts[3], 'stage');
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
  d.className = 'l' + (cls ? ' '+cls :
    text.startsWith('[✓]') ? ' ok'   :
    text.startsWith('[!]') ? ' warn' :
    text.startsWith('[✗]') ? ' err'  : '');
  d.textContent = text;
  box.appendChild(d);
  if (autoscroll) box.scrollTop = box.scrollHeight;
}

// ── Progress ──────────────────────────────────────────────────────────────────
function setProgress(stage, pct, label) {
  document.getElementById('prog-fill').style.width  = pct + '%';
  document.getElementById('prog-label').textContent = label + (pct < 100 ? '...' : '');
  STAGE_ORDER.forEach(s => {
    const el  = document.getElementById('ps-' + s);
    if (!el) return;
    const idx = STAGE_ORDER.indexOf(s);
    const cur = STAGE_ORDER.indexOf(stage);
    el.classList.remove('active','complete');
    if (idx < cur)       el.classList.add('complete');
    else if (idx === cur) el.classList.add('active');
  });
}
function getStagePercent(s){
  return {idle:0,meta:5,syft:20,grype:55,containers:70,report:90,done:100}[s]||10;
}
function getStageName(s){
  return {idle:'Idle',meta:'Collecting host info',syft:'Building SBOM',
          grype:'Scanning vulnerabilities',containers:'Scanning containers',
          report:'Generating report',done:'Complete'}[s]||'Running';
}

function toggleAutoscroll() {
  autoscroll = !autoscroll;
  document.getElementById('autoscroll-btn').textContent =
    'Autoscroll: ' + (autoscroll ? 'ON' : 'OFF');
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function setBadge(s) {
  const el  = document.getElementById('status-badge');
  const map = {idle:['b-idle','Idle'],running:['b-running','Scanning'],
               done:['b-done','Done'],error:['b-error','Error']};
  el.className   = 'badge ' + map[s][0];
  el.textContent = map[s][1];
}

// ── Summary (current scan) ────────────────────────────────────────────────────
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
    renderContainers(d.containers, 'container-body');
  });
}

// ── Vuln table (current scan) ─────────────────────────────────────────────────
function applyFilter() {
  const q   = document.getElementById('filter-input').value.toLowerCase();
  const sev = document.getElementById('sev-filter').value;
  renderVulns(allVulns, q, sev, 'vuln-body', 'vuln-count');
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('filter-input').addEventListener('input', applyFilter);
});

function renderVulns(vulns, q, sev, tbodyId, countId) {
  const filtered = vulns.filter(v =>
    (!sev || v.severity === sev) &&
    (!q   || v.cve.toLowerCase().includes(q) ||
             v.package.toLowerCase().includes(q) ||
             v.severity.toLowerCase().includes(q) ||
             v.source.toLowerCase().includes(q))
  );
  const tb = document.getElementById(tbodyId);
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
  if (countId) document.getElementById(countId).textContent =
    filtered.length + ' of ' + vulns.length + ' vulnerabilities';
}

function renderContainers(containers, tbodyId) {
  const cb = document.getElementById(tbodyId);
  cb.innerHTML = containers.length ? '' :
    '<tr><td colspan="5" style="color:#555;font-style:italic;padding:10px">No containers found.</td></tr>';
  containers.forEach(c => {
    cb.innerHTML += `<tr>
      <td><code>${c.image}</code></td>
      <td>${c.packages}</td><td>${c.vulns}</td>
      <td style="color:${c.critical?'#e05555':'#555'}">${c.critical}</td>
      <td style="color:${c.high?'#e07755':'#555'}">${c.high}</td>
    </tr>`;
  });
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(name) {
  ['vulns','containers'].forEach(id => {
    document.querySelector(`[onclick="switchTab('${id}')"]`)
            .classList.toggle('active', id === name);
    document.getElementById('tab-'+id).classList.toggle('active', id === name);
  });
}
function switchHistoryTab(name) {
  ['vulns','containers'].forEach(id => {
    document.querySelector(`[onclick="switchHistoryTab('${id}')"]`)
            .classList.toggle('active', id === name);
    document.getElementById('htab-'+id).classList.toggle('active', id === name);
  });
}

// ── History ───────────────────────────────────────────────────────────────────
function loadHistory() {
  document.getElementById('history-detail').style.display = 'none';
  document.getElementById('history-grid').style.display   = 'block';
  fetch('/history').then(r => r.json()).then(scans => {
    const grid = document.getElementById('history-grid');
    if (!scans.length) {
      grid.innerHTML = '<div class="empty-history">No previous scans found.</div>';
      return;
    }
    grid.innerHTML = scans.map(s => `
      <div class="history-card" onclick="openHistoryScan('${s.id}')">
        <div class="hc-id">${s.label}</div>
        <div class="hc-host">${s.hostname} &nbsp;·&nbsp; ${s.os}</div>
        <div class="hc-counts">
          <span class="hc-pill pill-crit">${s.counts.critical} Crit</span>
          <span class="hc-pill pill-high">${s.counts.high} High</span>
          <span class="hc-pill pill-med">${s.counts.medium} Med</span>
          <span class="hc-pill pill-low">${s.counts.low} Low</span>
        </div>
        <div class="hc-actions">
          ${s.has_report
            ? `<a class="btn btn-success btn-sm" href="/download/${s.id}"
                  onclick="event.stopPropagation()">⬇</a>`
            : '<span style="color:#444;font-size:11px">no report</span>'}
        </div>
      </div>`).join('');
  });
}

function openHistoryScan(sid) {
  document.getElementById('history-grid').style.display   = 'none';
  document.getElementById('history-detail').style.display = 'block';
  document.getElementById('detail-title').textContent     = sid.replace(/_/g,' ').replace(/-/,'/').replace(/-/,'/');
  document.getElementById('detail-dl-btn').href           = `/download/${sid}`;
  document.getElementById('hvuln-body').innerHTML         = '<tr><td colspan="8" style="color:#555">Loading...</td></tr>';

  fetch(`/summary/${sid}`).then(r => r.json()).then(d => {
    document.getElementById('hs-pkgs').textContent  = d.host_pkgs;
    document.getElementById('hs-total').textContent = d.counts.total;
    document.getElementById('hs-crit').textContent  = d.counts.critical;
    document.getElementById('hs-high').textContent  = d.counts.high;
    document.getElementById('hs-med').textContent   = d.counts.medium;
    document.getElementById('hs-low').textContent   = d.counts.low;
    historyVulns = d.vulns;
    applyHistoryFilter();
    renderContainers(d.containers, 'hcontainer-body');
  });
}

function applyHistoryFilter() {
  const q   = document.getElementById('hfilter-input').value.toLowerCase();
  const sev = document.getElementById('hsev-filter').value;
  renderVulns(historyVulns, q, sev, 'hvuln-body', 'hvuln-count');
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('hfilter-input').addEventListener('input', applyHistoryFilter);
});

function closeHistoryDetail() {
  document.getElementById('history-detail').style.display = 'none';
  document.getElementById('history-grid').style.display   = 'block';
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
    os.makedirs(SCAN_BASE, exist_ok=True)
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
