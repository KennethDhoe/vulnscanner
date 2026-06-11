#!/usr/bin/env python3
"""
webserver.py — Scan status web UI
- Live log streaming
- Vuln summary view
- Excel report download
- Shutdown button with confirmation
"""

import json
import os
import glob
import subprocess
import threading
import time
from pathlib import Path
from flask import Flask, Response, jsonify, send_file, render_template_string

SCAN_DIR    = os.environ.get("SCAN_DIR",    "/tmp/scan_output")
REPORT_PATH = os.environ.get("REPORT_PATH", "/tmp/security_report.xlsx")
INSTALL_DIR = os.environ.get("INSTALL_DIR", "/opt/syft-grype-report")
PORT        = int(os.environ.get("PORT", 5000))

app = Flask(__name__)

# ── Shared state ──────────────────────────────────────────────────────────────
scan_log     = []
scan_done    = False
scan_started = False
scan_lock    = threading.Lock()

# ── Data helpers (same logic as generate_report.py) ──────────────────────────
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
    meta = load_host_meta()
    host_vj   = load_json(os.path.join(SCAN_DIR, "host_vulns.json"))
    host_sbom = load_json(os.path.join(SCAN_DIR, "host_sbom.json"))
    host_pkgs  = len(host_sbom.get("artifacts", [])) if host_sbom else 0
    host_vulns = parse_vulns(host_vj, "host")

    container_vulns = []
    containers_dir  = os.path.join(SCAN_DIR, "containers")
    containers      = []
    if os.path.isdir(containers_dir):
        for sbom_path in glob.glob(os.path.join(containers_dir, "*_sbom.json")):
            base     = sbom_path.replace("_sbom.json", "")
            img_name = os.path.basename(base).replace("___", "/", 1).replace("___", ":")
            vj       = load_json(base + "_vulns.json")
            vulns    = parse_vulns(vj, img_name)
            sbom     = load_json(sbom_path)
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
        "meta":        meta,
        "host_pkgs":   host_pkgs,
        "containers":  containers,
        "vulns":       sorted(all_vulns, key=lambda v: (sev_order.get(v["severity"], 99), v["package"])),
        "counts": {
            "total":    len(all_vulns),
            "critical": sum(1 for v in all_vulns if v["severity"] == "Critical"),
            "high":     sum(1 for v in all_vulns if v["severity"] == "High"),
            "medium":   sum(1 for v in all_vulns if v["severity"] == "Medium"),
            "low":      sum(1 for v in all_vulns if v["severity"] == "Low"),
        }
    }

# ── HTML template ─────────────────────────────────────────────────────────────
PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnScanner</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; background: #0f1117; color: #e0e0e0; font-size: 13px; }

  header {
    background: #1a1f2e;
    border-bottom: 2px solid #1F4E79;
    padding: 14px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  header h1 { font-size: 17px; color: #4fa3e0; font-weight: 700; letter-spacing: 0.03em; }
  header .host { font-size: 11px; color: #888; margin-top: 2px; }

  .container { max-width: 1300px; margin: 0 auto; padding: 20px 24px; }

  /* Stat row */
  .stats { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
  .stat {
    flex: 1; min-width: 100px;
    background: #1a1f2e;
    border: 1px solid #2a3044;
    border-radius: 6px;
    padding: 14px 16px;
    text-align: center;
  }
  .stat .val { font-size: 26px; font-weight: 700; }
  .stat .lbl { font-size: 10px; color: #888; text-transform: uppercase; margin-top: 3px; }
  .stat.critical .val { color: #e05555; }
  .stat.high     .val { color: #e07755; }
  .stat.medium   .val { color: #e0a855; }
  .stat.low      .val { color: #e0d455; }
  .stat.total    .val { color: #4fa3e0; }
  .stat.pkgs     .val { color: #aaa; }

  /* Log box */
  .log-box {
    background: #0d1117;
    border: 1px solid #2a3044;
    border-radius: 6px;
    padding: 14px;
    font-family: monospace;
    font-size: 12px;
    height: 280px;
    overflow-y: auto;
    margin-bottom: 20px;
    line-height: 1.6;
  }
  .log-box .line { color: #aaa; }
  .log-box .line.ok   { color: #4caf50; }
  .log-box .line.warn { color: #ff9800; }
  .log-box .line.err  { color: #e05555; }

  /* Status badge */
  .status-bar {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 12px;
  }
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge.running  { background: #1a3a5c; color: #4fa3e0; }
  .badge.done     { background: #1a3a1a; color: #4caf50; }
  .badge.waiting  { background: #2a2a1a; color: #e0d455; }

  /* Section titles */
  h2 {
    font-size: 13px;
    color: #4fa3e0;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid #2a3044;
  }

  /* Tables */
  .section { margin-bottom: 28px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th {
    background: #1a1f2e;
    color: #888;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 7px 10px;
    text-align: left;
    border-bottom: 1px solid #2a3044;
  }
  td {
    padding: 6px 10px;
    border-bottom: 1px solid #1a1f2e;
    vertical-align: top;
  }
  tr:hover td { background: #1a1f2e; }

  .sev {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 700;
  }
  .sev-Critical  { background: #3a0000; color: #e05555; border: 1px solid #e05555; }
  .sev-High      { background: #3a1500; color: #e07755; border: 1px solid #e07755; }
  .sev-Medium    { background: #3a2800; color: #e0a855; border: 1px solid #e0a855; }
  .sev-Low       { background: #3a3500; color: #e0d455; border: 1px solid #e0d455; }
  .sev-Negligible{ background: #1e1e1e; color: #888;    border: 1px solid #444; }
  .sev-Unknown   { background: #1e1e1e; color: #666;    border: 1px solid #333; }

  /* Buttons */
  .btn {
    display: inline-block;
    padding: 8px 18px;
    border-radius: 5px;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    border: none;
    text-decoration: none;
  }
  .btn-primary  { background: #1F4E79; color: white; }
  .btn-primary:hover { background: #2a6099; }
  .btn-danger   { background: #4a1010; color: #e05555; border: 1px solid #e05555; }
  .btn-danger:hover { background: #6a1515; }
  .btn-disabled { background: #1e1e1e; color: #444; cursor: not-allowed; }

  .actions { display: flex; gap: 10px; align-items: center; margin-bottom: 24px; }

  .desc-cell { color: #888; font-size: 11px; max-width: 300px; }

  /* Shutdown modal */
  .modal-overlay {
    display: none;
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.7);
    z-index: 100;
    align-items: center;
    justify-content: center;
  }
  .modal-overlay.active { display: flex; }
  .modal {
    background: #1a1f2e;
    border: 1px solid #2a3044;
    border-radius: 8px;
    padding: 28px 32px;
    max-width: 380px;
    text-align: center;
  }
  .modal h3 { color: #e05555; margin-bottom: 10px; font-size: 15px; }
  .modal p  { color: #aaa; font-size: 12px; margin-bottom: 20px; }
  .modal .btn-row { display: flex; gap: 10px; justify-content: center; }

  #filter-input {
    background: #1a1f2e;
    border: 1px solid #2a3044;
    color: #e0e0e0;
    padding: 6px 12px;
    border-radius: 4px;
    font-size: 12px;
    width: 220px;
    margin-bottom: 10px;
  }
</style>
</head>
<body>

<header>
  <div>
    <h1>🔍 VulnScanner</h1>
    <div class="host" id="host-label">Loading...</div>
  </div>
  <button class="btn btn-danger" onclick="document.getElementById('shutdown-modal').classList.add('active')">
    Stop &amp; Shutdown
  </button>
</header>

<div class="container">

  <!-- Stats -->
  <div class="stats" id="stats-row">
    <div class="stat pkgs">    <div class="val" id="s-pkgs">—</div>    <div class="lbl">Host Packages</div></div>
    <div class="stat total">   <div class="val" id="s-total">—</div>   <div class="lbl">Total Vulns</div></div>
    <div class="stat critical"><div class="val" id="s-crit">—</div>    <div class="lbl">Critical</div></div>
    <div class="stat high">    <div class="val" id="s-high">—</div>    <div class="lbl">High</div></div>
    <div class="stat medium">  <div class="val" id="s-med">—</div>     <div class="lbl">Medium</div></div>
    <div class="stat low">     <div class="val" id="s-low">—</div>     <div class="lbl">Low</div></div>
  </div>

  <!-- Actions -->
  <div class="actions">
    <a id="dl-btn" class="btn btn-disabled" href="#">⬇ Download Excel Report</a>
    <span id="scan-status-badge" class="badge waiting">Waiting</span>
  </div>

  <!-- Log -->
  <div class="section">
    <h2>Scan Log</h2>
    <div class="log-box" id="log-box"><span style="color:#555">Waiting for scan output...</span></div>
  </div>

  <!-- Vuln table -->
  <div class="section" id="vuln-section" style="display:none">
    <h2>Vulnerabilities</h2>
    <input id="filter-input" type="text" placeholder="Filter by CVE, package, severity...">
    <table id="vuln-table">
      <thead><tr>
        <th>CVE / ID</th><th>Severity</th><th>CVSS</th>
        <th>Package</th><th>Version</th><th>Fix</th><th>Source</th><th>Description</th>
      </tr></thead>
      <tbody id="vuln-body"></tbody>
    </table>
  </div>

  <!-- Container table -->
  <div class="section" id="container-section" style="display:none">
    <h2>Containers</h2>
    <table>
      <thead><tr>
        <th>Image</th><th>Packages</th><th>Vulns</th><th>Critical</th><th>High</th>
      </tr></thead>
      <tbody id="container-body"></tbody>
    </table>
  </div>

</div>

<!-- Shutdown modal -->
<div class="modal-overlay" id="shutdown-modal">
  <div class="modal">
    <h3>Shut down the server?</h3>
    <p>This will stop the web UI. You can re-run <code>scan-and-report</code> at any time.</p>
    <div class="btn-row">
      <button class="btn btn-danger" onclick="shutdown()">Yes, shut down</button>
      <button class="btn btn-primary" onclick="document.getElementById('shutdown-modal').classList.remove('active')">Cancel</button>
    </div>
  </div>
</div>

<script>
  let allVulns = [];

  // ── Log streaming ──────────────────────────────────────────────────────────
  const logBox = document.getElementById('log-box');
  let logEmpty = true;

  const evtSource = new EventSource('/stream');
  evtSource.onmessage = (e) => {
    if (logEmpty) { logBox.innerHTML = ''; logEmpty = false; }
    const line = document.createElement('div');
    line.className = 'line' +
      (e.data.startsWith('[✓]') ? ' ok' :
       e.data.startsWith('[!]') ? ' warn' :
       e.data.startsWith('[✗]') ? ' err' : '');
    line.textContent = e.data;
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;
  };

  evtSource.addEventListener('done', () => {
    evtSource.close();
    document.getElementById('scan-status-badge').textContent = 'Complete';
    document.getElementById('scan-status-badge').className = 'badge done';
    loadSummary();
    const dlBtn = document.getElementById('dl-btn');
    dlBtn.href = '/download';
    dlBtn.className = 'btn btn-primary';
  });

  evtSource.addEventListener('running', () => {
    document.getElementById('scan-status-badge').textContent = 'Scanning';
    document.getElementById('scan-status-badge').className = 'badge running';
  });

  // ── Summary ────────────────────────────────────────────────────────────────
  function loadSummary() {
    fetch('/summary')
      .then(r => r.json())
      .then(d => {
        document.getElementById('host-label').textContent =
          (d.meta.hostname || '') + '  ·  ' + (d.meta.os || '') + '  ·  ' + (d.meta.date || '');
        document.getElementById('s-pkgs').textContent  = d.host_pkgs;
        document.getElementById('s-total').textContent = d.counts.total;
        document.getElementById('s-crit').textContent  = d.counts.critical;
        document.getElementById('s-high').textContent  = d.counts.high;
        document.getElementById('s-med').textContent   = d.counts.medium;
        document.getElementById('s-low').textContent   = d.counts.low;

        // Vulns table
        allVulns = d.vulns;
        renderVulns(allVulns);
        document.getElementById('vuln-section').style.display = allVulns.length ? '' : 'none';

        // Containers
        const cb = document.getElementById('container-body');
        cb.innerHTML = '';
        d.containers.forEach(c => {
          cb.innerHTML += `<tr>
            <td><code>${c.image}</code></td>
            <td>${c.packages}</td>
            <td>${c.vulns}</td>
            <td style="color:${c.critical ? '#e05555' : '#aaa'}">${c.critical}</td>
            <td style="color:${c.high ? '#e07755' : '#aaa'}">${c.high}</td>
          </tr>`;
        });
        if (d.containers.length) document.getElementById('container-section').style.display = '';
      });
  }

  function renderVulns(vulns) {
    const tb = document.getElementById('vuln-body');
    tb.innerHTML = '';
    vulns.forEach(v => {
      tb.innerHTML += `<tr>
        <td><strong>${v.cve}</strong></td>
        <td><span class="sev sev-${v.severity}">${v.severity}</span></td>
        <td>${v.cvss || '—'}</td>
        <td>${v.package}</td>
        <td>${v.version}</td>
        <td>${v.fix || '<span style="color:#555">—</span>'}</td>
        <td><span style="color:#666;font-size:11px">${v.source}</span></td>
        <td class="desc-cell">${v.desc}</td>
      </tr>`;
    });
  }

  // ── Filter ─────────────────────────────────────────────────────────────────
  document.getElementById('filter-input').addEventListener('input', function() {
    const q = this.value.toLowerCase();
    renderVulns(allVulns.filter(v =>
      v.cve.toLowerCase().includes(q) ||
      v.package.toLowerCase().includes(q) ||
      v.severity.toLowerCase().includes(q) ||
      v.source.toLowerCase().includes(q)
    ));
  });

  // ── Shutdown ───────────────────────────────────────────────────────────────
  function shutdown() {
    fetch('/shutdown', { method: 'POST' }).finally(() => {
      document.getElementById('shutdown-modal').classList.remove('active');
      document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:Arial;color:#4caf50;font-size:18px">Server stopped. You can close this tab.</div>';
    });
  }

  // Poll summary every 5s while scan is running (in case SSE missed done event)
  setInterval(() => {
    fetch('/status').then(r => r.json()).then(d => {
      if (d.done) loadSummary();
    });
  }, 5000);
</script>
</body>
</html>"""

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/stream")
def stream():
    def generate():
        yield "event: running\ndata: scan started\n\n"
        last = 0
        while True:
            with scan_lock:
                lines = scan_log[last:]
                last += len(lines)
                done = scan_done
            for line in lines:
                yield f"data: {line}\n\n"
            if done and not lines:
                yield "event: done\ndata: complete\n\n"
                break
            time.sleep(0.5)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/summary")
def summary():
    return jsonify(get_summary())

@app.route("/status")
def status():
    return jsonify({"done": scan_done})

@app.route("/download")
def download():
    if not os.path.exists(REPORT_PATH):
        return "Report not ready yet", 404
    return send_file(REPORT_PATH, as_attachment=True,
                     download_name=os.path.basename(REPORT_PATH))

@app.route("/shutdown", methods=["POST"])
def shutdown_server():
    def _stop():
        time.sleep(1)
        os._exit(0)
    threading.Thread(target=_stop, daemon=True).start()
    return "Shutting down"

# ── Scan runner ───────────────────────────────────────────────────────────────
def run_scan():
    global scan_done
    venv_python = os.path.join(INSTALL_DIR, "venv", "bin", "python3")

    commands = [
        ["bash", os.path.join(INSTALL_DIR, "scan.sh"), SCAN_DIR],
        [venv_python, os.path.join(INSTALL_DIR, "generate_report.py"),
         SCAN_DIR, REPORT_PATH],
    ]

    for cmd in commands:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                with scan_lock:
                    scan_log.append(line)
        proc.wait()
        if proc.returncode != 0:
            with scan_lock:
                scan_log.append(f"[✗] Command failed with exit code {proc.returncode}")

    with scan_lock:
        scan_done = True
        scan_log.append("[✓] All done. Download your report above.")

if __name__ == "__main__":
    t = threading.Thread(target=run_scan, daemon=True)
    t.start()
    print(f"[*] Web UI running at http://0.0.0.0:{PORT}")
    print(f"[*] Open http://$(hostname -I | awk '{{print $1}}'):{PORT} from your browser")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
