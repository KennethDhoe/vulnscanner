#!/usr/bin/env python3
"""
generate_pdf_report.py — Generate a PDF security report from Syft + Grype scan output
Usage: python generate_pdf_report.py [scan_output_dir] [report.pdf]
"""

import json
import sys
import os
import glob
from datetime import datetime, timezone
from pathlib import Path

# ── Config ───────────────────────────────────────────────────────────────────
SCAN_DIR    = sys.argv[1] if len(sys.argv) > 1 else "./scan_output"
OUTPUT_FILE = sys.argv[2] if len(sys.argv) > 2 else "security_report.pdf"

SEVERITY_ORDER  = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}
SEVERITY_COLORS = {
    "Critical":  ("#C00000", "#FFFFFF"),
    "High":      ("#FF4C4C", "#FFFFFF"),
    "Medium":    ("#FF7C00", "#FFFFFF"),
    "Low":       ("#FFD700", "#000000"),
    "Negligible":("#AAAAAA", "#FFFFFF"),
    "Unknown":   ("#DDDDDD", "#000000"),
}

# ── Data loaders (shared with generate_report.py) ────────────────────────────
def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def load_host_meta(path):
    meta = {}
    if not os.path.exists(path):
        return meta
    with open(path) as f:
        for line in f:
            k, _, v = line.strip().partition("=")
            meta[k] = v
    return meta

def parse_syft_packages(sbom):
    if not sbom or "artifacts" not in sbom:
        return []
    packages = []
    for a in sbom["artifacts"]:
        packages.append({
            "name":     a.get("name", ""),
            "version":  a.get("version", ""),
            "type":     a.get("type", ""),
            "language": a.get("language", ""),
            "location": "; ".join(
                loc.get("realPath", loc.get("path", ""))
                for loc in a.get("locations", [])
            )[:120],
        })
    return packages

def parse_grype_vulns(vuln_json, source="host"):
    if not vuln_json or "matches" not in vuln_json:
        return []
    vulns = []
    for m in vuln_json["matches"]:
        v   = m.get("vulnerability", {})
        art = m.get("artifact", {})
        fix = v.get("fix", {})
        vulns.append({
            "source":      source,
            "cve":         v.get("id", ""),
            "severity":    v.get("severity", "Unknown"),
            "cvss":        next(
                (s.get("metrics", {}).get("baseScore", "")
                 for s in v.get("cvss", []) if s.get("metrics", {}).get("baseScore")),
                ""
            ),
            "package":     art.get("name", ""),
            "version":     art.get("version", ""),
            "fix_version": ", ".join(fix.get("versions", [])) if fix else "",
            "fix_state":   fix.get("state", "") if fix else "",
            "description": v.get("description", "")[:200],
        })
    return vulns

# ── HTML builder ─────────────────────────────────────────────────────────────
def sev_badge(severity):
    bg, fg = SEVERITY_COLORS.get(severity, ("#DDDDDD", "#000000"))
    return f'<span class="badge" style="background:{bg};color:{fg}">{severity}</span>'

def vuln_rows(vulns):
    if not vulns:
        return '<tr><td colspan="7" class="empty">No vulnerabilities found.</td></tr>'
    rows = ""
    for v in sorted(vulns, key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x["package"])):
        fix = v["fix_version"] if v["fix_version"] else f'<span class="nofix">{v["fix_state"] or "—"}</span>'
        rows += f"""
        <tr>
          <td>{v['cve']}</td>
          <td>{sev_badge(v['severity'])}</td>
          <td>{v['cvss'] or '—'}</td>
          <td><strong>{v['package']}</strong></td>
          <td>{v['version']}</td>
          <td>{fix}</td>
          <td class="desc">{v['description']}</td>
        </tr>"""
    return rows

def pkg_rows(packages):
    if not packages:
        return '<tr><td colspan="4" class="empty">No packages found.</td></tr>'
    rows = ""
    for p in sorted(packages, key=lambda x: x["name"]):
        rows += f"""
        <tr>
          <td><strong>{p['name']}</strong></td>
          <td>{p['version']}</td>
          <td>{p['type']}</td>
          <td class="desc">{p['location']}</td>
        </tr>"""
    return rows

def count_by_sev(vulns, sev):
    return sum(1 for v in vulns if v["severity"] == sev)

def build_html(meta, host_pkgs, host_vulns, container_data):
    all_vulns = host_vulns + [v for _, _, cv in container_data for v in cv]
    critical_high = [v for v in all_vulns if v["severity"] in ("Critical", "High")]
    scan_date = meta.get("date", datetime.now(timezone.utc).isoformat())

    # Summary stat boxes
    def stat_box(label, value, color="#1F4E79"):
        return f'<div class="stat-box"><div class="stat-val" style="color:{color}">{value}</div><div class="stat-label">{label}</div></div>'

    summary_boxes = "".join([
        stat_box("Host Packages",      len(host_pkgs)),
        stat_box("Total Vulns",        len(all_vulns)),
        stat_box("Critical",           count_by_sev(all_vulns, "Critical"), "#C00000"),
        stat_box("High",               count_by_sev(all_vulns, "High"),     "#FF4C4C"),
        stat_box("Medium",             count_by_sev(all_vulns, "Medium"),   "#FF7C00"),
        stat_box("Containers Scanned", len(container_data)),
    ])

    # Container inventory table
    container_rows = ""
    for img, pkgs, vulns in sorted(container_data, key=lambda x: x[0]):
        crit = count_by_sev(vulns, "Critical")
        high = count_by_sev(vulns, "High")
        med  = count_by_sev(vulns, "Medium")
        low  = count_by_sev(vulns, "Low")
        crit_str = f'<strong style="color:#C00000">{crit}</strong>' if crit else str(crit)
        high_str = f'<strong style="color:#FF4C4C">{high}</strong>' if high else str(high)
        container_rows += f"""
        <tr>
          <td><code>{img}</code></td>
          <td>{len(pkgs)}</td>
          <td>{len(vulns)}</td>
          <td>{crit_str}</td>
          <td>{high_str}</td>
          <td>{med}</td>
          <td>{low}</td>
        </tr>"""
    if not container_rows:
        container_rows = '<tr><td colspan="7" class="empty">No containers scanned.</td></tr>'

    # Per-container vuln sections
    container_vuln_sections = ""
    for img, pkgs, vulns in sorted(container_data, key=lambda x: x[0]):
        if not vulns:
            continue
        container_vuln_sections += f"""
        <h3 style="margin-top:1.5em;color:#1F4E79;font-size:0.95em">
          Container: <code>{img}</code>
        </h3>
        <table>
          <thead><tr>
            <th>CVE</th><th>Severity</th><th>CVSS</th>
            <th>Package</th><th>Version</th><th>Fix</th><th>Description</th>
          </tr></thead>
          <tbody>{vuln_rows(vulns)}</tbody>
        </table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  @page {{
    size: A4 landscape;
    margin: 15mm 12mm;
    @top-center {{
      content: "Security Scan Report — {meta.get('hostname','unknown')}";
      font-family: Arial, sans-serif;
      font-size: 8pt;
      color: #888;
    }}
    @bottom-right {{
      content: "Page " counter(page) " of " counter(pages);
      font-family: Arial, sans-serif;
      font-size: 8pt;
      color: #888;
    }}
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: Arial, sans-serif;
    font-size: 9pt;
    color: #1a1a1a;
    line-height: 1.4;
  }}

  /* Cover block */
  .cover {{
    background: #1F4E79;
    color: white;
    padding: 20px 24px;
    border-radius: 4px;
    margin-bottom: 20px;
  }}
  .cover h1 {{ font-size: 20pt; font-weight: 700; margin-bottom: 4px; }}
  .cover .sub {{ font-size: 10pt; opacity: 0.85; }}

  /* Meta grid */
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 6px;
    margin-bottom: 20px;
  }}
  .meta-item {{ background: #F0F4F8; padding: 6px 10px; border-radius: 3px; }}
  .meta-item .key {{ font-size: 7.5pt; color: #666; text-transform: uppercase; letter-spacing: 0.03em; }}
  .meta-item .val {{ font-size: 9pt; font-weight: 600; color: #1F4E79; }}

  /* Stat boxes */
  .stat-row {{ display: flex; gap: 8px; margin-bottom: 20px; }}
  .stat-box {{
    flex: 1;
    background: #F7F9FC;
    border: 1px solid #DDE3EA;
    border-radius: 4px;
    padding: 10px;
    text-align: center;
  }}
  .stat-val {{ font-size: 18pt; font-weight: 700; }}
  .stat-label {{ font-size: 7.5pt; color: #666; text-transform: uppercase; margin-top: 2px; }}

  /* Section headers */
  h2 {{
    font-size: 11pt;
    color: #1F4E79;
    border-bottom: 2px solid #1F4E79;
    padding-bottom: 4px;
    margin: 20px 0 10px;
    page-break-after: avoid;
  }}

  /* Tables */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 8pt;
    margin-bottom: 16px;
    page-break-inside: auto;
  }}
  thead {{ display: table-header-group; }}
  tr {{ page-break-inside: avoid; }}
  th {{
    background: #1F4E79;
    color: white;
    padding: 5px 6px;
    text-align: left;
    font-weight: 600;
    font-size: 7.5pt;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}
  td {{
    padding: 4px 6px;
    border-bottom: 1px solid #E8ECF0;
    vertical-align: top;
  }}
  tr:nth-child(even) td {{ background: #F7F9FC; }}
  .desc {{ color: #444; font-size: 7.5pt; max-width: 220px; }}
  .empty {{ color: #888; font-style: italic; padding: 8px 6px; }}
  .nofix {{ color: #888; font-style: italic; }}

  /* Severity badge */
  .badge {{
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 7.5pt;
    font-weight: 700;
    white-space: nowrap;
  }}

  /* Critical/High priority section */
  .priority-header {{
    background: #7B0000;
    color: white;
    padding: 6px 10px;
    border-radius: 4px 4px 0 0;
    font-weight: 700;
    font-size: 10pt;
    margin-bottom: 0;
    page-break-after: avoid;
  }}
  .priority-header + table th {{ background: #A00000; }}

  code {{
    font-family: monospace;
    font-size: 8pt;
    background: #F0F4F8;
    padding: 1px 4px;
    border-radius: 2px;
  }}

  .page-break {{ page-break-before: always; }}
</style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <h1>Security Scan Report</h1>
  <div class="sub">{meta.get('hostname','unknown')} &nbsp;·&nbsp; {scan_date}</div>
</div>

<!-- Host metadata -->
<div class="meta-grid">
  <div class="meta-item"><div class="key">Operating System</div><div class="val">{meta.get('os','N/A')}</div></div>
  <div class="meta-item"><div class="key">Kernel</div><div class="val">{meta.get('kernel','N/A')}</div></div>
  <div class="meta-item"><div class="key">Architecture</div><div class="val">{meta.get('arch','N/A')}</div></div>
  <div class="meta-item"><div class="key">Hostname</div><div class="val">{meta.get('hostname','N/A')}</div></div>
  <div class="meta-item"><div class="key">Uptime</div><div class="val">{meta.get('uptime','N/A')}</div></div>
  <div class="meta-item"><div class="key">Scan Date</div><div class="val">{scan_date}</div></div>
</div>

<!-- Summary stats -->
<div class="stat-row">{summary_boxes}</div>

<!-- Priority: Critical & High -->
<div class="priority-header">⚠ Critical &amp; High Vulnerabilities</div>
<table>
  <thead><tr>
    <th>CVE / ID</th><th>Severity</th><th>CVSS</th>
    <th>Package</th><th>Version</th><th>Fix Version</th><th>Source</th><th>Description</th>
  </tr></thead>
  <tbody>
    {"".join(
        f"<tr><td>{v['cve']}</td><td>{sev_badge(v['severity'])}</td><td>{v['cvss'] or '—'}</td>"
        f"<td><strong>{v['package']}</strong></td><td>{v['version']}</td>"
        f"<td>{v['fix_version'] or '—'}</td><td>{v['source']}</td>"
        f"<td class='desc'>{v['description']}</td></tr>"
        for v in sorted(critical_high, key=lambda x: (SEVERITY_ORDER.get(x['severity'],99), x['package']))
    ) or '<tr><td colspan="8" class="empty">No Critical or High vulnerabilities found.</td></tr>'}
  </tbody>
</table>

<!-- Container Inventory -->
<h2>Container Inventory</h2>
<table>
  <thead><tr>
    <th>Image</th><th>Packages</th><th>Total Vulns</th>
    <th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
  </tr></thead>
  <tbody>{container_rows}</tbody>
</table>

<!-- Host Vulnerabilities -->
<div class="page-break"></div>
<h2>Host Vulnerabilities</h2>
<table>
  <thead><tr>
    <th>CVE / ID</th><th>Severity</th><th>CVSS</th>
    <th>Package</th><th>Version</th><th>Fix Version</th><th>Description</th>
  </tr></thead>
  <tbody>{vuln_rows(host_vulns)}</tbody>
</table>

<!-- Container Vulnerabilities -->
<div class="page-break"></div>
<h2>Container Vulnerabilities</h2>
{container_vuln_sections or '<p class="empty">No container vulnerabilities found.</p>'}

<!-- Host Packages -->
<div class="page-break"></div>
<h2>Host Packages ({len(host_pkgs)} total)</h2>
<table>
  <thead><tr>
    <th>Name</th><th>Version</th><th>Type</th><th>Location</th>
  </tr></thead>
  <tbody>{pkg_rows(host_pkgs)}</tbody>
</table>

</body>
</html>"""

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    from weasyprint import HTML

    print(f"[*] Loading scan data from: {SCAN_DIR}")

    meta       = load_host_meta(os.path.join(SCAN_DIR, "host_meta.txt"))
    host_sbom  = load_json(os.path.join(SCAN_DIR, "host_sbom.json"))
    host_vj    = load_json(os.path.join(SCAN_DIR, "host_vulns.json"))
    host_pkgs  = parse_syft_packages(host_sbom)
    host_vulns = parse_grype_vulns(host_vj, source="host")

    print(f"    Host packages : {len(host_pkgs)}")
    print(f"    Host vulns    : {len(host_vulns)}")

    container_data = []
    containers_dir = os.path.join(SCAN_DIR, "containers")
    if os.path.isdir(containers_dir):
        for sbom_path in glob.glob(os.path.join(containers_dir, "*_sbom.json")):
            base     = sbom_path.replace("_sbom.json", "")
            img_name = os.path.basename(base).replace("___", "/", 1).replace("___", ":")
            vuln_path = base + "_vulns.json"
            pkgs  = parse_syft_packages(load_json(sbom_path))
            vulns = parse_grype_vulns(load_json(vuln_path), source=img_name)
            container_data.append((img_name, pkgs, vulns))
            print(f"    Container [{img_name}]: {len(pkgs)} pkgs, {len(vulns)} vulns")

    print("[*] Rendering PDF...")
    html = build_html(meta, host_pkgs, host_vulns, container_data)
    HTML(string=html).write_pdf(OUTPUT_FILE)
    print(f"[✓] PDF report saved: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
