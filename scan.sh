#!/usr/bin/env bash
# scan.sh — Syft + Grype host & container scanner
# Usage: sudo ./scan.sh [output_dir]

set -euo pipefail

OUTPUT_DIR="${1:-./scan_output}"
mkdir -p "$OUTPUT_DIR"

echo "[*] Output directory: $OUTPUT_DIR"

# ── Host metadata ────────────────────────────────────────────────────────────
echo "[*] Collecting host metadata..."
{
  echo "hostname=$(hostname)"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "os=$(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "kernel=$(uname -r)"
  echo "arch=$(uname -m)"
  echo "uptime=$(uptime -p 2>/dev/null || uptime)"
} > "$OUTPUT_DIR/host_meta.txt"

# ── Host SBOM (Syft) ─────────────────────────────────────────────────────────
echo "[*] Scanning host filesystem with Syft..."
syft packages:/ \
  -o syft-json \
  > "$OUTPUT_DIR/host_sbom.json"

# ── Host vulns (Grype) ───────────────────────────────────────────────────────
echo "[*] Scanning host SBOM with Grype..."
grype sbom:"$OUTPUT_DIR/host_sbom.json" \
  -o json \
  > "$OUTPUT_DIR/host_vulns.json"

# ── Container images ─────────────────────────────────────────────────────────
CONTAINER_SBOMS_DIR="$OUTPUT_DIR/containers"
mkdir -p "$CONTAINER_SBOMS_DIR"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  echo "[*] Docker detected, scanning images..."
  docker images --format "{{.Repository}}:{{.Tag}}" | grep -v '<none>' | while read -r img; do
    safe_name=$(echo "$img" | tr '/: ' '___')
    echo "    [+] $img"
    syft "docker:$img" -o syft-json > "$CONTAINER_SBOMS_DIR/${safe_name}_sbom.json" 2>/dev/null || true
    grype sbom:"$CONTAINER_SBOMS_DIR/${safe_name}_sbom.json" -o json \
      > "$CONTAINER_SBOMS_DIR/${safe_name}_vulns.json" 2>/dev/null || true
  done
else
  echo "[!] Docker not available or not running, skipping container scan."
fi

echo "[✓] Scan complete. Files in: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
