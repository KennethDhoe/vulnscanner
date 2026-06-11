#!/usr/bin/env bash
# install.sh — Bootstrap Syft + Grype + Python env for security scanning
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/YOURUSER/YOURREPO/main/install.sh)

set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/KennethDhoe/vulnscanner/main"
INSTALL_DIR="/opt/syft-grype-report"

echo "[*] Creating install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# ── Syft ─────────────────────────────────────────────────────────────────────
if command -v syft &>/dev/null; then
  echo "[✓] Syft already installed: $(syft version | head -1)"
else
  echo "[*] Installing Syft..."
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  echo "[✓] Syft installed: $(syft version | head -1)"
fi

# ── Grype ────────────────────────────────────────────────────────────────────
if command -v grype &>/dev/null; then
  echo "[✓] Grype already installed: $(grype version | head -1)"
else
  echo "[*] Installing Grype..."
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  echo "[✓] Grype installed: $(grype version | head -1)"
fi

# ── Python venv + openpyxl ────────────────────────────────────────────────────
if [ ! -d "$INSTALL_DIR/venv" ]; then
  echo "[*] Creating Python venv..."
  python3 -m venv "$INSTALL_DIR/venv"
fi
echo "[*] Installing openpyxl..."
"$INSTALL_DIR/venv/bin/pip" install --quiet openpyxl
echo "[✓] openpyxl installed"

# ── Download scripts ──────────────────────────────────────────────────────────
echo "[*] Downloading scan.sh and generate_report.py..."
curl -fsSL "$REPO_RAW/scan.sh"             -o "$INSTALL_DIR/scan.sh"
curl -fsSL "$REPO_RAW/generate_report.py"  -o "$INSTALL_DIR/generate_report.py"
chmod +x "$INSTALL_DIR/scan.sh"

# ── Wrapper: scan-and-report ──────────────────────────────────────────────────
cat > /usr/local/bin/scan-and-report <<WRAPPER
#!/usr/bin/env bash
# Usage: scan-and-report [output_dir] [report.xlsx]
OUTPUT_DIR="\${1:-/tmp/scan_output}"
REPORT="\${2:-/tmp/security_report.xlsx}"
sudo bash $INSTALL_DIR/scan.sh "\$OUTPUT_DIR"
$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/generate_report.py "\$OUTPUT_DIR" "\$REPORT"
echo "[✓] Report ready: \$REPORT"
WRAPPER
chmod +x /usr/local/bin/scan-and-report

# ── Update Grype DB ───────────────────────────────────────────────────────────
echo "[*] Updating Grype vulnerability database (this may take a moment)..."
grype db update

echo ""
echo "════════════════════════════════════════════"
echo " Installation complete."
echo " Run a scan with:  scan-and-report"
echo " Or with paths:    scan-and-report /tmp/out /tmp/report.xlsx"
echo "════════════════════════════════════════════"
