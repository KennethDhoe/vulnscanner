#!/usr/bin/env bash
# install.sh — Bootstrap Syft + Grype + Python env for security scanning
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, Arch, SUSE
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/YOURUSER/YOURREPO/main/install.sh)

set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/KennethDhoe/vulnscanner/main"
INSTALL_DIR="/opt/syft-grype-report"

# ── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "${ID_LIKE:-$ID}"
  elif command -v apk &>/dev/null;  then echo "alpine"
  elif command -v apt-get &>/dev/null; then echo "debian"
  elif command -v dnf &>/dev/null;  then echo "fedora"
  elif command -v yum &>/dev/null;  then echo "rhel"
  elif command -v pacman &>/dev/null; then echo "arch"
  elif command -v zypper &>/dev/null; then echo "suse"
  else
    echo "unknown"
  fi
}

DISTRO=$(detect_distro)
echo "[*] Detected distro family: $DISTRO"

# ── Install system packages ───────────────────────────────────────────────────
install_deps() {
  case "$DISTRO" in
    *debian*|*ubuntu*)
      apt-get update -qq
      apt-get install -y -q \
        curl python3 python3-pip python3-full python3-venv \
        libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 libffi-dev shared-mime-info fonts-liberation
      ;;
    *fedora*|*rhel*|*centos*)
      PKG="dnf"
      command -v dnf &>/dev/null || PKG="yum"
      $PKG install -y -q \
        curl python3 python3-pip python3-virtualenv \
        pango gdk-pixbuf2 libffi shared-mime-info \
        levien-inconsolata-fonts google-noto-fonts-common
      ;;
    *alpine*)
      apk add --quiet --no-cache \
        curl python3 py3-pip py3-virtualenv \
        pango gdk-pixbuf fontconfig ttf-liberation shared-mime-info
      ;;
    *arch*)
      pacman -Sy --noconfirm --quiet \
        curl python python-pip python-virtualenv \
        pango gdk-pixbuf2 shared-mime-info ttf-liberation
      ;;
    *suse*|*opensuse*)
      zypper install -y -q \
        curl python3 python3-pip python3-virtualenv \
        pango gdk-pixbuf libffi shared-mime-info fonts-liberation2
      ;;
    *)
      echo "[!] Unknown distro — skipping system package install."
      echo "    Make sure these are installed manually:"
      echo "    curl, python3, python3-venv, pango, gdk-pixbuf, libffi"
      ;;
  esac
}

echo "[*] Installing system dependencies..."
install_deps
echo "[✓] System dependencies installed"

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

# ── Python venv + packages ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
if [ ! -d "$INSTALL_DIR/venv" ]; then
  echo "[*] Creating Python venv..."
  python3 -m venv "$INSTALL_DIR/venv"
fi
echo "[*] Installing Python packages..."
"$INSTALL_DIR/venv/bin/pip" install --quiet openpyxl weasyprint
echo "[✓] Python packages installed"

# ── Download scripts ──────────────────────────────────────────────────────────
echo "[*] Downloading scripts..."
curl -fsSL "$REPO_RAW/scan.sh"                -o "$INSTALL_DIR/scan.sh"
curl -fsSL "$REPO_RAW/generate_report.py"     -o "$INSTALL_DIR/generate_report.py"
curl -fsSL "$REPO_RAW/generate_pdf_report.py" -o "$INSTALL_DIR/generate_pdf_report.py"
chmod +x "$INSTALL_DIR/scan.sh"

# ── Wrapper: scan-and-report ──────────────────────────────────────────────────
cat > /usr/local/bin/scan-and-report <<WRAPPER
#!/usr/bin/env bash
OUTPUT_DIR="\${1:-/tmp/scan_output}"
BASENAME="\${2:-/tmp/security_report}"
sudo bash $INSTALL_DIR/scan.sh "\$OUTPUT_DIR"
$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/generate_report.py     "\$OUTPUT_DIR" "\${BASENAME}.xlsx"
$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/generate_pdf_report.py "\$OUTPUT_DIR" "\${BASENAME}.pdf"
echo ""
echo "[✓] Reports ready:"
echo "    Excel : \${BASENAME}.xlsx"
echo "    PDF   : \${BASENAME}.pdf"
WRAPPER
chmod +x /usr/local/bin/scan-and-report

# ── Update Grype DB ───────────────────────────────────────────────────────────
echo "[*] Updating Grype vulnerability database..."
grype db update

echo ""
echo "════════════════════════════════════════════"
echo " Installation complete."
echo ""
echo " Run a full scan:   scan-and-report"
echo " Custom paths:      scan-and-report /tmp/out /tmp/my_report"
echo "════════════════════════════════════════════"

# ── Run scan ──────────────────────────────────────────────────────────────────
echo "[*] Starting scan..."
scan-and-report
