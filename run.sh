#!/usr/bin/env bash
# install.sh — Bootstrap Syft + Grype + Python env for security scanning
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, Arch, SUSE
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/KennethDhoe/vulnscanner/main/install.sh)

set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/KennethDhoe/vulnscanner/main"
INSTALL_DIR="/opt/syft-grype-report"

# ── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "${ID_LIKE:-$ID}"
  elif command -v apk &>/dev/null;     then echo "alpine"
  elif command -v apt-get &>/dev/null; then echo "debian"
  elif command -v dnf &>/dev/null;     then echo "fedora"
  elif command -v yum &>/dev/null;     then echo "rhel"
  elif command -v pacman &>/dev/null;  then echo "arch"
  elif command -v zypper &>/dev/null;  then echo "suse"
  else echo "unknown"
  fi
}

DISTRO=$(detect_distro)
echo "[*] Detected distro family: $DISTRO"

# ── List packages ─────────────────────────────────────────────────────────────
list_deps() {
  case "$DISTRO" in
    *debian*|*ubuntu*)
      echo "  curl, python3, python3-pip, python3-full, python3-venv"
      echo "  libpango-1.0-0, libpangoft2-1.0-0, libpangocairo-1.0-0"
      echo "  libgdk-pixbuf2.0-0, libffi-dev, shared-mime-info, fonts-liberation"
      ;;
    *fedora*|*rhel*|*centos*)
      echo "  curl, python3, python3-pip, python3-virtualenv"
      echo "  pango, gdk-pixbuf2, libffi, shared-mime-info"
      echo "  levien-inconsolata-fonts, google-noto-fonts-common"
      ;;
    *alpine*)
      echo "  curl, python3, py3-pip, py3-virtualenv"
      echo "  pango, gdk-pixbuf, fontconfig, ttf-liberation, shared-mime-info"
      ;;
    *arch*)
      echo "  curl, python, python-pip, python-virtualenv"
      echo "  pango, gdk-pixbuf2, shared-mime-info, ttf-liberation"
      ;;
    *suse*|*opensuse*)
      echo "  curl, python3, python3-pip, python3-virtualenv"
      echo "  pango, gdk-pixbuf, libffi, shared-mime-info, fonts-liberation2"
      ;;
    *)
      echo "  curl, python3, python3-venv, pango, gdk-pixbuf, libffi"
      ;;
  esac
  echo ""
  echo "  Python packages (isolated venv):"
  echo "  openpyxl, flask"
  echo ""
  echo "  Tools (installed to /usr/local/bin):"
  echo "  syft, grype"
}

# ── Install system packages ───────────────────────────────────────────────────
install_deps() {
  case "$DISTRO" in
    *debian*|*ubuntu*)
      apt-get update -qq
      apt-get install -y \
        curl python3 python3-pip python3-full python3-venv \
        libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 libffi-dev shared-mime-info fonts-liberation
      ;;
    *fedora*|*rhel*|*centos*)
      PKG="dnf"; command -v dnf &>/dev/null || PKG="yum"
      $PKG install -y \
        curl python3 python3-pip python3-virtualenv \
        pango gdk-pixbuf2 libffi shared-mime-info \
        levien-inconsolata-fonts google-noto-fonts-common
      ;;
    *alpine*)
      apk add --no-cache \
        curl python3 py3-pip py3-virtualenv \
        pango gdk-pixbuf fontconfig ttf-liberation shared-mime-info
      ;;
    *arch*)
      pacman -Sy --noconfirm \
        curl python python-pip python-virtualenv \
        pango gdk-pixbuf2 shared-mime-info ttf-liberation
      ;;
    *suse*|*opensuse*)
      zypper install -y \
        curl python3 python3-pip python3-virtualenv \
        pango gdk-pixbuf libffi shared-mime-info fonts-liberation2
      ;;
    *)
      echo "[!] Unknown distro — skipping system package install."
      echo "    Install manually: curl, python3, python3-venv, pango, gdk-pixbuf, libffi"
      ;;
  esac
}

# ── Confirm before proceeding ─────────────────────────────────────────────────
echo ""
echo "The following will be installed on this system:"
echo "────────────────────────────────────────────────"
list_deps
echo "────────────────────────────────────────────────"
read -r -p "Continue? [y/N] " confirm
case "$confirm" in
  [yY][eE][sS]|[yY]) ;;
  *) echo "Aborted."; exit 1 ;;
esac

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
"$INSTALL_DIR/venv/bin/pip" install --quiet openpyxl flask
echo "[✓] Python packages installed"

# ── Download scripts ──────────────────────────────────────────────────────────
echo "[*] Downloading scripts..."
curl -fsSL "$REPO_RAW/scan.sh"             -o "$INSTALL_DIR/scan.sh"
curl -fsSL "$REPO_RAW/generate_report.py"  -o "$INSTALL_DIR/generate_report.py"
curl -fsSL "$REPO_RAW/webserver.py"        -o "$INSTALL_DIR/webserver.py"
chmod +x "$INSTALL_DIR/scan.sh"

# ── Wrapper: scan-and-report ──────────────────────────────────────────────────
cat > /usr/local/bin/scan-and-report <<WRAPPER
#!/usr/bin/env bash
OUTPUT_DIR="\${1:-/tmp/scan_output}"
REPORT="\${2:-/tmp/security_report.xlsx}"
PORT="\${3:-5000}"

SCAN_DIR="\$OUTPUT_DIR" \
REPORT_PATH="\$REPORT" \
INSTALL_DIR="$INSTALL_DIR" \
PORT="\$PORT" \
$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/webserver.py
WRAPPER
chmod +x /usr/local/bin/scan-and-report

# ── Update Grype DB ───────────────────────────────────────────────────────────
echo "[*] Updating Grype vulnerability database..."
grype db update

# ── Run ───────────────────────────────────────────────────────────────────────
echo "[*] Starting scan and web UI..."
scan-and-report
