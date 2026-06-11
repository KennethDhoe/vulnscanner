#!/usr/bin/env bash
# run.sh — VulnScanner bootstrap
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, Arch, SUSE
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/KennethDhoe/vulnscanner/main/run.sh)

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

# ── Check what's already installed ───────────────────────────────────────────
NEED_SYSDEPS=false
NEED_SYFT=false
NEED_GRYPE=false
NEED_VENV=false
NEED_SCRIPTS=false

# System deps: check for python3 AND that venv actually works
if ! command -v python3 &>/dev/null; then
  NEED_SYSDEPS=true
elif ! python3 -m venv /tmp/vulnscanner_venv_test &>/dev/null 2>&1; then
  NEED_SYSDEPS=true
  rm -rf /tmp/vulnscanner_venv_test
else
  rm -rf /tmp/vulnscanner_venv_test
fi

command -v syft  &>/dev/null  || NEED_SYFT=true
command -v grype &>/dev/null  || NEED_GRYPE=true

[ ! -d "$INSTALL_DIR/venv" ] && NEED_VENV=true
[ ! -f "$INSTALL_DIR/webserver.py" ] && NEED_SCRIPTS=true

# ── Nothing to do path ───────────────────────────────────────────────────────
if ! $NEED_SYSDEPS && ! $NEED_SYFT && ! $NEED_GRYPE && ! $NEED_VENV && ! $NEED_SCRIPTS; then
  echo "[✓] All dependencies already installed, skipping setup."
  echo "[*] Starting VulnScanner..."
  scan-and-report
  exit 0
fi

# ── Show what needs installing ────────────────────────────────────────────────
echo ""
echo "The following will be installed:"
echo "────────────────────────────────────────────────"
$NEED_SYSDEPS  && echo "  [new] System packages (python3, venv, pango, fonts, ...)"
$NEED_SYFT     && echo "  [new] syft"
$NEED_GRYPE    && echo "  [new] grype"
$NEED_VENV     && echo "  [new] Python venv + openpyxl, flask"
$NEED_SCRIPTS  && echo "  [new] VulnScanner scripts → $INSTALL_DIR"
! $NEED_SYSDEPS && echo "  [ok]  System packages"
! $NEED_SYFT    && echo "  [ok]  syft ($(syft version 2>/dev/null | head -1))"
! $NEED_GRYPE   && echo "  [ok]  grype ($(grype version 2>/dev/null | head -1))"
! $NEED_VENV    && echo "  [ok]  Python venv"
! $NEED_SCRIPTS && echo "  [ok]  VulnScanner scripts"
echo "────────────────────────────────────────────────"
read -r -p "Continue? [y/N] " confirm
case "$confirm" in
  [yY][eE][sS]|[yY]) ;;
  *) echo "Aborted."; exit 1 ;;
esac

# ── Install system packages ───────────────────────────────────────────────────
if $NEED_SYSDEPS; then
  echo "[*] Installing system dependencies..."
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
      echo "[!] Unknown distro — skipping system packages."
      echo "    Install manually: curl, python3, python3-venv, pango, gdk-pixbuf, libffi"
      ;;
  esac
  echo "[✓] System dependencies installed"
else
  echo "[✓] System dependencies already present"
fi

# ── Syft ─────────────────────────────────────────────────────────────────────
if $NEED_SYFT; then
  echo "[*] Installing Syft..."
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  echo "[✓] Syft installed: $(syft version | head -1)"
else
  echo "[✓] Syft already installed: $(syft version | head -1)"
fi

# ── Grype ────────────────────────────────────────────────────────────────────
if $NEED_GRYPE; then
  echo "[*] Installing Grype..."
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  echo "[✓] Grype installed: $(grype version | head -1)"
else
  echo "[✓] Grype already installed: $(grype version | head -1)"
fi

# ── Python venv + packages ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
if $NEED_VENV; then
  echo "[*] Creating Python venv..."
  python3 -m venv "$INSTALL_DIR/venv"
  echo "[*] Installing Python packages..."
  "$INSTALL_DIR/venv/bin/pip" install --quiet openpyxl flask
  echo "[✓] Python packages installed"
else
  echo "[✓] Python venv already present"
fi

# ── Download scripts ──────────────────────────────────────────────────────────
if $NEED_SCRIPTS; then
  echo "[*] Downloading VulnScanner scripts..."
  curl -fsSL "$REPO_RAW/scan.sh"            -o "$INSTALL_DIR/scan.sh"
  curl -fsSL "$REPO_RAW/generate_report.py" -o "$INSTALL_DIR/generate_report.py"
  curl -fsSL "$REPO_RAW/webserver.py"       -o "$INSTALL_DIR/webserver.py"
  chmod +x "$INSTALL_DIR/scan.sh"
  echo "[✓] Scripts downloaded"
else
  echo "[✓] Scripts already present"
fi

# ── Wrapper ───────────────────────────────────────────────────────────────────
cat > /usr/local/bin/scan-and-report <<WRAPPER
#!/usr/bin/env bash
PORT="\${1:-5000}"

SCAN_BASE="/var/lib/vulnscanner/scans" \
INSTALL_DIR="$INSTALL_DIR" \
PORT="\$PORT" \
$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/webserver.py
WRAPPER
chmod +x /usr/local/bin/scan-and-report

# ── Update Grype DB ───────────────────────────────────────────────────────────
echo "[*] Updating Grype vulnerability database..."
grype db update

# ── Launch ────────────────────────────────────────────────────────────────────
echo "[*] Starting VulnScanner..."
scan-and-report
