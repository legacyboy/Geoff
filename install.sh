#!/usr/bin/env bash
# ============================================================================
# GEOFF Installer — Git-backed Evidence Operations Forensic Framework
# ============================================================================
# Usage:
#   curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash
#   curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --profile local
#   curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --profile cloud --dir /opt/geoff
#   curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --profile cloud --ollama-key YOUR_KEY
#
# Options:
#   --profile cloud|local   Model profile (default: cloud)
#   --ollama-key <key>      Ollama API key for cloud models (sets OLLAMA_API_KEY env var)
#   --dir <path>            Install directory (default: /opt/geoff)
#   --skip-ollama           Skip Ollama model pulls (Ollama itself is always installed if missing)
#   --skip-deps             Skip apt dependency installs
#   -h, --help              Show this help
# ============================================================================

set -euo pipefail

REPO="https://github.com/legacyboy/Geoff.git"
INSTALL_DIR="/opt/geoff"
PROFILE="cloud"
OLLAMA_KEY=""
OLLAMA_SIGNIN=false
SKIP_OLLAMA=false
SKIP_REMNUX=false
SKIP_DEPS=false
REMNUX_BG_PID=""

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[GEOFF]${NC} $*"; }
ok()    { echo -e "${GREEN}[GEOFF]${NC} $*"; }
warn()  { echo -e "${YELLOW}[GEOFF]${NC} $*"; }
fail()  { echo -e "${RED}[GEOFF]${NC} $*" >&2; exit 1; }

# ── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)     PROFILE="$2"; shift 2;;
        --ollama-key)  OLLAMA_KEY="$2"; shift 2;;
        --ollama-signin) OLLAMA_SIGNIN=true; shift;;
        --dir)         INSTALL_DIR="$2"; shift 2;;
        --skip-ollama) SKIP_OLLAMA=true; shift;;
        --skip-remnux) SKIP_REMNUX=true; shift;;
        --skip-deps)   SKIP_DEPS=true; shift;;
        -h|--help)
            echo "GEOFF Installer — Git-backed Evidence Operations Forensic Framework"
            echo ""
            echo "Usage: curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- [options]"
            echo ""
            echo "Options:"
            echo "  --profile cloud|local   Model profile (default: cloud)"
            echo "  --ollama-key <key>      Ollama API key for cloud models"
            echo "  --ollama-signin         Interactive ollama signin"
            echo "  --dir <path>            Install directory (default: /opt/geoff)"
            echo "  --skip-ollama           Skip Ollama model pulls"
            echo "  --skip-remnux           Skip REMnux install"
            echo "  --skip-deps             Skip apt dependency installs"
            echo "  -h, --help              Show this help"
            exit 0
            ;;
        *) fail "Unknown option: $1";;
    esac
done

# ── Validate profile ───────────────────────────────────────────────────────
if [[ "$PROFILE" != "cloud" && "$PROFILE" != "local" ]]; then
    fail "Unknown profile '$PROFILE'. Must be 'cloud' or 'local'."
fi

if [[ "$PROFILE" == "cloud" ]]; then
    if [[ -z "$OLLAMA_KEY" && "$OLLAMA_SIGNIN" == false ]]; then
        warn "Cloud profile selected. Cloud models require authentication:"
        warn "  Option 1: --ollama-signin (interactive login via 'ollama signin')"
        warn "  Option 2: --ollama-key <key> (for direct ollama.com API access)"
        warn "Cloud models may fail without authentication."
    fi
fi

info "Installing GEOFF with profile: ${YELLOW}${PROFILE}${NC}"
info "Install directory: ${INSTALL_DIR}"

# ── Check prerequisites ────────────────────────────────────────────────────
command -v git >/dev/null  || fail "git is required but not found"
command -v python3 >/dev/null || fail "python3 is required but not found"

# ── Install system dependencies ─────────────────────────────────────────────
if [[ "$SKIP_DEPS" == false ]]; then
    info "Installing system dependencies..."
    if command -v apt-get >/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq python3-pip python3-venv python3.12-venv git curl jq \
            sleuthkit ewf-tools ssdeep hashdeep exiftool plaso-tools \
            regripper libimage-exiftool-perl \
            foremost scalpel tcpflow zeek \
            libbde-utils libpst-utils pst-utils libguestfs-tools qemu-utils \
            bulk-extractor dc3dd cryptsetup testdisk \
            libmagic1 libmagic-dev \
            libimobiledevice-utils ifuse \
            yara chkrootkit rkhunter debsums \
            nfdump geoip-bin \
            tcpdump sqlite3 nmap ncat socat iptables nftables ent \
            libvshadow-utils ltrace strace busybox-static cron \
            docker.io \
            etcd-client passing-the-hash 2>/dev/null || true
        # Ensure forensic tools are available
        info "Verifying forensic tool installation..."
        for tool in exiftool tshark ssdeep hashdeep ewfmount vol yara vol.py foremost scalpel tcpflow zeek bdeinfo readpst guestmount qemu-img bulk_extractor dc3dd; do
            if ! command -v $tool &>/dev/null; then
                warn "$tool not found in PATH — some analyses may fail"
            fi
        done
        # Verify REMnux/malware tools are findable
        for tool in die exiftool hashdeep clamscan upx pdfid oledump.py pdf-parser.py js-beautify floss peframe r2; do
            if ! command -v $tool &>/dev/null; then
                warn "$tool not found in PATH — REMnux playbook may skip this tool"
            fi
        done
        # guestmount fallback — libguestfs-tools may not be in all repos
        if ! command -v guestmount &>/dev/null; then
            info "guestmount not found — attempting specific install..."
            sudo apt-get install -y -qq libguestfs-tools 2>/dev/null || true
            if ! command -v guestmount &>/dev/null; then
                # Fallback: download and install the deb from Debian bookworm
                info "  Attempting direct .deb install from Debian..."
                GUESTFS_DEB="libguestfs-tools_1.52.0-5+b1_amd64.deb"
                curl -sL "http://ftp.debian.org/debian/pool/main/libg/libguestfs/${GUESTFS_DEB}" \
                    -o "/tmp/${GUESTFS_DEB}" 2>/dev/null && \
                    sudo dpkg -i "/tmp/${GUESTFS_DEB}" 2>/dev/null && \
                    sudo apt-get install -f -y -qq 2>/dev/null && \
                    rm -f "/tmp/${GUESTFS_DEB}" && \
                    ok "guestmount installed via direct .deb" || \
                    warn "guestmount install failed — VM forensics will use qemu-img only"
            fi
        fi
        # REMnux tools (install if on REMnux or SIFT with REMnux repo)
        sudo apt-get install -y -qq die upx clamav radare2 2>/dev/null || true
        # Python-based REMnux/malware tools (install via pip since apt packages may not exist)
        info "Installing Python-based REMnux/malware tools..."
        pip3 install --break-system-packages \
            oletools floss jsbeautifier capstone python-evtx \
            plyvel pyinstxtractor uncompyle6 \
            pefile python-magic lief construct \
            gitpython mcp 2>/dev/null || \
            pip3 install --user \
            oletools floss jsbeautifier capstone python-evtx \
            plyvel pyinstxtractor uncompyle6 \
            pefile python-magic lief construct \
            gitpython mcp 2>/dev/null || true
        # Verify critical Python forensic tools
        info "Verifying Python forensic imports..."
        for _py_tool in python-evtx lief construct mcp; do
            _py_mod="${_py_tool//-/_}"
            if python3 -c "import ${_py_mod}" 2>/dev/null; then
                info "  ${_py_tool}: OK"
            else
                warn "  ${_py_tool}: NOT INSTALLED — retrying individually..."
                pip3 install --break-system-packages "${_py_tool}" 2>/dev/null || \
                    pip3 install --user "${_py_tool}" 2>/dev/null || true
            fi
        done
        # yara-python — Python bindings for YARA (binary installed via apt separately)
        if ! python3 -c "import yara" 2>/dev/null; then
            info "Installing yara-python (YARA Python bindings)..."
            pip3 install --break-system-packages yara-python 2>/dev/null || \
                pip3 install --user yara-python 2>/dev/null || \
                warn "yara-python install failed — YARA scanning from Python will be unavailable"
        fi
        # Ensure ~/.local/bin is on PATH for pip-installed tools
        LOCAL_BIN="${HOME}/.local/bin"
        if [ -d "$LOCAL_BIN" ] && [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
            export PATH="$LOCAL_BIN:$PATH"
            echo "export PATH=\$PATH:$LOCAL_BIN" >> "${HOME}/.bashrc" 2>/dev/null
        fi
        # peframe — install from GitHub (no pip package)
        if ! command -v peframe &>/dev/null; then
            info "Installing peframe (PE static analysis)..."
            info "  Cloning from guelfoweb/peframe.git..."
            pip3 install --break-system-packages git+https://github.com/guelfoweb/peframe.git 2>/dev/null || \
                pip3 install --user git+https://github.com/guelfoweb/peframe.git 2>/dev/null || \
                warn "peframe install failed — PE analysis will use die/file as fallback"
            command -v peframe &>/dev/null && ok "peframe installed"
        fi
        # crackmapexec — AD/network security assessment (PB-SIFT-035)
        if ! command -v crackmapexec &>/dev/null && ! command -v nxc &>/dev/null; then
            info "Installing crackmapexec (AD/network security)..."
            info "  pip installing crackmapexec..."
            pip3 install --break-system-packages crackmapexec 2>/dev/null || \
                pip3 install --user crackmapexec 2>/dev/null || \
                warn "crackmapexec install failed — AD DC forensics playbook may be limited"
            if command -v crackmapexec &>/dev/null || command -v nxc &>/dev/null; then
                ok "crackmapexec installed"
            fi
        fi
        # fsevents-parser — macOS FSEvents log parser (PB-SIFT-024)
        if ! python3 -c "import fsevents_parser" &>/dev/null 2>&1; then
            info "Installing fsevents-parser (macOS FSEvents)..."
            pip3 install --break-system-packages fsevents-parser 2>/dev/null || \
                pip3 install --user fsevents-parser 2>/dev/null || \
                warn "fsevents-parser install failed — macOS FSEvents analysis will be limited"
            python3 -c "import fsevents_parser" 2>/dev/null && ok "fsevents-parser installed"
        fi
        # kubectl — Kubernetes CLI (PB-SIFT-033 container forensics)
        if ! command -v kubectl &>/dev/null; then
            info "Installing kubectl..."
            curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key 2>/dev/null | \
                sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg 2>/dev/null && \
                echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | \
                sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null && \
                sudo apt-get update -qq && \
                sudo apt-get install -y -qq kubectl 2>/dev/null || \
                warn "kubectl install failed — Kubernetes forensics (PB-SIFT-033) will be limited"
        fi
        # crictl — CRI container runtime CLI (PB-SIFT-033)
        if ! command -v crictl &>/dev/null; then
            info "Installing crictl..."
            CRICTL_VER=$(curl -s https://api.github.com/repos/kubernetes-sigs/cri-tools/releases/latest | \
                grep '"tag_name"' | sed 's/.*"v\([^"]*\)\".*/\1/' 2>/dev/null || echo "1.29.0")
            curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/v${CRICTL_VER}/crictl-v${CRICTL_VER}-linux-amd64.tar.gz" \
                -o /tmp/crictl.tar.gz 2>/dev/null && \
                sudo tar -C /usr/local/bin -xzf /tmp/crictl.tar.gz 2>/dev/null && \
                rm -f /tmp/crictl.tar.gz || \
                warn "crictl install failed — container runtime forensics (PB-SIFT-033) will be limited"
        fi
        # chrome-historiographer — Chrome history parser (PB-SIFT-022)
        if ! python3 -c "import chrome_historian" &>/dev/null 2>&1; then
            info "Installing chrome-historiographer (Chrome history parser)..."
            pip3 install --break-system-packages chrome-historiographer 2>/dev/null || \
                pip3 install --user chrome-historiographer 2>/dev/null || \
                warn "chrome-historiographer install failed — Chrome history parsing will use SQLite fallback"
            python3 -c "import chrome_historian" 2>/dev/null && ok "chrome-historiographer installed"
        fi
        # Tshark (needs non-interactive setup)
        echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
        sudo apt-get install -y -qq tshark wireshark-common 2>/dev/null || true
        # Volatility3 - only install if missing
        # Check for 'vol' or 'volatility3' binary (SIFT may ship either) in system and venv
        vol_found=false
        if command -v vol &>/dev/null || command -v volatility3 &>/dev/null; then
            vol_found=true
            info "Volatility3 already installed ($(command -v vol 2>/dev/null || command -v volatility3 2>/dev/null))"
        elif [ -f "${INSTALL_DIR}/venv/bin/vol" ] || [ -f "${INSTALL_DIR}/venv/bin/volatility3" ]; then
            vol_found=true
            info "Volatility3 already in venv"
        fi
        if [ "$vol_found" = false ]; then
            info "Installing volatility3..."
            sudo apt-get install -y -qq python3-pip 2>/dev/null || true
            sudo pip3 install volatility3 --break-system-packages 2>/dev/null || \
                sudo pip3 install volatility3 2>/dev/null || true
            # Also install into venv if it exists
            if [ -d "${INSTALL_DIR}/venv" ]; then
                source "${INSTALL_DIR}/venv/bin/activate" 2>/dev/null && \
                    pip install volatility3 2>/dev/null || true
                deactivate 2>/dev/null || true
            fi
            # Verify install
            if command -v vol &>/dev/null; then
                ok "Volatility3 installed (vol: $(command -v vol))"
            elif [ -f "${INSTALL_DIR}/venv/bin/vol" ]; then
                ok "Volatility3 installed in venv"
            else
                warn "Volatility3 installation may have failed — check manually"
            fi
        fi
        # Volatility2 - install alongside Volatility3 for legacy OS support (Win2K, XP early)
        vol2_found=false
        if command -v vol.py &>/dev/null || [ -f /usr/local/bin/vol.py ]; then
            # Verify the existing vol.py actually runs on python3
            if python3 /usr/local/bin/vol.py --help &>/dev/null 2>&1; then
                vol2_found=true
                info "Volatility2 already installed and working"
            else
                warn "Existing vol.py found but broken — will reinstall"
                sudo rm -f /usr/local/bin/vol.py 2>/dev/null || true
            fi
        fi
        if [ "$vol2_found" = false ]; then
            info "Installing Volatility2 for legacy OS support (Win2K, XP early)..."
            # Volatility2 is Python 2 source. On modern SIFT/Kali (Python 3.12+),
            # 2to3/lib2to3 are removed from stdlib. We apply manual sed fixes
            # for Python 2 syntax (print statements, except clauses).
            VOL2_URL="https://github.com/volatilityfoundation/volatility/archive/refs/heads/master.zip"
            info "  Downloading Volatility2 from GitHub..."
            if curl -sL "$VOL2_URL" -o "/tmp/vol2.zip" 2>/dev/null && \
               unzip -q -o "/tmp/vol2.zip" -d "/tmp/vol2" 2>/dev/null && \
               sudo mkdir -p /opt/volatility2 && \
               sudo cp -r /tmp/vol2/volatility-master/* /opt/volatility2/ 2>/dev/null; then
                info "  Applying Python 2→3 syntax fixes to all Volatility2 .py files..."
                # Fix shebang in all .py files: python → python3
                sudo find /opt/volatility2 -name '*.py' -exec sed -i '1s|^#!.*python[0-9]*\?|#!/usr/bin/env python3|' {} \;
                # Convert print statements: print X → print(X)
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/^\([[:space:]]*\)print \([^(].*\)$/\1print(\2)/' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/^\([[:space:]]*\)print$/\1print()/' {} \;
                # Convert except X, e: → except X as e: (single class)
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/except \([A-Za-z_][A-Za-z0-9_.]*\), \([a-z_][a-z0-9_]*\):/except \1 as \2:/g' {} \;
                # Convert except (X, Y), e: → except (X, Y) as e: (tuple exceptions)
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/except (\([^)]*\)), \([a-z_][a-z0-9_]*\):/except (\1) as \2:/g' {} \;
                # Convert Python 2 stdlib imports to Python 3
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/import ConfigParser/import configparser/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/ConfigParser\.ConfigParser/configparser.ConfigParser/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/import StringIO/import io/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/StringIO\.StringIO/io.StringIO/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/import cPickle as pickle/import pickle/g' {} \;
                # Convert raise Class, "msg" → raise Class("msg") (Python 2 raise syntax)
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/raise \([A-Z][A-Za-z]*\), \(.*\)/raise \1(\2)/g' {} \;
                # Convert long → int (Python 2 builtin, unified in Python 3)
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/class Address(long)/class Address(int)/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/class Address64(long)/class Address64(int)/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/class Hex(long)/class Hex(int)/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/long\.__new__/int.__new__/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/= long(/= int(/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/set(\[int, long,/set([int,/g' {} \;
                # Fix type-check comparisons with long
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/== long)/== int)/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/== long and/== int and/g' {} \;
                # Fix collections.abc for Python 3.12+
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/collections\.Sequence/collections.abc.Sequence/g' {} \;
                sudo find /opt/volatility2 -name '*.py' -exec sed -i 's/collections\.OrderedDict()/dict()/g' {} \;
                # Fix StandardError → Exception (removed in Python 3)
                sudo sed -i 's/class TreePopulationError(StandardError)/class TreePopulationError(Exception)/' /opt/volatility2/volatility/renderers/__init__.py
                # Fix tuple parameter unpacking in lambda (2 instances in renderers/__init__.py)
                sudo sed -i 's/lambda (x, y): sort_key(x\.values)/lambda xy: sort_key(xy[0].values)/g' /opt/volatility2/volatility/renderers/__init__.py
                # Verify vol.py runs on python3
                if python3 /opt/volatility2/vol.py --help &>/dev/null 2>&1; then
                    sudo ln -sf /opt/volatility2/vol.py /usr/local/bin/vol.py
                    ok "Volatility2 installed and verified (python3 compatible)"
                else
                    warn "Volatility2 syntax fixes incomplete — vol.py may have issues"
                    sudo ln -sf /opt/volatility2/vol.py /usr/local/bin/vol.py 2>/dev/null || true
                fi
            else
                warn "Volatility2 download failed — legacy memory dumps will need manual processing"
            fi
            rm -rf "/tmp/vol2" "/tmp/vol2.zip" 2>/dev/null || true
        fi
        # Install REMnux distro for malware analysis tools
        # REMnux addon install can take 20+ minutes on first run.
        # We background it and wait at the end so the rest of the install continues.
        REMNUX_BG_PID=""
        if [[ "$SKIP_REMNUX" == true ]]; then
            info "Skipping REMnux install (--skip-remnux)"
        elif ! command -v remnux &>/dev/null; then
            info "Installing REMnux distro (addon mode) — running in background..."
            (
                set +e
                cd /tmp
                curl -sSL -O https://REMnux.org/remnux 2>/dev/null && \
                    chmod +x /tmp/remnux && sudo mv /tmp/remnux /usr/local/bin/ && \
                    sudo remnux install --mode=addon 2>&1 | tail -1 || \
                    echo "REMNUX_BG_FAIL"
                rm -f /tmp/remnux 2>/dev/null
            ) & REMNUX_BG_PID=$!
            info "REMnux install running in background (PID: ${REMNUX_BG_PID})"
        else
            info "REMnux already installed, updating..."
            (
                set +e
                sudo remnux update 2>&1 | tail -1 || echo "REMNUX_BG_FAIL"
            ) & REMNUX_BG_PID=$!
            info "REMnux update running in background (PID: ${REMNUX_BG_PID})"
        fi
    elif command -v dnf >/dev/null; then
        sudo dnf install -y python3-pip git curl jq 2>/dev/null || true
    elif command -v yum >/dev/null; then
        sudo yum install -y python3-pip git curl jq 2>/dev/null || true
    fi

    # Create wrapper scripts for Python-only forensic tools
    VENV_BIN="${INSTALL_DIR}/venv/bin"
    if [ -d "$VENV_BIN" ]; then
        info "Creating forensic tool wrappers..."
        # pdfid wrapper (Python module, not a CLI binary)
        cat > "${VENV_BIN}/pdfid" << 'PDFID_EOF'
#!/bin/bash
exec python3 -m pdfid "$@"
PDFID_EOF
        chmod +x "${VENV_BIN}/pdfid"
        # die wrapper (fallback to 'file' command when Detect It Easy CLI unavailable)
        cat > "${VENV_BIN}/die" << 'DIE_EOF'
#!/bin/bash
if command -v diec >/dev/null 2>&1; then
    exec diec "$@"
else
    exec file "$@"
fi
DIE_EOF
        chmod +x "${VENV_BIN}/die"
        ok "Forensic tool wrappers created"
    fi

    # Zimmerman Tools (Eric Zimmerman forensic tools — .NET 9)
    info "Setting up Zimmerman forensic tools..."
    ZIMMERMAN_DIR="/opt/zimmerman_tools"
    sudo mkdir -p "$ZIMMERMAN_DIR"
    sudo chown "$(whoami):$(id -gn)" "$ZIMMERMAN_DIR"
    if ! command -v dotnet >/dev/null 2>&1; then
        info "Installing .NET 9 runtime for Zimmerman tools..."
        curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 9.0 --runtime-only 2>/dev/null || \
            sudo apt-get install -y -qq dotnet-runtime-9.0 2>/dev/null || \
            warn "dotnet install failed — Zimmerman tools will be unavailable"
        # Add dotnet to PATH if installed via script
        export PATH="$HOME/.dotnet:$PATH"
    fi
    if command -v dotnet >/dev/null 2>&1 || [[ -f "$HOME/.dotnet/dotnet" ]]; then
        for tool in EvtxECmd MFTECmd bstrings ShellBagsExplorer AmcacheParser SrumECmd PECmd JLECmd LECmd AppCompatCacheParser WxTCmd RecentFileCacheParser RBCmd SQLECmd; do
            if [[ ! -f "${ZIMMERMAN_DIR}/${tool}/${tool}.dll" ]]; then
                info "  Downloading ${tool}..."
                # Download from Zimmerman's distribution (net9 builds)
                # Extract into per-tool subdir, then flatten files from nested dirs
                ZIM_TOOL_DIR="${ZIMMERMAN_DIR}/${tool}"
                mkdir -p "$ZIM_TOOL_DIR"
                if curl -sL "https://download.ericzimmermanstools.com/net9/${tool}.zip" -o "/tmp/${tool}.zip"; then
                    if unzip -q -o "/tmp/${tool}.zip" -d "$ZIM_TOOL_DIR" 2>/dev/null; then
                        # Flatten: move files from nested subdirs into tool dir
                        find "$ZIM_TOOL_DIR" -mindepth 2 -type f -exec mv -n {} "$ZIM_TOOL_DIR/" \; 2>/dev/null || true
                        # Clean up empty subdirectories
                        find "$ZIM_TOOL_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null || true
                        # Remove non-empty subdirs that only contain maps/data (keep them as subdirs)
                        ok "  ${tool} downloaded and extracted"
                    else
                        warn "Failed to extract ${tool}"
                    fi
                else
                    warn "Failed to download ${tool}"
                fi
                rm -f "/tmp/${tool}.zip"
            else
                info "  ${tool} already present"
            fi
        done
        ok "Zimmerman tools ready"
    else
        warn "dotnet not available — Zimmerman tools skipped"
    fi

    # apfs-fuse — APFS volume mounting (macOS + encrypted container playbooks)
    if ! command -v apfs-fuse &>/dev/null; then
        info "Installing apfs-fuse for APFS volume support..."
        info "  Installing apfs-fuse build dependencies..."
        sudo apt-get update -qq 2>/dev/null || true
        sudo apt-get install -y -qq fuse libfuse-dev cmake libattr1-dev zlib1g-dev bzip2 libbz2-dev \
            libz-dev 2>/dev/null || true
        # liblzfse-dev may not exist in all repos — try it but don't fail
        sudo apt-get install -y -qq liblzfse-dev 2>/dev/null || \
            info "  liblzfse-dev not available — building without LZFSE compression"
        # Verify critical build deps before attempting build
        MISSING_DEPS=""
        for _dep in cmake gcc g++; do
            command -v $_dep &>/dev/null || MISSING_DEPS="$MISSING_DEPS $_dep"
        done
        dpkg -s libfuse-dev 2>/dev/null | grep -q 'install ok installed' || MISSING_DEPS="$MISSING_DEPS libfuse-dev"
        if [ -n "$MISSING_DEPS" ]; then
            warn "Missing apfs-fuse build deps:${MISSING_DEPS} — APFS mounting may use fsapfs fallback"
        fi
        if ! command -v apfs-fuse &>/dev/null; then
            info "  Building apfs-fuse from source..."
            ( cd /tmp && \
                git clone --depth=1 https://github.com/sgan81/apfs-fuse.git /tmp/apfs-fuse 2>/dev/null && \
                cd /tmp/apfs-fuse && git submodule update --init --recursive 2>/dev/null && \
                mkdir -p build && cd build && cmake .. 2>/dev/null && make -j"$(nproc)" 2>/dev/null && \
                sudo make install 2>/dev/null && rm -rf /tmp/apfs-fuse 2>/dev/null
            ) || warn "apfs-fuse build failed — APFS volumes will need manual mounting"
        fi
    else
        info "apfs-fuse already installed"
    fi

    # pycdc — Python bytecode decompiler (PB-009 Malware Hunting); not in apt, build from source
    if ! command -v pycdc &>/dev/null; then
        info "Building pycdc (Python bytecode decompiler) from source..."
        sudo apt-get install -y -qq cmake 2>/dev/null || true
        ( cd /tmp && \
            git clone --depth=1 https://github.com/zrax/pycdc.git /tmp/pycdc 2>/dev/null && \
            cd /tmp/pycdc && cmake . -DCMAKE_BUILD_TYPE=Release 2>/dev/null && make -j2 2>/dev/null && \
            sudo cp pycdc pycdas /usr/local/bin/ 2>/dev/null && \
            rm -rf /tmp/pycdc
        ) || warn "pycdc build failed — Python bytecode decompilation (PB-009) will fall back to uncompyle6"
    else
        info "pycdc already installed"
    fi

    # dive — Docker layer explorer (container forensics playbook)
    if ! command -v dive &>/dev/null; then
        info "Installing dive for Docker layer analysis..."
        DIVE_VERSION=$(curl -s https://api.github.com/repos/wagoodman/dive/releases/latest \
            | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/' 2>/dev/null || echo "0.12.0")
        curl -sL "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_amd64.deb" \
            -o "/tmp/dive.deb" 2>/dev/null && \
            sudo dpkg -i /tmp/dive.deb 2>/dev/null && rm -f /tmp/dive.deb || \
            warn "dive install failed — container layer analysis will be manual"
    else
        info "dive already installed"
    fi

    # python-cim — WMI repository parser (persistence playbooks)
    # Note: flare-wmi was renamed to flare-cim in 2023
    if ! python3 -c "import cim" &>/dev/null 2>&1; then
        info "Installing python-cim for WMI repository forensics..."
        pip3 install --break-system-packages git+https://github.com/mandiant/flare-cim.git 2>/dev/null || \
            pip3 install --user git+https://github.com/mandiant/flare-cim.git 2>/dev/null || \
            warn "python-cim install failed — WMI OBJECTS.DATA parsing will use strings fallback"
    else
        info "python-cim already installed"
    fi

    # iLEAPP — clone from GitHub for full iOS backup analysis (PB-021)
    if [ ! -d /opt/iLEAPP ]; then
        info "Installing iLEAPP to /opt/iLEAPP..."
        sudo git clone --depth=1 https://github.com/abrignoni/iLEAPP.git /opt/iLEAPP 2>/dev/null || \
            warn "iLEAPP clone failed — iOS mobile analysis will be limited"
    else
        info "iLEAPP already installed at /opt/iLEAPP"
    fi
    # ALEAPP — clone from GitHub for full Android data analysis (PB-021)
    if [ ! -d /opt/ALEAPP ]; then
        info "Installing ALEAPP to /opt/ALEAPP..."
        sudo git clone --depth=1 https://github.com/abrignoni/ALEAPP.git /opt/ALEAPP 2>/dev/null || \
            warn "ALEAPP clone failed — Android mobile analysis will be limited"
    else
        info "ALEAPP already installed at /opt/ALEAPP"
    fi
    if [ -f /opt/ALEAPP/requirements.txt ]; then
        pip3 install --break-system-packages -r /opt/ALEAPP/requirements.txt 2>/dev/null || true
    fi
    # Mobile malware analysis tools (APK/IPA)
    if ! command -v apktool &>/dev/null; then
        info "Installing apktool (Android APK analysis)..."
        info "  Downloading apktool wrapper script..."
        sudo wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool 2>/dev/null && \
            sudo chmod +x /usr/local/bin/apktool && \
            ok "apktool installed" || \
            warn "apktool download failed — APK analysis may be limited"
    fi
    sudo apt-get install -y -qq yara 2>/dev/null || true

    # Verify mobile tools
    for mobile_tool_dir in iLEAPP ALEAPP; do
        mobile_tool_lower="$(echo "$mobile_tool_dir" | tr '[:upper:]' '[:lower:]')"
        if [ -d "/opt/$mobile_tool_dir" ] && [ -f "/opt/$mobile_tool_dir/${mobile_tool_lower}.py" ]; then
            info "$mobile_tool_dir available for mobile forensics"
        else
            warn "$mobile_tool_dir not found — mobile analysis (PB-021) may be limited"
        fi
    done

    ok "System dependencies installed"
fi

# ── Clone repo ──────────────────────────────────────────────────────────────
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Updating existing GEOFF installation..."
    cd "$INSTALL_DIR"
    git pull origin main || warn "Git pull failed — continuing with existing code"
else
    # If the directory exists but is not a git repo (e.g., created by dependency installs),
    # remove it so git clone can proceed cleanly.
    if [[ -d "${INSTALL_DIR}" ]]; then
        info "Removing pre-existing directory ${INSTALL_DIR} for clean clone..."
        sudo rm -rf "${INSTALL_DIR}"
    fi
    info "Cloning GEOFF repository..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(whoami):$(id -gn)" "$INSTALL_DIR"
    git clone "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi
ok "Code ready at ${INSTALL_DIR}"

# ── Create evidence directories ────────────────────────────────────────────
info "Creating evidence storage directories..."
sudo mkdir -p /mnt/evidence
sudo mkdir -p /mnt/cases
sudo chown -R "$(whoami):$(id -gn)" /mnt/evidence /mnt/cases 2>/dev/null || true
ok "Evidence directories created"

# ── Python virtual environment ─────────────────────────────────────────────
info "Setting up Python environment..."
python3 -m venv "${INSTALL_DIR}/venv" 2>/dev/null || sudo python3 -m venv "${INSTALL_DIR}/venv" || sudo python3 -m venv "${INSTALL_DIR}/venv" || {
    warn "venv creation failed, trying with --without-pip..."
    python3 -m venv --without-pip "${INSTALL_DIR}/venv" || fail "Failed to create Python virtual environment"
    # Install pip manually into the venv
    curl -sSL https://bootstrap.pypa.io/get-pip.py | "${INSTALL_DIR}/venv/bin/python3"
}
source "${INSTALL_DIR}/venv/bin/activate" || fail "Failed to activate virtual environment"
pip install --quiet -r requirements.txt || { warn "Full requirements install failed, trying core packages..."; pip install --quiet flask requests jsonschema python-dotenv markupsafe gitpython mcp; }
ok "Python environment ready"

# ── Configure profile ──────────────────────────────────────────────────────
info "Configuring profile: ${PROFILE}"

# Create .env file for the profile
ENV_EXTRA=""
[[ -n "$OLLAMA_KEY" ]] && ENV_EXTRA="OLLAMA_API_KEY=${OLLAMA_KEY}"
cat > "${INSTALL_DIR}/.env" << EOF
GEOFF_PROFILE=${PROFILE}
OLLAMA_URL=http://localhost:11434
${ENV_EXTRA}
EOF

ok "Profile '${PROFILE}' configured in ${INSTALL_DIR}/.env"

# ── Install Ollama if missing ──────────────────────────────────────────
_OLLAMA_VERSION="0.30.5"
# Remove stale 0-byte placeholder binary left by previous failed installs
if [[ -f /usr/local/bin/ollama && ! -s /usr/local/bin/ollama ]]; then
    info "Removing stale 0-byte ollama placeholder at /usr/local/bin/ollama"
    sudo rm -f /usr/local/bin/ollama
fi
if ! command -v ollama >/dev/null 2>&1; then
    info "Installing Ollama ${_OLLAMA_VERSION} (pinned for cloud API key compatibility)..."
    _OLLAMA_URL="https://github.com/ollama/ollama/releases/download/v${_OLLAMA_VERSION}/ollama-linux-amd64.tar.zst"
    _OLLAMA_TMP="$(mktemp -d)"
    _OLLAMA_TARBALL="${_OLLAMA_TMP}/ollama.tar.zst"
    # Download tarball to a file first — piping directly hangs on large files
    curl -L -o "$_OLLAMA_TARBALL" "$_OLLAMA_URL" || fail "Ollama ${_OLLAMA_VERSION} download failed."
    if ! command -v zstd >/dev/null 2>&1; then
        sudo apt-get install -y -qq zstd >/dev/null 2>&1 || fail "Failed to install zstd (required to extract Ollama)."
    fi
    tar --zstd -xf "$_OLLAMA_TARBALL" -C "$_OLLAMA_TMP" || {
        rm -rf "$_OLLAMA_TMP"
        fail "Ollama ${_OLLAMA_VERSION} extraction failed."
    }
    # The tarball extracts to bin/ollama (not plain ollama) in newer releases
    if [ -f "${_OLLAMA_TMP}/bin/ollama" ]; then
        sudo mv "${_OLLAMA_TMP}/bin/ollama" /usr/local/bin/ollama
    elif [ -f "${_OLLAMA_TMP}/ollama" ]; then
        sudo mv "${_OLLAMA_TMP}/ollama" /usr/local/bin/ollama
    else
        rm -rf "$_OLLAMA_TMP"
        fail "Ollama binary not found in extracted tarball."
    fi
    sudo chmod +x /usr/local/bin/ollama
    # Also copy lib/ollama for CUDA support
    if [ -d "${_OLLAMA_TMP}/lib/ollama" ]; then
        sudo mkdir -p /usr/local/lib/ollama
        sudo cp -r "${_OLLAMA_TMP}/lib/ollama/"* /usr/local/lib/ollama/ 2>/dev/null || true
    fi
    rm -rf "$_OLLAMA_TMP"
    if ! command -v ollama >/dev/null 2>&1; then
        fail "Ollama install failed. Install manually: https://ollama.com"
    fi
    ok "Ollama ${_OLLAMA_VERSION} installed"
fi

# ── Ensure Ollama is running ──────────────────────────────────────────────
if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    info "Starting Ollama service..."

    # Create systemd service for Ollama with cloud API key if provided
    if command -v systemctl >/dev/null 2>&1; then
        _OLLAMA_SERVICE="/etc/systemd/system/ollama.service"
        if [[ ! -f "$_OLLAMA_SERVICE" ]]; then
            info "Creating systemd service for Ollama..."
            _OLLAMA_ENV_LINE=""
            [[ -n "$OLLAMA_KEY" ]] && _OLLAMA_ENV_LINE="Environment=OLLAMA_CLOUD_API_KEY=${OLLAMA_KEY}"
            sudo bash -c "cat > $_OLLAMA_SERVICE << 'SERVICEEOF'
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
User=${USER}
Group=${USER}
Restart=always
RestartSec=3
Environment=OLLAMA_HOST=127.0.0.1
${_OLLAMA_ENV_LINE}

[Install]
WantedBy=default.target
SERVICEEOF"
            sudo systemctl daemon-reload
            sudo systemctl enable ollama
            sudo systemctl start ollama
            ok "Ollama systemd service created and started"
        else
            # Service exists — restart to pick up any new env vars
            if [[ -n "$OLLAMA_KEY" ]]; then
                if ! grep -q "OLLAMA_CLOUD_API_KEY" "$_OLLAMA_SERVICE"; then
                    info "Updating Ollama service with cloud API key..."
                    sudo sed -i '/^\[Service\]/a Environment=OLLAMA_CLOUD_API_KEY='"${OLLAMA_KEY}" "$_OLLAMA_SERVICE"
                    sudo systemctl daemon-reload
                fi
            fi
            sudo systemctl restart ollama
        fi
    else
        # No systemd — fall back to background process
        ollama serve &>/dev/null &
    fi

    # Wait for Ollama to be ready
    for i in $(seq 1 30); do
        if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        fail "Ollama failed to start after 30 seconds"
    fi
    ok "Ollama is running"
fi

# ── Ensure Ollama SSH keys exist for cloud model auth ─────────────────────
if [[ "$PROFILE" == "cloud" && -n "$OLLAMA_KEY" ]]; then
    _OLLAMA_DIR="${HOME}/.ollama"
    if [[ ! -f "${_OLLAMA_DIR}/id_ed25519" ]]; then
        info "Generating Ollama SSH key pair for cloud model authentication..."
        mkdir -p "${_OLLAMA_DIR}"
        ssh-keygen -t ed25519 -f "${_OLLAMA_DIR}/id_ed25519" -N "" -q
        chmod 600 "${_OLLAMA_DIR}/id_ed25519"
        chmod 644 "${_OLLAMA_DIR}/id_ed25519.pub"
        ok "SSH key pair generated at ${_OLLAMA_DIR}/id_ed25519"
        
        # Register the public key with ollama.com using the API key
        _PUBKEY=$(cat "${_OLLAMA_DIR}/id_ed25519.pub")
        if curl -s -X POST "https://ollama.com/api/user/keys" \
            -H "Authorization: Bearer ${OLLAMA_KEY}" \
            -H "Content-Type: application/json" \
            -d "{\"key\": \"${_PUBKEY}\"}" >/dev/null 2>&1; then
            ok "Public key registered with ollama.com"
        else
            warn "Could not register public key with ollama.com — cloud model execution may fail"
            warn "  Run 'ollama signin' manually to authenticate"
        fi
        
        # Restart ollama to pick up the new keys
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl restart ollama 2>/dev/null || true
        fi
    fi
fi

# ── Pull Ollama models ────────────────────────────────────────────────────
if [[ "$SKIP_OLLAMA" == false ]]; then
    info "Setting up models for ${PROFILE} profile..."

        # Read model names from profiles.json
        if [[ -f "${INSTALL_DIR}/profiles.json" ]]; then
            MANAGER_MODEL=$(jq -r ".${PROFILE}.manager" "${INSTALL_DIR}/profiles.json")
            FORENSICATOR_MODEL=$(jq -r ".${PROFILE}.forensicator" "${INSTALL_DIR}/profiles.json")
            CRITIC_MODEL=$(jq -r ".${PROFILE}.critic" "${INSTALL_DIR}/profiles.json")
            CRITIC2_MODEL=$(jq -r ".${PROFILE}.critic2" "${INSTALL_DIR}/profiles.json")
        else
            # Fallback if profiles.json missing
            if [[ "$PROFILE" == "cloud" ]]; then
                MANAGER_MODEL="deepseek-v4-pro:cloud"
                FORENSICATOR_MODEL="qwen3-coder-next:cloud"
                CRITIC_MODEL="glm-5.1:cloud"
                CRITIC2_MODEL="gemma4:31b-cloud"
            else
                MANAGER_MODEL="deepseek-r1:32b"
                FORENSICATOR_MODEL="qwen2.5-coder:14b"
                CRITIC_MODEL="qwen2.5:14b"
                CRITIC2_MODEL="gemma4:31b"
            fi
        fi

        info "  Manager:      ${MANAGER_MODEL}"
        info "  Forensicator: ${FORENSICATOR_MODEL}"
        info "  Critic:       ${CRITIC_MODEL}"
        info "  Critic 2:     ${CRITIC2_MODEL}"

        if [[ "$PROFILE" == "cloud" ]]; then
            # ── Cloud: pull from ollama.com registry ──
            [[ -n "$OLLAMA_KEY" ]] && export OLLAMA_API_KEY="$OLLAMA_KEY"

            if [[ "$OLLAMA_SIGNIN" == true ]]; then
                info "Running 'ollama signin' (interactive) — enter your Ollama credentials:"
                ollama signin || warn "ollama signin failed — cloud models may not work"
            fi

            for MODEL_NAME in "$MANAGER_MODEL" "$FORENSICATOR_MODEL" "$CRITIC_MODEL" "$CRITIC2_MODEL"; do
                info "Pulling ${MODEL_NAME}..."
                ollama pull "$MODEL_NAME" || { warn "Failed to pull ${MODEL_NAME}"; continue; }
            done

            ok "Cloud models pulled"
        else
            # ── Local: download from HuggingFace with SHA256 verification ──
            MODELS_DIR="${INSTALL_DIR}/models"
            GGUF_DIR="${INSTALL_DIR}/gguf"
            mkdir -p "$GGUF_DIR"

            # Parse manifest.toml to download and verify each model
            CURRENT_MODEL=""
            while IFS= read -r line; do
                # Track which [[models]] section we're in
                if [[ "$line" == "[[models]]" ]]; then
                    CURRENT_MODEL=""
                    continue
                fi

                # Parse key = value pairs
                if [[ "$line" =~ ^ollama_name ]]; then
                    CURRENT_MODEL=$(echo "$line" | sed 's/ollama_name *= *"\(.*\)"/\1/' | tr -d '"')
                    continue
                fi

                if [[ -n "$CURRENT_MODEL" ]]; then
                    # Check if this model is one we need
                    case "$CURRENT_MODEL" in
                        "$MANAGER_MODEL"|"$FORENSICATOR_MODEL"|"$CRITIC_MODEL"|"$CRITIC2_MODEL")
                            # Parse fields
                            if [[ "$line" =~ ^gguf_url ]]; then
                                GGUF_URL=$(echo "$line" | sed 's/gguf_url *= *"\(.*\)"/\1/' | tr -d '"')
                            elif [[ "$line" =~ ^gguf_sha256 ]]; then
                                EXPECTED_SHA256=$(echo "$line" | sed 's/gguf_sha256 *= *"\(.*\)"/\1/' | tr -d '"')
                            elif [[ "$line" =~ ^gguf_size ]]; then
                                EXPECTED_SIZE=$(echo "$line" | sed 's/gguf_size *= *\([0-9]*\)/\1/')
                            elif [[ "$line" =~ ^modelfile ]]; then
                                MODELFILE=$(echo "$line" | sed 's/modelfile *= *"\(.*\)"/\1/' | tr -d '"')
                            elif [[ "$line" =~ ^hf_file ]]; then
                                GGUF_FILE=$(echo "$line" | sed 's/hf_file *= *"\(.*\)"/\1/' | tr -d '"')
                            fi
                            ;;
                    esac
                fi
            done < "${MODELS_DIR}/manifest.toml"

            # Download and verify each local model
            for MODEL_NAME in "$MANAGER_MODEL" "$FORENSICATOR_MODEL" "$CRITIC_MODEL" "$CRITIC2_MODEL"; do
                # Re-parse just this model from manifest
                GGUF_URL=""
                EXPECTED_SHA256=""
                EXPECTED_SIZE=""
                MODELFILE=""
                GGUF_FILE=""
                IN_SECTION=false

                while IFS= read -r line; do
                    if [[ "$line" == "[[models]]" ]]; then
                        IN_SECTION=false
                        continue
                    fi
                    if [[ "$line" == *"ollama_name = \"${MODEL_NAME}\""* ]]; then
                        IN_SECTION=true
                        continue
                    fi
                    if [[ "$IN_SECTION" == true ]]; then
                        if [[ "$line" =~ ^gguf_url ]]; then
                            GGUF_URL=$(echo "$line" | sed 's/gguf_url *= *"\(.*\)"/\1/' | tr -d '"')
                        elif [[ "$line" =~ ^gguf_sha256 ]]; then
                            EXPECTED_SHA256=$(echo "$line" | sed 's/gguf_sha256 *= *"\(.*\)"/\1/' | tr -d '"')
                        elif [[ "$line" =~ ^gguf_size ]]; then
                            EXPECTED_SIZE=$(echo "$line" | sed 's/gguf_size *= *\([0-9]*\)/\1/')
                        elif [[ "$line" =~ ^modelfile ]]; then
                            MODELFILE=$(echo "$line" | sed 's/modelfile *= *"\(.*\)"/\1/' | tr -d '"')
                        elif [[ "$line" =~ ^hf_file ]]; then
                            GGUF_FILE=$(echo "$line" | sed 's/hf_file *= *"\(.*\)"/\1/' | tr -d '"')
                        fi
                    fi
                done < "${MODELS_DIR}/manifest.toml"

                if [[ -z "$GGUF_URL" || -z "$EXPECTED_SHA256" ]]; then
                    warn "No manifest entry for ${MODEL_NAME} — falling back to ollama pull"
                    ollama pull "$MODEL_NAME" || warn "Failed to pull ${MODEL_NAME}"
                    continue
                fi

                GGUF_PATH="${GGUF_DIR}/${GGUF_FILE}"

                # Download if not already present
                if [[ -f "$GGUF_PATH" ]]; then
                    info "GGUF already exists: ${GGUF_FILE}"
                else
                    info "Downloading ${GGUF_FILE} from HuggingFace (~$(( EXPECTED_SIZE / 1073741824 ))GB)..."
                    curl -L -o "$GGUF_PATH" "$GGUF_URL" || { warn "Failed to download ${GGUF_FILE}"; continue; }
                fi

                # Verify size
                ACTUAL_SIZE=$(stat -c%s "$GGUF_PATH" 2>/dev/null || stat -f%z "$GGUF_PATH" 2>/dev/null)
                if [[ -n "$EXPECTED_SIZE" && "$ACTUAL_SIZE" -ne "$EXPECTED_SIZE" ]]; then
                    warn "Size mismatch for ${GGUF_FILE}: expected ${EXPECTED_SIZE}, got ${ACTUAL_SIZE}"
                    warn "Deleting corrupted download..."
                    rm -f "$GGUF_PATH"
                    continue
                fi

                # Verify SHA256
                info "Verifying SHA256 for ${GGUF_FILE}..."
                ACTUAL_SHA256=$(sha256sum "$GGUF_PATH" | cut -d' ' -f1)
                if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
                    warn "SHA256 MISMATCH for ${GGUF_FILE}!"
                    warn "  Expected: ${EXPECTED_SHA256}"
                    warn "  Got:      ${ACTUAL_SHA256}"
                    warn "Deleting unverified download..."
                    rm -f "$GGUF_PATH"
                    continue
                fi
                ok "SHA256 verified: ${GGUF_FILE}"

                # Create Ollama model from Modelfile
                info "Creating Ollama model ${MODEL_NAME}..."
                # Modelfile uses relative path — run from gguf dir
                (cd "$GGUF_DIR" && ollama create "$MODEL_NAME" -f "${MODELS_DIR}/${MODELFILE}") || \
                    { warn "Failed to create ${MODEL_NAME}"; continue; }

                # Verify model identity
                if [[ -f "${MODELS_DIR}/verify_model.sh" ]]; then
                    bash "${MODELS_DIR}/verify_model.sh" "$MODEL_NAME" "${MODELS_DIR}/manifest.toml" || \
                        warn "Model ${MODEL_NAME} identity verification FAILED"
                fi

                ok "Model ${MODEL_NAME} ready (verified)"
            done
        fi
else
    info "Skipping Ollama model pulls (--skip-ollama)"
fi

# ── Start Services ────────────────────────────────────────────────────────────
info "Starting Geoff services..."

# Ensure log directory exists
mkdir -p "${INSTALL_DIR}/logs"

# Start web server (Flask on 8080)
nohup bash -c "cd ${INSTALL_DIR} && source venv/bin/activate && set -a && source .env && set +a && python3 src/geoff_integrated.py" > "${INSTALL_DIR}/logs/geoff.log" 2>&1 &
GEOFF_PID=$!
info "Geoff web server starting on port 8080 (PID: ${GEOFF_PID})"

# Start MCP server (on 9999)
nohup bash -c "cd ${INSTALL_DIR} && source venv/bin/activate && python3 src/geoff_mcp_server.py --host 127.0.0.1 --port 9999" > "${INSTALL_DIR}/logs/mcp.log" 2>&1 &
MCP_PID=$!
info "Geoff MCP server starting on port 9999 (PID: ${MCP_PID})"

# Wait a moment and check if processes are running
sleep 2
if kill -0 ${GEOFF_PID} 2>/dev/null; then
    ok "Geoff web server running"
else
    warn "Geoff web server may have failed to start (check logs/geoff.log)"
fi

if kill -0 ${MCP_PID} 2>/dev/null; then
    ok "Geoff MCP server running"
else
    warn "Geoff MCP server may have failed to start (check logs/mcp.log)"
fi

# ── External tool presence checks ────────────────────────────────────────────
# These tools are large/dependency-heavy; we don't install them, just warn if absent.
info "Checking for externally-managed tools (not installed here)..."
for _ext_tool in NetworkMiner networkminer; do
    if command -v "$_ext_tool" &>/dev/null; then
        ok "NetworkMiner found: $(command -v $_ext_tool)"
        break
    fi
done
if ! command -v NetworkMiner &>/dev/null && ! command -v networkminer &>/dev/null; then
    warn "NetworkMiner not found — install mono + NetworkMiner manually for network forensics (PB-005)"
fi
for _jtr_tool in john johnny; do
    if command -v "$_jtr_tool" &>/dev/null; then
        ok "$_jtr_tool found: $(command -v $_jtr_tool)"
    else
        warn "$_jtr_tool not found — install john/johnny manually for password cracking support"
    fi
done

# ── Wait for background REMnux install ──────────────────────────────────────
if [[ -n "$REMNUX_BG_PID" ]]; then
    info "Waiting for REMnux background install to finish (PID: ${REMNUX_BG_PID})..."
    # Temporarily disable exit-on-error for the wait loop
    set +e
    REMNUX_WAIT=0
    while kill -0 "$REMNUX_BG_PID" 2>/dev/null && [ $REMNUX_WAIT -lt 1800 ]; do
        sleep 5
        REMNUX_WAIT=$((REMNUX_WAIT + 5))
        # Print progress every 30 seconds
        if [ $((REMNUX_WAIT % 30)) -eq 0 ]; then
            info "  REMnux still running... (${REMNUX_WAIT}s elapsed)"
        fi
    done
    if kill -0 "$REMNUX_BG_PID" 2>/dev/null; then
        warn "REMnux install is still running after 30 minutes — continuing anyway"
    else
        wait "$REMNUX_BG_PID" 2>/dev/null
        REMNUX_EXIT=$?
        if [ $REMNUX_EXIT -eq 0 ]; then
            ok "REMnux install completed successfully"
        else
            warn "REMnux install exited with code $REMNUX_EXIT — some malware tools may be unavailable"
        fi
    fi
    set -e
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          GEOFF Installation Complete             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Profile:    ${YELLOW}${PROFILE}${NC}"
echo -e "${GREEN}║${NC} Directory:  ${INSTALL_DIR}${NC}"
echo -e "${GREEN}║${NC} Config:     ${INSTALL_DIR}/.env${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Services:                                       ${NC}"
echo -e "${GREEN}║${NC}   Web UI:   http://127.0.0.1:8080              ${NC}"
echo -e "${GREEN}║${NC}   MCP:      http://127.0.0.1:9999/mcp          ${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} To restart manually:                             ${NC}"
echo -e "${GREEN}║${NC}   cd ${INSTALL_DIR}                               ${NC}"
echo -e "${GREEN}║${NC}   source venv/bin/activate                      ${NC}"
echo -e "${GREEN}║${NC}   python3 src/geoff_integrated.py &             ${NC}"
echo -e "${GREEN}║${NC}   python3 src/geoff_mcp_server.py &             ${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} To switch profiles:                             ${NC}"
echo -e "${GREEN}║${NC}   Edit .env: GEOFF_PROFILE=cloud|local          ${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"