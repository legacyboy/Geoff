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
SKIP_DEPS=false

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
        --skip-deps)   SKIP_DEPS=true; shift;;
        -h|--help)
            head -14 "$0" | tail -10 | sed 's/^# //'
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
            sleuthkit ssdeep hashdeep exiftool plaso-tools \
            regripper 2>/dev/null || true
        # REMnux tools (install if on REMnux or SIFT with REMnux repo)
        sudo apt-get install -y -qq die peframe upx clamav radare2 floss 2>/dev/null || true
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
        # Install REMnux distro for malware analysis tools
        if ! command -v remnux &>/dev/null; then
            info "Installing REMnux distro (addon mode)..."
            curl -O https://REMnux.org/remnux 2>/dev/null && \
                chmod +x remnux && sudo mv remnux /usr/local/bin/ && \
                sudo remnux install --mode=addon 2>/dev/null || \
                warn "REMnux installation failed — some malware analysis tools may be unavailable"
        else
            info "REMnux already installed, updating..."
            sudo remnux update 2>/dev/null || true
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
    ZIMMERMAN_DIR="${INSTALL_DIR}/zimmerman_tools"
    sudo mkdir -p "$ZIMMERMAN_DIR"
    if ! command -v dotnet >/dev/null 2>&1; then
        info "Installing .NET 9 runtime for Zimmerman tools..."
        curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 9.0 --runtime-only 2>/dev/null || \
            sudo apt-get install -y -qq dotnet-runtime-9.0 2>/dev/null || \
            warn "dotnet install failed — Zimmerman tools will be unavailable"
        # Add dotnet to PATH if installed via script
        export PATH="$HOME/.dotnet:$PATH" 2>/dev/null || true
    fi
    if command -v dotnet >/dev/null 2>&1 || [[ -f "$HOME/.dotnet/dotnet" ]]; then
        for tool in EvtxECmd MFTECmd bstrings ShellBagsExplorer AmcacheParser SrumECmd; do
            if [[ ! -f "${ZIMMERMAN_DIR}/${tool}.dll" ]]; then
                info "  Downloading ${tool}..."
                # Download from Zimmerman's distribution (net9 builds)
                curl -sL "https://download.ericzimmermanstools.com/net9/${tool}.zip" -o "/tmp/${tool}.zip" 2>/dev/null && \
                    unzip -q -o "/tmp/${tool}.zip" -d "$ZIMMERMAN_DIR" 2>/dev/null && \
                    # Flatten subdirectories (some zips extract into subdirs)
                    find "$ZIMMERMAN_DIR" -mindepth 2 -type f -exec mv -n {} "$ZIMMERMAN_DIR/" \; 2>/dev/null && \
                    find "$ZIMMERMAN_DIR" -mindepth 1 -maxdepth 1 -type d -empty -delete 2>/dev/null && \
                    rm -f "/tmp/${tool}.zip" || \
                    warn "Failed to download ${tool}"
            else
                info "  ${tool} already present"
            fi
        done
        ok "Zimmerman tools ready"
    else
        warn "dotnet not available — Zimmerman tools skipped"
    fi

    ok "System dependencies installed"
fi

# ── Clone repo ──────────────────────────────────────────────────────────────
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Updating existing GEOFF installation..."
    cd "$INSTALL_DIR"
    git pull origin main || warn "Git pull failed — continuing with existing code"
else
    info "Cloning GEOFF repository..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(whoami):$(id -gn)" "$INSTALL_DIR"
    git clone "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi
ok "Code ready at ${INSTALL_DIR}"

# ── Create evidence directories ────────────────────────────────────────────
info "Creating evidence storage directories..."
sudo mkdir -p /home/sansforensics/evidence-storage/evidence
sudo mkdir -p /home/sansforensics/evidence-storage/cases
sudo chown -R sansforensics:sansforensics /home/sansforensics/evidence-storage 2>/dev/null || \
    sudo chown -R "$(whoami):$(id -gn)" /home/sansforensics/evidence-storage 2>/dev/null || true
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
pip install --quiet -r requirements.txt 2>/dev/null || pip install --quiet flask requests jsonschema
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
if ! command -v ollama >/dev/null 2>&1; then
    info "Ollama not found — installing..."
    curl -fsSL https://ollama.com/install.sh | sh || fail "Ollama install failed. Install manually: https://ollama.com"
    ok "Ollama installed"
fi

# ── Ensure Ollama is running ──────────────────────────────────────────────
if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    info "Starting Ollama service..."
    ollama serve &>/dev/null &
    OLLAMA_PID=$!
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
    ok "Ollama is running (PID ${OLLAMA_PID})"
fi

# ── Pull Ollama models ────────────────────────────────────────────────────
if [[ "$SKIP_OLLAMA" == false ]]; then
    info "Setting up models for ${PROFILE} profile..."

        # Read model names from profiles.json
        if [[ -f "${INSTALL_DIR}/profiles.json" ]]; then
            MANAGER_MODEL=$(jq -r ".${PROFILE}.manager" "${INSTALL_DIR}/profiles.json")
            FORENSICATOR_MODEL=$(jq -r ".${PROFILE}.forensicator" "${INSTALL_DIR}/profiles.json")
            CRITIC_MODEL=$(jq -r ".${PROFILE}.critic" "${INSTALL_DIR}/profiles.json")
        else
            # Fallback if profiles.json missing
            if [[ "$PROFILE" == "cloud" ]]; then
                MANAGER_MODEL="deepseek-v3.2:cloud"
                FORENSICATOR_MODEL="qwen3-coder-next:cloud"
                CRITIC_MODEL="qwen3.5:cloud"
            else
                MANAGER_MODEL="deepseek-r1:32b"
                FORENSICATOR_MODEL="qwen2.5-coder:14b"
                CRITIC_MODEL="qwen2.5:14b"
            fi
        fi

        info "  Manager:      ${MANAGER_MODEL}"
        info "  Forensicator: ${FORENSICATOR_MODEL}"
        info "  Critic:       ${CRITIC_MODEL}"

        if [[ "$PROFILE" == "cloud" ]]; then
            # ── Cloud: pull from ollama.com registry ──
            [[ -n "$OLLAMA_KEY" ]] && export OLLAMA_API_KEY="$OLLAMA_KEY"

            if [[ "$OLLAMA_SIGNIN" == true ]]; then
                info "Running 'ollama signin' (interactive) — enter your Ollama credentials:"
                ollama signin || warn "ollama signin failed — cloud models may not work"
            fi

            for MODEL_NAME in "$MANAGER_MODEL" "$FORENSICATOR_MODEL" "$CRITIC_MODEL"; do
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
                        "$MANAGER_MODEL"|"$FORENSICATOR_MODEL"|"$CRITIC_MODEL")
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
            for MODEL_NAME in "$MANAGER_MODEL" "$FORENSICATOR_MODEL" "$CRITIC_MODEL"; do
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

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          GEOFF Installation Complete             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Profile:    ${YELLOW}${PROFILE}${NC}"
echo -e "${GREEN}║${NC} Directory:  ${INSTALL_DIR}${NC}"
echo -e "${GREEN}║${NC} Config:     ${INSTALL_DIR}/.env${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} To start:                                       ${NC}"
echo -e "${GREEN}║${NC}   cd ${INSTALL_DIR}                               ${NC}"
echo -e "${GREEN}║${NC}   source venv/bin/activate                      ${NC}"
echo -e "${GREEN}║${NC}   set -a && source .env && set +a              ${NC}"
echo -e "${GREEN}║${NC}   python3 src/geoff_integrated.py                ${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} To switch profiles:                             ${NC}"
echo -e "${GREEN}║${NC}   Edit .env: GEOFF_PROFILE=cloud|local          ${NC}"
echo -e "${GREEN}║${NC}   Or: GEOFF_PROFILE=local python3 src/geoff_integrated.py${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"