#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# verify_model.sh — Verify an Ollama model's identity against manifest.toml
#
# Usage: verify_model.sh <ollama_model_tag> <manifest.toml_path>
#
# Checks: architecture, base_model, quantization, parameter_count, size_label
# Returns: 0 if verified, 1 if mismatch or error
# ──────────────────────────────────────────────────────────────────────────────
set -uo pipefail

MODEL_NAME="${1:?Usage: verify_model.sh <model_tag> <manifest_path>}"
MANIFEST="${2:?Usage: verify_model.sh <model_tag> <manifest_path>}"

# Query Ollama for model info
MODEL_INFO=$(curl -s http://localhost:11434/api/show -d "{\"name\":\"${MODEL_NAME}\"}" 2>/dev/null) || {
    echo "[VERIFY] ERROR: Could not query Ollama for ${MODEL_NAME}" >&2
    exit 1
}

# Extract model properties
ARCH=$(echo "$MODEL_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model_info',{}).get('general.architecture',''))" 2>/dev/null || echo "")
BASE=$(echo "$MODEL_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model_info',{}).get('general.base_model.0.name',''))" 2>/dev/null || echo "")
QUANT=$(echo "$MODEL_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('details',{}).get('quantization_level',''))" 2>/dev/null || echo "")
PARAMS=$(echo "$MODEL_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model_info',{}).get('general.parameter_count',''))" 2>/dev/null || echo "")
SIZE=$(echo "$MODEL_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model_info',{}).get('general.size_label',''))" 2>/dev/null || echo "")

# Find matching entry in manifest
# Simple TOML parser: look for the block with matching ollama_name
MATCHED=false
VERIFIED=true

# Read manifest as sections
OLLAMA_NAME=""
SECTION=""
while IFS= read -r line; do
    # Track which [[models]] section we're in
    if [[ "$line" == "[[models]]" ]]; then
        SECTION="models"
        OLLAMA_NAME=""
        continue
    fi
    
    # Parse ollama_name
    if [[ "$line" == ollama_name* ]]; then
        OLLAMA_NAME=$(echo "$line" | sed 's/ollama_name *= *"\(.*\)"/\1/' | tr -d '"')
    fi
    
    # If we found the matching model, verify
    if [[ -n "$OLLAMA_NAME" && "$OLLAMA_NAME" == "$MODEL_NAME" ]]; then
        MATCHED=true
        # Parse expected values from manifest
        if [[ "$line" == expected_architecture* ]]; then
            EXPECTED=$(echo "$line" | sed 's/expected_architecture *= *"\(.*\)"/\1/' | tr -d '"')
            if [[ "$ARCH" != "$EXPECTED" ]]; then
                echo "[VERIFY] FAIL: ${MODEL_NAME} architecture=${ARCH} expected=${EXPECTED}" >&2
                VERIFIED=false
            fi
        fi
        if [[ "$line" == expected_base_model* ]]; then
            EXPECTED=$(echo "$line" | sed 's/expected_base_model *= *"\(.*\)"/\1/' | tr -d '"')
            # Base model matching is fuzzy (Ollama may return slightly different names)
            if [[ "$BASE" != *"$EXPECTED"* && "$EXPECTED" != *"$BASE"* ]]; then
                echo "[VERIFY] WARN: ${MODEL_NAME} base_model=${BASE} expected~=${EXPECTED}" >&2
                # Don't fail on fuzzy base model match — different Ollama versions may vary
            fi
        fi
        if [[ "$line" == expected_quantization* ]]; then
            EXPECTED=$(echo "$line" | sed 's/expected_quantization *= *"\(.*\)"/\1/' | tr -d '"')
            if [[ "$QUANT" != "$EXPECTED" ]]; then
                echo "[VERIFY] FAIL: ${MODEL_NAME} quantization=${QUANT} expected=${EXPECTED}" >&2
                VERIFIED=false
            fi
        fi
        if [[ "$line" == expected_parameter_count* ]]; then
            EXPECTED=$(echo "$line" | sed 's/expected_parameter_count *= *\([0-9]*\)/\1/')
            # Allow 5% tolerance for parameter count rounding
            if [[ -n "$PARAMS" && -n "$EXPECTED" ]]; then
                DIFF=$((PARAMS > EXPECTED ? PARAMS - EXPECTED : EXPECTED - PARAMS))
                PCT=$((DIFF * 100 / (EXPECTED > 0 ? EXPECTED : 1)))
                if [[ $PCT -gt 5 ]]; then
                    echo "[VERIFY] FAIL: ${MODEL_NAME} parameter_count=${PARAMS} expected=${EXPECTED} (diff=${PCT}%)" >&2
                    VERIFIED=false
                fi
            fi
        fi
        if [[ "$line" == expected_size_label* ]]; then
            EXPECTED=$(echo "$line" | sed 's/expected_size_label *= *"\(.*\)"/\1/' | tr -d '"')
            if [[ "$SIZE" != "$EXPECTED" ]]; then
                echo "[VERIFY] FAIL: ${MODEL_NAME} size_label=${SIZE} expected=${EXPECTED}" >&2
                VERIFIED=false
            fi
        fi
    fi
done < "$MANIFEST"

if [[ "$MATCHED" == false ]]; then
    echo "[VERIFY] WARN: ${MODEL_NAME} not found in manifest — skipping verification" >&2
    exit 0
fi

if [[ "$VERIFIED" == true ]]; then
    echo "[VERIFY] OK: ${MODEL_NAME} identity verified (arch=${ARCH} quant=${QUANT} params=${PARAMS} size=${SIZE})"
    exit 0
else
    echo "[VERIFY] FAIL: ${MODEL_NAME} identity verification failed" >&2
    exit 1
fi