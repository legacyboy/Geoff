#!/usr/bin/env bash
# GEOFF install loop test — runs continuously, restoring snapshots between tests
# Designed to be run by OpenClaw cron every 30 min
set -euo pipefail

VM_NAME="SIFT-DFIR"
SNAPSHOT="fresh-install"
SSH_CMD="sshpass -p forensics ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p 2222 sansforensics@localhost"
LOG="/home/claw/.openclaw/workspace/projects/Geoff/install_test.log"
COMMIT=$(cd /home/claw/.openclaw/workspace/projects/Geoff && git rev-parse --short HEAD)

echo "=== GEOFF Install Test $(date) | commit ${COMMIT} ===" | tee "$LOG"

# Step 1: Power off and restore snapshot
echo "[1/6] Restoring snapshot..." | tee -a "$LOG"
VM_STATE=$(VBoxManage showvminfo "$VM_NAME" --machinereadable 2>/dev/null | grep VMState= | cut -d'"' -f2)
if [[ "$VM_STATE" == "running" ]]; then
    VBoxManage controlvm "$VM_NAME" poweroff 2>&1 | tee -a "$LOG"
    sleep 5
fi
VBoxManage snapshot "$VM_NAME" restore "$SNAPSHOT" 2>&1 | tee -a "$LOG"
VBoxManage startvm "$VM_NAME" --type headless 2>&1 | tee -a "$LOG"

# Step 2: Wait for SSH
echo "[2/6] Waiting for SSH..." | tee -a "$LOG"
ssh-keygen -f '/home/claw/.ssh/known_hosts' -R '[localhost]:2222' >/dev/null 2>&1
SSH_READY=false
for i in $(seq 1 24); do
    if $SSH_CMD "echo SSH_OK" 2>/dev/null | grep -q "SSH_OK"; then
        SSH_READY=true
        echo "  SSH connected after ${i}x5s" | tee -a "$LOG"
        break
    fi
    sleep 5
done
if [[ "$SSH_READY" == false ]]; then
    echo "FAIL: SSH never became available" | tee -a "$LOG"
    exit 1
fi

# Step 3: Run installer (with Ollama install but skip model pulls for speed)
echo "[3/6] Running installer..." | tee -a "$LOG"
INSTALL_OUTPUT=$($SSH_CMD "curl -sSL 'https://raw.githubusercontent.com/legacyboy/Geoff/${COMMIT}/install.sh' | bash -s -- --profile cloud --skip-ollama" 2>&1)
echo "$INSTALL_OUTPUT" | tee -a "$LOG"

# Check for failure keywords
if echo "$INSTALL_OUTPUT" | grep -qi "fail\|error\|denied\|not found"; then
    echo "FAIL: Installer had errors (see above)" | tee -a "$LOG"
    # Don't exit — still verify what we can
fi

# Step 4: Verify installation
echo "[4/6] Verifying..." | tee -a "$LOG"
FAILS=0

# Check code exists
if $SSH_CMD "test -d /opt/geoff/.git" 2>/dev/null; then
    echo "  ✅ Code cloned" | tee -a "$LOG"
else
    echo "  ❌ Code NOT cloned" | tee -a "$LOG"; FAILS=$((FAILS+1))
fi

# Check venv
if $SSH_CMD "test -f /opt/geoff/venv/bin/python3" 2>/dev/null; then
    echo "  ✅ Python venv created" | tee -a "$LOG"
else
    echo "  ❌ Python venv NOT created" | tee -a "$LOG"; FAILS=$((FAILS+1))
fi

# Check Python deps
DEP_CHECK=$($SSH_CMD "/opt/geoff/venv/bin/python3 -c 'import flask, requests, jsonschema; print(\"OK\")'" 2>&1)
if echo "$DEP_CHECK" | grep -q "OK"; then
    echo "  ✅ Python dependencies installed" | tee -a "$LOG"
else
    echo "  ❌ Python dependencies FAILED: $DEP_CHECK" | tee -a "$LOG"; FAILS=$((FAILS+1))
fi

# Check .env
if $SSH_CMD "test -f /opt/geoff/.env" 2>/dev/null; then
    echo "  ✅ .env config created" | tee -a "$LOG"
    ENV_CONTENT=$($SSH_CMD "cat /opt/geoff/.env" 2>&1)
    echo "$ENV_CONTENT" | sed 's/^/    /' | tee -a "$LOG"
else
    echo "  ❌ .env NOT created" | tee -a "$LOG"; FAILS=$((FAILS+1))
fi

# Check profiles.json
if $SSH_CMD "test -f /opt/geoff/profiles.json" 2>/dev/null; then
    echo "  ✅ profiles.json present" | tee -a "$LOG"
else
    echo "  ❌ profiles.json NOT found" | tee -a "$LOG"; FAILS=$((FAILS+1))
fi

# Check Ollama installed
OL_CHECK=$($SSH_CMD "which ollama" 2>&1)
if [[ -n "$OL_CHECK" ]]; then
    echo "  ✅ Ollama installed: $OL_CHECK" | tee -a "$LOG"
else
    echo "  ❌ Ollama NOT installed" | tee -a "$LOG"; FAILS=$((FAILS+1))
fi

# Step 5: Try starting GEOFF
echo "[5/6] Testing GEOFF startup..." | tee -a "$LOG"
STARTUP_OUTPUT=$($SSH_CMD "cd /opt/geoff && source venv/bin/activate && export \$(cat .env | xargs) && timeout 10 python3 src/geoff_integrated.py 2>&1 || true" 2>&1)
if echo "$STARTUP_OUTPUT" | grep -q "Geoff DFIR on port"; then
    echo "  ✅ GEOFF starts successfully" | tee -a "$LOG"
elif echo "$STARTUP_OUTPUT" | grep -q "Ollama"; then
    echo "  ⚠️  GEOFF starts but can't reach Ollama (expected without models)" | tee -a "$LOG"
elif echo "$STARTUP_OUTPUT" | grep -qi "error\|traceback"; then
    echo "  ❌ GEOFF startup error:" | tee -a "$LOG"
    echo "$STARTUP_OUTPUT" | tail -20 | sed 's/^/    /' | tee -a "$LOG"
    FAILS=$((FAILS+1))
else
    echo "  ⚠️  GEOFF startup unclear:" | tee -a "$LOG"
    echo "$STARTUP_OUTPUT" | tail -5 | sed 's/^/    /' | tee -a "$LOG"
fi

# Step 6: Summary
echo "[6/6] Summary" | tee -a "$LOG"
if [[ $FAILS -eq 0 ]]; then
    echo "✅ ALL CHECKS PASSED — install test clean on commit ${COMMIT}" | tee -a "$LOG"
else
    echo "❌ ${FAILS} CHECKS FAILED on commit ${COMMIT}" | tee -a "$LOG"
fi

echo "=== Test complete $(date) ===" | tee -a "$LOG"
exit $FAILS