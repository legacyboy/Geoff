#!/usr/bin/env bash
# GEOFF install test script - runs on host, tests on SIFT VM
set -euo pipefail

SSH="sshpass -p forensics ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p 2222 sansforensics@localhost"
VM_NAME="SIFT-DFIR"
LOG="/home/claw/.openclaw/workspace/projects/Geoff/install_test.log"

echo "=== GEOFF Install Test $(date) ===" | tee "$LOG"

# Check if VM is running
VM_STATE=$(VBoxManage showvminfo "$VM_NAME" --machinereadable 2>/dev/null | grep VMState= | cut -d'"' -f2)
if [[ "$VM_STATE" != "running" ]]; then
    echo "VM not running, starting..." | tee -a "$LOG"
    VBoxManage startvm "$VM_NAME" --type headless 2>&1 | tee -a "$LOG"
    echo "Waiting for VM to boot..." | tee -a "$LOG"
    sleep 30
fi

# Wait for SSH
echo "Waiting for SSH..." | tee -a "$LOG"
for i in $(seq 1 20); do
    if $SSH "echo SSH_OK" 2>/dev/null | grep -q "SSH_OK"; then
        echo "SSH connected" | tee -a "$LOG"
        break
    fi
    sleep 5
done

# Run the installer on the VM
echo "Running GEOFF installer on VM..." | tee -a "$LOG"
$SSH "curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --profile cloud" 2>&1 | tee -a "$LOG"

# Check results
echo "" | tee -a "$LOG"
echo "=== Verification ===" | tee -a "$LOG"
$SSH "cd /opt/geoff && source venv/bin/activate && python3 -c 'import flask, requests, jsonschema; print(\"Python deps: OK\")'" 2>&1 | tee -a "$LOG"
$SSH "test -f /opt/geoff/.env && echo 'Config: OK' || echo 'Config: MISSING'" 2>&1 | tee -a "$LOG"
$SSH "test -f /opt/geoff/profiles.json && echo 'Profiles: OK' || echo 'Profiles: MISSING'" 2>&1 | tee -a "$LOG"
$SSH "which ollama && echo 'Ollama: OK' || echo 'Ollama: MISSING'" 2>&1 | tee -a "$LOG"
$SSH "curl -s http://localhost:11434/api/tags >/dev/null 2>&1 && echo 'Ollama running: OK' || echo 'Ollama running: FAILED'" 2>&1 | tee -a "$LOG"

echo "=== Test complete $(date) ===" | tee -a "$LOG"
