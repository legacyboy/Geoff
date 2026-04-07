#!/bin/bash
# Import SIFT VM and configure evidence mapping

VM_NAME="SIFT-Workstation"
OVA_PATH="$HOME/Downloads/sift-2026.03.24.ova"
EVIDENCE_PATH="/mnt/evidence"  # 1TB drive mount point

echo "=== SIFT VM Setup ==="

# Check if OVA exists
if [[ ! -f "$OVA_PATH" ]]; then
    echo "❌ OVA not found: $OVA_PATH"
    exit 1
fi

echo "✅ Found OVA: $(ls -lh $OVA_PATH | awk '{print $5}')"

# Remove existing VM if present
vboxmanage list vms | grep -q "$VM_NAME" && {
    echo "Removing existing SIFT VM..."
    vboxmanage controlvm "$VM_NAME" poweroff 2>/dev/null
    sleep 2
    vboxmanage unregistervm "$VM_NAME" --delete 2>/dev/null
}

# Import OVA
echo "Importing SIFT VM (this may take a few minutes)..."
vboxmanage import "$OVA_PATH" --vsys 0 --vmname "$VM_NAME" --cpus 4 --memory 8192

# Configure VM
echo "Configuring VM..."

# Add port forwards for SSH and UI
vboxmanage modifyvm "$VM_NAME" --natpf1 "ssh,tcp,,2222,,22"
vboxmanage modifyvm "$VM_NAME" --natpf1 "ui,tcp,,8080,,8080"

# Set up shared folder for evidence (1TB drive)
# First check if evidence path exists, if not create it
if [[ ! -d "$EVIDENCE_PATH" ]]; then
    echo "Creating evidence mount point..."
    echo "holidayhack" | sudo -S mkdir -p "$EVIDENCE_PATH"
fi

# Add shared folder (auto-mount)
vboxmanage sharedfolder add "$VM_NAME" --name "evidence" --hostpath "$EVIDENCE_PATH" --automount

echo ""
echo "=== SIFT VM Ready ==="
echo "VM: $VM_NAME"
echo "RAM: 8GB"
echo "CPUs: 4"
echo ""
echo "Port Forwards:"
echo "  - SSH: localhost:2222 → VM:22"
echo "  - UI: localhost:8080 → VM:8080"
echo ""
echo "Evidence Folder:"
echo "  Host: $EVIDENCE_PATH (1TB drive)"
echo "  VM: /media/sf_evidence (auto-mounted)"
echo ""
echo "SIFT Credentials:"
echo "  User: sansforensics"
echo "  Pass: forensics"
echo "  Root: sudo su -"
echo ""

# Start VM
echo "Starting SIFT VM..."
vboxmanage startvm "$VM_NAME" --type gui

echo "✅ SIFT VM is starting!"
echo ""
echo "Wait ~60 seconds for boot, then:"
echo "  SSH: ssh -p 2222 sansforensics@localhost"
