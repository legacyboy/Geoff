#!/bin/bash
# Create Geoff VM in VirtualBox

VM_NAME="Geoff-Test"
ISO_PATH="$HOME/Downloads/ubuntu-24.04.4-desktop-amd64.iso"
DISK_PATH="$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi"

echo "=== Creating Geoff VM ==="
echo "VM Name: $VM_NAME"
echo "ISO: $ISO_PATH"
echo ""

# Check if ISO exists
if [[ ! -f "$ISO_PATH" ]]; then
    echo "❌ ISO not found: $ISO_PATH"
    exit 1
fi

# Delete existing VM if it exists
vboxmanage list vms | grep -q "$VM_NAME" && {
    echo "Removing existing VM..."
    vboxmanage controlvm "$VM_NAME" poweroff 2>/dev/null
    sleep 2
    vboxmanage unregistervm "$VM_NAME" --delete 2>/dev/null
}

# Create VM
echo "Creating VM..."
vboxmanage createvm --name "$VM_NAME" --ostype Ubuntu_64 --register

# Configure VM
echo "Configuring VM..."
vboxmanage modifyvm "$VM_NAME" \
    --memory 8192 \
    --cpus 4 \
    --vram 128 \
    --graphicscontroller vmsvga \
    --boot1 dvd \
    --boot2 disk \
    --nic1 nat \
    --natpf1 "geoff-ssh,tcp,,2222,,22" \
    --natpf1 "geoff-ui,tcp,,8080,,8080" \
    --natpf1 "geoff-gateway,tcp,,18789,,18789"

# Create virtual disk
echo "Creating disk..."
vboxmanage createmedium disk --filename "$DISK_PATH" --size 40960 --format VDI

# Attach disk and ISO
echo "Attaching storage..."
vboxmanage storagectl "$VM_NAME" --name "SATA Controller" --add sata --controller IntelAhci
vboxmanage storageattach "$VM_NAME" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$DISK_PATH"
vboxmanage storagectl "$VM_NAME" --name "IDE Controller" --add ide
vboxmanage storageattach "$VM_NAME" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "$ISO_PATH"

# Start VM
echo ""
echo "=== Geoff VM Created ==="
echo ""
echo "VM: $VM_NAME"
echo "RAM: 8GB"
echo "CPUs: 4"
echo "Disk: 40GB"
echo ""
echo "Port Forwards:"
echo "  - SSH: localhost:2222 → VM:22"
echo "  - Geoff UI: localhost:8080 → VM:8080"
echo "  - Gateway: localhost:18789 → VM:18789"
echo ""
echo "To start: vboxmanage startvm \"$VM_NAME\" --type gui"
echo ""

# Auto-start
echo "Starting VM now..."
vboxmanage startvm "$VM_NAME" --type gui
