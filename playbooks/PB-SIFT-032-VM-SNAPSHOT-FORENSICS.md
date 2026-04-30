# PB-SIFT-032 — VM Snapshot Forensics

**Phase:** Collection / Analysis
**Auto-triggered when:** `.vmss`, `.vmsn`, `.vmem`, `.vhdx`, `.vmdk`, `.qcow2` snapshot files detected
**Specialist:** `vm`

## Objective

Analyze virtual machine snapshot files, suspended state files, and VM memory dumps to extract RAM contents, running processes, and disk artifacts without powering on the original VM. Detect malicious activity hidden inside VMs and anti-forensics using VMs as sandboxes.

## Steps

### Snapshot Detection & Inventory (`vm.detect_snapshots`)

- Enumerate all VM snapshot files: `.vmss` (saved state), `.vmsn` (snapshot), `.vmem` (VM memory)
- Parse VM configuration files (`.vmx`, `.xml`, `.ovf`) for snapshot metadata
- Identify parent-child snapshot chains (delta disks)
- Detect suspended VMs (`.vmss` present = live RAM captured)
- Map snapshot timestamps to incident window
- Flag snapshots created after incident detection (anti-forensics)

### VM Memory Extraction (`vm.extract_memory`)

- Extract RAM from `.vmem` files (VMware) or `.vmss` (saved state)
- Parse `.vmsn` files to reconstruct VM memory map
- Use Volatility3 with VMware address space plugins
- Extract processes, network connections, and loaded modules from VM RAM
- Cross-reference with host memory analysis for VM escape attempts
- Detect VM-aware malware that behaves differently inside VMs

### Disk Image Extraction (`vm.extract_disk`)

- Mount or parse VMDK/VHDX/QCOW2 files without full VM startup
- Handle multi-part VMDK files (descriptor + extent files)
- Parse differential/delta disks for snapshot-based disk states
- Extract files from VM filesystem using forensic mount tools
- Carve deleted files from VM disk images
- Compare snapshot disk states to baseline for anomaly detection

### VM Configuration Analysis (`vm.analyze_config`)

- Parse `.vmx` / `.xml` for VM settings, network adapters, shared folders
- Detect suspicious VM configurations:
  - Shared folders mapping host sensitive directories
  - Serial/port connections to host devices
  - Clipboard/file drag-and-drop enabled (data exfiltration)
  - Network adapter in bridged mode (lateral movement)
  - USB passthrough for hardware keyloggers
- Identify VM tools version (outdated = potential escape vulnerability)

### Anti-VM & Escape Detection (`vm.detect_escape`)

- Check host for VM escape artifacts (processes spawned by VM tools)
- Analyze VMware Tools / VirtualBox Guest Additions logs
- Detect suspicious host-VM file transfers via shared folders
- Look for VM escape exploit indicators (CVE-2017-4901, CVE-2021-21972, etc.)
- Check for nested virtualization (VM inside VM = sandbox evasion)

## Indicators of Interest

- VM snapshot created minutes before incident detection
- Suspicious VM running on host without documented purpose
- Shared folder mapping `/etc`, `C:\Windows`, or evidence directories
- VM memory contains malware that checks for VM before execution
- Clipboard sharing enabled with known-malicious VM
- Nested virtualization detected (malware analysis sandbox inside VM)
- VM disk contains same files as host but with different timestamps
- Snapshot chain with missing parent (delta disk orphaned)
- VM network adapter in bridged mode communicating with internal systems
- Host processes spawned by `vmtoolsd.exe` or `VBoxService.exe`

## Output

```json
{
  "vm_type": "VMware Workstation",
  "snapshot_count": 3,
  "snapshots": [
    {
      "name": "Clean State",
      "created": "2024-01-15T09:00:00Z",
      "vmem_size": 4294967296,
      "suspicious": false
    },
    {
      "name": "After Testing",
      "created": "2024-07-15T03:22:00Z",
      "vmem_size": 4294967296,
      "suspicious": true,
      "reason": "Created during incident window"
    }
  ],
  "memory_extracted": true,
  "processes_in_memory": 87,
  "suspicious_processes": 2,
  "disk_images": 2,
  "files_extracted": 1243,
  "shared_folders": [
    "C:\\Evidence",
    "\\tmp\\malware"
  ],
  "network_adapters": ["NAT", "Bridged"],
  "escape_indicators": [
    "Host process spawned by vmtoolsd.exe during incident window"
  ],
  "findings": []
}
```

## Tools Required

- `volatility3` with VMware address space plugins — VM memory analysis
- `vmware-mount` / `vmware-vdiskmanager` — VMDK mounting (if available)
- `qemu-img` — QCOW2/VMDK/VHDX conversion and inspection
- `guestmount` (libguestfs) — Mount VM disks without root
- `vshadowmount` — Windows shadow copy analysis from VHDX
- `strings` + `grep` — VM configuration parsing

## Notes

- VMware `.vmem` files are raw memory dumps — treat like physical RAM dumps
- VMDK descriptor files describe extent files — parse descriptor before accessing data
- Differential disks (snapshot deltas) require parent disk for full reconstruction
- VM escape is rare but critical — always check host for VM-spawned processes
- Suspended VMs capture live state — may contain decrypted data not on disk
- Nested virtualization can be used to bypass anti-VM malware checks
