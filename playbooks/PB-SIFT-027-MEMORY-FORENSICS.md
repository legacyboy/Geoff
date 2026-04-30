# PB-SIFT-027 — Memory Forensics & Volatile Analysis

**Phase:** Collection / Analysis
**Auto-triggered when:** `.raw`, `.dmp`, `.lime`, `.mem`, `.vmem` files detected in evidence
**Specialist:** `memory`

## Objective

Analyze volatile memory dumps to recover running processes, network connections, loaded modules, memory-resident malware, registry hives in RAM, and credentials that may not exist on disk.

## Steps

### Process Listing (`volatility.pslist` / `volatility.linux_pslist` / `volatility.mac_pslist`)

- Enumerate all processes from the memory image using Volatility3 (or fallback to Volatility2 / Rekall)
- Extract PID, PPID, process name, start time, and command line arguments
- Identify processes with no mapped executable on disk (hollowed/injected)
- Flag processes with parent-child relationships that violate normal OS behavior
- Cross-reference process names against known malware families

### Network Connections (`volatility.netscan` / `volatility.linux_netstat`)

- Extract all active and recently-closed network connections from memory
- Include local/remote IP, port, state, owning PID, and process name
- Flag connections to known C2 IPs or suspicious ports (4444, 5555, 9999)
- Correlate connection timestamps with incident window

### Loaded DLLs & Kernel Modules (`volatility.dlllist` / `volatility.linux_lsmod` / `volatility.mac_modules`)

- Enumerate DLLs loaded by each process (Windows)
- Enumerate kernel modules (Linux `.ko` files)
- Enumerate kexts (macOS kernel extensions)
- Flag unsigned or unmapped DLLs/modules (injected code)
- Cross-reference module paths against known-good baselines

### Memory-Resident Malware (`volatility.malfind` / `volatility.linux_malfind`)

- Scan process memory for injected code segments (RX pages without mapped file)
- Identify executable pages in normally non-executable memory regions
- Dump suspicious memory regions to disk for further analysis
- Hash dumped segments and check against known malware signatures
- Flag processes with multiple injected code regions

### Registry Hives in Memory (`volatility.hivelist` / `volatility.registry`)

- Locate loaded registry hives in Windows memory
- Extract volatile registry keys that may differ from on-disk hives
- Focus on SAM, SECURITY, SYSTEM hives for credential artifacts
- Compare in-memory hive timestamps with disk versions for anti-forensics

### Credential Extraction (`volatility.lsadump` / `volatility.hashdump`)

- Extract cached credentials and password hashes from memory
- Dump LM/NTLM hashes from SAM hive in memory
- Extract Kerberos tickets (TGTs/TGSs) if present
- Flag plaintext credentials in memory (browser sessions, RDP, SSH agents)
- Note: Mimikatz-like extraction via Volatility3 `windows.lsadump.Lsadump`

## Indicators of Interest

- Processes with no disk executable (hollow process injection)
- Network connections to known APT C2 infrastructure
- Unsigned kernel modules or kexts loaded without Apple/MS signatures
- Injected code regions in browser or email client processes
- Kerberos TGTs from privileged accounts
- Cached credentials older than normal policy but still in memory
- Process hollowing indicators (legitimate process name, unusual memory map)
- Anti-virus processes with injected code (AV bypass)

## Output

```json
{
  "memory_image": "memdump.raw",
  "image_type": "Windows 10 x64",
  "volatility_profile": "Win10x64_19041",
  "processes": 187,
  "processes_suspicious": 3,
  "network_connections": 42,
  "connections_flagged": 2,
  "injected_segments": 7,
  "registry_hives_loaded": 12,
  "credentials_extracted": {
    "ntlm_hashes": 8,
    "kerberos_tgts": 1,
    "plaintext_passwords": 0
  },
  "suspicious_processes": [
    {
      "pid": 4821,
      "name": "svchost.exe",
      "ppid": 4,
      "injected_segments": 2,
      "network_connections": ["185.220.101.42:443"]
    }
  ],
  "findings": []
}
```

## Tools Required

- `volatility3` (Python 3) — primary memory analysis framework
- `volatility2` (fallback for older profiles)
- `rekall` — alternative memory forensic framework
- `yara` — memory-resident malware signature scanning
- `strings` — extracting strings from dumped memory regions

## Notes

- Memory analysis is time-consuming — runs after disk-based analysis unless memory-resident malware is suspected
- Volatility3 requires symbol tables for the exact OS build — maintain local symbol cache
- Linux memory dumps (`.lime`) require Volatility3 Linux plugin set
- macOS memory dumps require `lime` compiled for the target kernel version
- Always dump suspicious memory regions — they disappear when the system reboots
