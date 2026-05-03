# PB-SIFT-027 — Memory Forensics & Volatile Analysis

**Phase:** Collection / Analysis
**Auto-triggered when:** `.raw`, `.dmp`, `.lime`, `.mem`, `.vmem` files detected in evidence
**Specialist:** `memory`

## Objective

Analyze volatile memory dumps to recover running processes, network connections, loaded modules, memory-resident malware, registry hives in RAM, and credentials that may not exist on disk.

## Auto-Detection

The `memory` specialist automatically detects the OS version and selects the correct Volatility framework:

| OS Detected | Volatility Version | Plugin Style |
|---|---|---|
| Windows 10/11, Server 2016+ | **Volatility3** | `windows.pslist.PsList` |
| Windows XP, Vista, 7, 8, 8.1 | **Volatility3** | `windows.pslist.PsList` |
| Windows 2000, Server 2003 | **Volatility2** | `pslist --profile=...` |
| Linux | **Volatility3** | `linux.pslist.PsList` |

The specialist runs `windows.info` (Vol3) first. If parsing fails or the kernel is legacy, it falls back to `imageinfo` (Vol2) and applies the correct `--profile`. You don't need to specify the tool — just call the method.

## Steps

### Process Listing (`memory.extract_processes`)

- Enumerate all processes from the memory image (auto-detects Vol2/Vol3)
- Extract PID, PPID, process name, start time, and command line arguments
- Identify processes with no mapped executable on disk (hollowed/injected)
- Flag processes with parent-child relationships that violate normal OS behavior
- Cross-reference process names against known malware families

### Network Connections (`memory.extract_network`)

- Extract all active and recently-closed network connections from memory
- Include local/remote IP, port, state, owning PID, and process name
- Flag connections to known C2 IPs or suspicious ports (4444, 5555, 9999)
- Correlate connection timestamps with incident window
- **Auto:** Vol3 uses `netscan`; Vol2 uses `netscan` (Win7+) or `connections` (XP/2003)

### Memory-Resident Malware (`memory.find_injected_code`)

- Scan process memory for injected code segments (RX pages without mapped file)
- Identify executable pages in normally non-executable memory regions
- Dump suspicious memory regions to disk for further analysis
- Hash dumped segments and check against known malware signatures
- Flag processes with multiple injected code regions
- **Tool:** `malfind` (both Vol2 and Vol3)

### Registry Hives in Memory (`memory.extract_registry`)

- Locate loaded registry hives in Windows memory
- Extract volatile registry keys that may differ from on-disk hives
- Focus on SAM, SECURITY, SYSTEM hives for credential artifacts
- Compare in-memory hive timestamps with disk versions for anti-forensics
- **Tool:** `hivelist` (Vol2) / `windows.registry.hivelist.HiveList` (Vol3)

### Credential Extraction (`memory.extract_credentials`)

- Extract cached credentials and password hashes from memory
- Dump LM/NTLM hashes from SAM hive in memory
- Extract Kerberos tickets (TGTs/TGSs) if present
- Flag plaintext credentials in memory (browser sessions, RDP, SSH agents)
- **Auto:** Vol3 uses `windows.lsadump.Lsadump`; Vol2 uses `hashdump`

## Example Playbook Invocation

```python
from sift_specialists_extended import MEMORY_Specialist

m = MEMORY_Specialist()

# All methods auto-detect OS and choose correct Volatility version
processes = m.extract_processes('memory.raw')
network = m.extract_network('memory.raw')
malware = m.find_injected_code('memory.raw')
registry = m.extract_registry('memory.raw')
creds = m.extract_credentials('memory.raw')
```

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
  "volatility_version": "vol3",
  "os_detected": "winxp",
  "processes": 44,
  "processes_suspicious": 0,
  "network_connections": 12,
  "connections_flagged": 0,
  "injected_segments": 0,
  "registry_hives_loaded": 5,
  "credentials_extracted": {
    "ntlm_hashes": 0,
    "kerberos_tgts": 0,
    "plaintext_passwords": 0
  },
  "findings": []
}
```

## Tools Required

- `volatility3` (Python 3) — primary memory analysis framework
- `volatility2` (Python 2) — legacy OS support (Win2K, Server 2003, profiles without ISF symbols)
- `rekall` — alternative memory forensic framework
- `yara` — memory-resident malware signature scanning
- strings extraction (specialist) — extracting strings from dumped memory regions

## Notes

- Memory analysis is time-consuming — runs after disk-based analysis unless memory-resident malware is suspected
- Volatility3 requires symbol tables for the exact OS build — maintain local symbol cache
- Linux memory dumps (`.lime`) require Volatility3 Linux plugin set
- macOS memory dumps require `lime` compiled for the target kernel version
- Always dump suspicious memory regions — they disappear when the system reboots
- **The specialist handles tool selection automatically** — don't hardcode Vol2 or Vol3 in playbooks
