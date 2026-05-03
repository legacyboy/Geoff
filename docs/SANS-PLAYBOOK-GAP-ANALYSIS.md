# SANS / Industry Practice vs Geoff Playbook & Installer Gap Analysis

**Date:** 2026-05-03
**Branch:** claude/research-san-playbook-gaps-aUjO5
**Scope:** All 33 playbooks, install.sh, TOOLS.md, SIFT Workstation default toolset

---

## Executive Summary

Geoff has strong SANS FOR500/FOR508 alignment (~85% coverage per the existing matrix), but has **four categories of gaps**:

1. **Critical content mismatches** — three playbooks have the wrong content for their label
2. **Installer tool gaps** — tools referenced by playbooks that the installer never installs
3. **Technique-without-tool gaps** — playbook phases that describe analysis but cite no specific command
4. **Missing playbook domains** — entire investigation types absent from the library

---

## Part 1 — Critical Playbook Content Mismatches

These are the most urgent fixes. The PLAYBOOK_INDEX promises one thing; the file delivers another.

| Playbook | Indexed As | Actual Content | Impact |
|---|---|---|---|
| **PB-004** | Privilege Escalation | Network device forensics (router/switch config, ARP, VLAN, firmware) | Geoff will run "privilege escalation" analysis and produce network device output — wrong for Windows IR cases |
| **PB-011** | Web Shell Indicators | Insider threat (data hoarding, USB, personal cloud sync, departure patterns) | Geoff cannot properly analyze web shell compromise; no IIS/Apache log correlation, no .aspx/.php drop detection |
| **PB-013** | Insider Threat | Cloud & SaaS artifacts (Teams token cache, OneDrive sync, rclone, AzCopy) | Cloud content duplicates PB-030; true insider threat behavioral analysis is entirely absent |

### What each mislabeled playbook SHOULD contain:

**PB-004 — Real Privilege Escalation content needed:**
- Token impersonation / SeDebugPrivilege detection (`vol windows.privs`)
- UAC bypass registry keys (`HKCU\Software\Classes\ms-settings\shell\open\command`)
- Scheduled task privilege abuse (HIGH integrity tasks run by low privilege user)
- Service binary path hijacking (unquoted paths, writable directories)
- DLL hijacking (writeable DLL search order locations)
- Linux: SUID/SGID bit abuse (`find / -perm -4000`), sudo misconfig, cron privesc
- Token impersonation artifacts in memory (`vol windows.getsids`)
- Exploit artifacts (CVE pattern matching in executed binary names)

**PB-011 — Real Web Shell content needed:**
- Web server log analysis (IIS `u_ex*.log`, Apache `access.log`): anomalous POSTs to static files
- Web directory filesystem scan: newly created `.asp`, `.aspx`, `.php`, `.jsp`, `.cfm` files
- File creation timestamps vs. web server install date
- Web shell signature strings (`eval(base64_decode`, `system($_GET`, `cmd.exe /c`)
- Prefetch for `cmd.exe`, `powershell.exe` spawned by `w3wp.exe` or `httpd.exe`
- Parent-child process chains: `w3wp.exe → cmd.exe → whoami`
- IIS application pool identity anomalies
- `AppCmd.exe` usage (IIS management abuse)

**PB-013 — Real Insider Threat behavioral content needed (non-cloud):**
- Print spooler job history (`%SystemRoot%\System32\spool\PRINTERS`)
- SearchIndex (`Windows.edb`) — documents indexed and accessed
- UserAssist MRU timeline
- Windows Search history (`%APPDATA%\Microsoft\Search`)
- Clipboard manager artifacts
- Email forwarding rules (Outlook profile and OAB changes)
- Behavioral baselining: access outside normal hours, volume anomalies
- DLP event correlation (if endpoint DLP logs present)
- HR event correlation framework (structured gap between resignation and access spike)

---

## Part 2 — Installer Tool Gaps

### 2A — Tools Referenced by Playbooks, Not Installed

These tools are called by name in playbook phases but `install.sh` never installs them.

#### apt-installable (add to existing `apt-get install` block)

| Tool | Package | Playbook(s) | Gap Description |
|---|---|---|---|
| `foremost` | `foremost` | PB-026 | File carving — playbook cites it explicitly but it's not installed |
| `scalpel` | `scalpel` | PB-026 | File carving — playbook cites it explicitly |
| `tcpflow` | `tcpflow` | PB-018 | Network stream reconstruction; REMnux SOP cites it |
| `zeek` | `zeek` | PB-019, TOOLS.md | TOOLS.md lists it as available; installer never installs it |
| `bdeinfo` / `bdemount` | `libbde-utils` | PB-029 | BitLocker unlock/mount for encrypted container playbook |
| `readpst` | `libpst-utils` | PB-023 | PST/OST → mbox conversion; installer lacks this despite SIFT having it |
| `guestmount` | `libguestfs-tools` | PB-032 | VM disk mounting for snapshot forensics |
| `qemu-img` | `qemu-utils` | PB-032 | VMDK/VHD/QCOW2 conversion for VM snapshot playbook |
| `bulk_extractor` | `bulk-extractor` | General | Deep pattern extraction from raw disk images; SIFT default, not installed |
| `dc3dd` | `dc3dd` | Chain of custody | Forensic imaging tool; SIFT default, not installed by GEOFF |
| `ewfacquire` | `ewf-tools` | Evidence acquisition | Already in installer apt block — verify it's present |
| `apfs-fuse` | `apfs-fuse` (PPA) | PB-024, PB-029 | APFS volume mounting; macOS + encrypted container playbooks call it |
| `cryptsetup` | `cryptsetup` | PB-029 | LUKS analysis (`luksDump`) — may already be on system, verify |

#### pip-installable (add to existing pip install block)

| Package | Playbook(s) | Gap Description |
|---|---|---|
| `plyvel` | PB-030, PB-031 | LevelDB parsing — cloud sync (Teams, Slack, Chrome) uses LevelDB databases |
| `pyinstxtractor` | PB-009 | PyInstaller extractor; ransomware packed with PyInstaller needs this |
| `uncompyle6` | PB-009 | Python bytecode decompiler for ransomware analysis |
| `pefile` | PB-008, PB-017, PB-018 | PE header analysis — used in malware hunting; `peframe` depends on it |
| `python-magic` | PB-008, PB-018 | File type detection via libmagic bindings |
| `lief` | PB-017, PB-018 | Binary analysis (PE/ELF/Mach-O); static analysis SOP benefits from it |
| `construct` | PB-027, PB-032 | Binary format parsing for memory/VM structures |
| `pycdc` | PB-009 | Alternative Python decompiler (decompyle3 compatible) |

#### GitHub release / custom install

| Tool | Install Method | Playbook(s) | Gap Description |
|---|---|---|---|
| **iLEAPP** | `pip install ileapp` or GitHub | PB-021 | iOS artifact extraction; playbook calls `run_ileapp()` — never installed |
| **ALEAPP** | `pip install aleapp` or GitHub | PB-021 | Android artifact extraction; playbook calls `run_aleapp()` — never installed |
| **dive** | GitHub release binary | PB-033 | Docker layer explorer; container forensics playbook cites it |
| **apfs-fuse** | PPA / build from source | PB-024, PB-029 | APFS FUSE driver for mounting macOS volumes on Linux |
| **pycdc** | pip / GitHub | PB-009 | Python decompiler for ransomware analysis |

#### Zimmerman Tools — Missing from Installer List

The installer downloads 9 Zimmerman tools. These are also referenced by playbooks but absent:

| Tool | Playbook(s) | Gap Description |
|---|---|---|
| **WxTCmd** | PB-028 | Windows 10 Timeline (`ActivitiesCache.db`) parser — modern artifact, FOR500 coverage |
| **RecentFileCacheParser** | PB-028 | `RecentFileCache.bcf` parsing — execution evidence on Win7/2008 |
| **RBCmd** | PB-012, PB-026 | Recycle Bin (`$I` / `$R` files) parser — anti-forensics + file carving |
| **MFTECmd** | PB-020 | Already in installer ✅ (verify download URL works) |
| **SQLECmd** | PB-022, PB-030, PB-031 | SQLite Evidence Commander — batch SQL across browser, cloud, collab databases |

### 2B — Tools on SIFT by Default, Not Verified by Installer

SIFT ships these out of the box. The installer doesn't check or verify them, so on a fresh non-SIFT Ubuntu they'll be absent.

| Tool | SIFT Default | Installer Checks It? | Risk |
|---|---|---|---|
| `photorec` / `testdisk` | ✅ | ❌ | PB-001, PB-008, PB-026 call `photorec.recover_files()` |
| `ssdeep` | ✅ | ✅ (apt) | Low risk |
| `hashdeep` | ✅ | ✅ (apt) | Low risk |
| `regripper` | ✅ | ✅ (apt) | Low risk |
| `NetworkMiner` | ✅ | ❌ | PB-019 network analysis; passive packet reassembly |
| `john` (John the Ripper) | ✅ | ❌ | PB-005 credential recovery |
| `nmap` | ✅ | ❌ | PB-006, PB-019 network mapping |
| `Autopsy` | ✅ (optional) | ❌ | GUI only — acceptable gap |
| `ltrace` / `strace` | ✅ | ❌ | Dynamic analysis support; PB-018 dynamic analysis phase |

---

## Part 3 — Technique-Without-Tool Gaps

These playbook phases describe a forensic technique but give no specific command. An investigator (or LLM) has to know the answer already. These are **documentation gaps** that reduce playbook reliability.

### High Priority (Core FOR500/FOR508 techniques)

| Playbook | Phase | Missing Technique/Tool |
|---|---|---|
| PB-002, PB-010 | PowerShell forensics | Script Block Log multi-block reassembly (EID 4104 has `ScriptBlockId` and `MessageNumber` — no tool for stitching split blocks) |
| PB-003, PB-010 | WMI persistence | `OBJECTS.DATA` / `INDEX.BTR` parsing — no tool specified. Should be `python-cim` (FireEye) or `strings + grep` workflow |
| PB-002, PB-003 | Scheduled tasks | `.xml` and `.job` file parsing — `schtasks /query /xml` output parsing, no parser tool named |
| PB-005 | Kerberoasting / ticket theft | No Kerberos ticket analysis tool named — `kerberoast.py`, `GetSPNs.py` patterns in memory not covered |
| PB-005 | NTDS.dit extraction | VSS + `ntdsutil` snapshot → `secretsdump.py` evidence chain not described as artifacts to look for |
| PB-010 | Obfuscation detection | No tool for encoded command decoding (should be `cyberchef-cli`, `base64 -d`, or `deobfuscate-ps` pattern matching) |
| PB-012 | Timestomping detection | `$STANDARD_INFORMATION` vs `$FILE_NAME` MACB comparison — should use `MFTECmd` output with `$FILENAME_Modified` column |
| PB-019 | TLS JA3 fingerprinting | JA3/JA3S hashes mentioned but no tool named — should be `ja3` Python lib or `tshark -T fields -e tls.handshake.ja3` |
| PB-019 | DGA detection | Domain generation algorithm detection — no tool (`dga-detector`, `dgaintel`, or entropy analysis) |
| PB-001 | Mark-of-the-Web (MotW) | Zone.Identifier ADS parsing — should be `sleuthkit` ADS scan or `Get-Item -Stream *` equivalent via `fls` |
| PB-006 | ARP spoofing | ARP cache + MAC table comparison — `arp -a` output, no tool for anomaly detection |
| PB-004 (real priv-esc) | Token analysis | `vol windows.getsids`, `vol windows.privs` not in any playbook |
| PB-008, PB-018 | Mutex / named pipe | Volatility `windows.mutantscan`, `windows.handles` — PB-027 covers handles but PB-008/018 don't reference it |

### Medium Priority

| Playbook | Phase | Missing Technique/Tool |
|---|---|---|
| PB-009 | Ransomware family ID | No family identification tool — should be YARA rules, `r2` byte pattern matching, or ID Ransomware API lookup |
| PB-009 | PyInstaller unpacking | `pyinstxtractor` + `uncompyle6` workflow not described — ransomware commonly uses PyInstaller |
| PB-013 (cloud) | LevelDB parsing | Teams/Slack use LevelDB; no parsing workflow — should be `plyvel` Python snippet |
| PB-014 | Rootkit detection | No tool named — should be `chkrootkit`, `rkhunter`, or `volatility linux.check_syscall` |
| PB-014 | LD_PRELOAD detection | `cat /etc/ld.so.preload` step present but no tool for detecting hidden injection via `ldd` comparison |
| PB-021 | SQLite WAL recovery | `.db-wal` + `.db-shm` handling not described — SQLite WAL checkpoint procedure missing |
| PB-024 | FSEvents parsing | `fsevents_parser` mentioned but no install or example command shown |
| PB-032 | Snapshot chain analysis | VMSD/VMSN correlation to reconstruct snapshot tree — no tool or workflow |
| PB-033 | Container SBOM | No SBOM analysis tool (`syft`, `grype`) — supply chain threat in PB-033 has no command |
| PB-016 | Binary correlation | Cross-host hash matching — no tool for bulk hash comparison across images |

---

## Part 4 — Missing Playbook Domains

These investigation types have **no playbook at all** in the current library. All are SANS or industry-standard domains.

### Critical Missing Playbooks

| Gap | SANS Course | Why It Matters | Suggested ID |
|---|---|---|---|
| **Real Privilege Escalation** | FOR508, FOR610 | Windows token abuse, UAC bypass, DLL hijacking, Linux SUID — PB-004 covers network devices instead | Fix PB-004 |
| **Real Web Shell Detection** | FOR500, FOR508 | IIS/Apache log + filesystem analysis for dropped web shells — PB-011 covers insider threat instead | Fix PB-011 |
| **Cloud/Enterprise IR (M365/Azure AD)** | FOR509 | Unified Audit Log, Azure AD sign-in logs, conditional access bypass, OAuth abuse — zero coverage | PB-025 |
| **Network Device Forensics** | FOR572 | Router/switch config analysis, ARP/VLAN, firmware — currently in PB-004 but mislabeled | PB-034 |

### High Priority Missing Playbooks

| Gap | SANS Course | Why It Matters | Suggested ID |
|---|---|---|---|
| **Active Directory / Domain Controller** | FOR508 | DC replication, DCSync artifacts, NTDS.dit, Golden/Silver ticket detection, Group Policy forensics | PB-035 |
| **PCAP / Network Forensics** | FOR572 | Dedicated PCAP analysis: Zeek log correlation, NetFlow, NetworkMiner, protocol-specific analysis | PB-036 |
| **EDR Telemetry Analysis** | FOR508 (emerging) | CrowdStrike/SentinelOne/Carbon Black log parsing — increasingly common evidence source | PB-037 |

### Lower Priority (Emerging)

| Gap | Why It Matters |
|---|---|
| **AWS/GCP CloudTrail forensics** | Cloud IR is now standard; CloudTrail + VPC flow logs have distinct forensic workflow |
| **Kubernetes pod forensics** | PB-033 mentions K8s but has no orchestration-level analysis |
| **iOS physical acquisition** | PB-021 covers logical/backup; physical (GrayKey/Cellebrite-style) workflow absent |
| **Firmware analysis** | Embedded/IoT device forensics; PB-004 mentions firmware but no analysis workflow |

---

## Part 5 — SIFT vs Installer Alignment Summary

### What SIFT Provides by Default (Verified Present on SIFT Workstation)

These are on SIFT and the installer should **verify/assert** rather than re-install:

```
sleuthkit, plaso, volatility3, regripper, ewf-tools, exiftool,
ssdeep, hashdeep, photorec, testdisk, foremost, scalpel,
tshark, wireshark, tcpflow, tcpdump, zeek, nmap, netcat,
bulk_extractor, dc3dd, readpst, yara, clamav, radare2,
strings, gdb, ltrace, strace, john, networkMiner
```

### What the Installer Currently Adds (Above SIFT Baseline)

```
Zimmerman tools (9): EvtxECmd, MFTECmd, bstrings, ShellBagsExplorer,
  AmcacheParser, SrumECmd, PECmd, JLECmd, LECmd, AppCompatCacheParser
pip tools: oletools, floss, jsbeautifier, capstone, peframe
REMnux addon (attempted): die, upx, radare2, clamav
Volatility2 (legacy): vol.py
dotnet 9 runtime
```

### Tools the Installer Should Add (Gap List)

```bash
# apt block additions
apt-get install -y foremost scalpel tcpflow zeek libbde-utils \
    libpst-utils libguestfs-tools qemu-utils bulk-extractor dc3dd \
    apfs-fuse cryptsetup testdisk

# pip block additions  
pip3 install plyvel pyinstxtractor uncompyle6 pefile python-magic \
    lief construct iLEAPP aLeapp

# Zimmerman tools additions
WxTCmd.zip  RecentFileCacheParser.zip  RBCmd.zip  SQLECmd.zip

# GitHub release installs
dive (Docker layer explorer)
python-cim (WMI forensics)
```

---

## Part 6 — Priority Matrix

### Fix Immediately (Correctness — wrong content)

| # | Action | Effort |
|---|---|---|
| 1 | Rewrite PB-004 for real privilege escalation | Medium |
| 2 | Rewrite PB-011 for real web shell detection | Medium |
| 3 | Rewrite PB-013 for real behavioral insider threat | Medium |
| 4 | Add PB-025 for Cloud/Enterprise IR (M365/Azure AD) | Large |
| 5 | Add PB-034 for Network Device Forensics (move PB-004 content) | Small |

### Fix Soon (Installer correctness — tools referenced but absent)

| # | Action | Effort |
|---|---|---|
| 6 | Add `iLEAPP` + `ALEAPP` install to installer | Small |
| 7 | Add `foremost`, `scalpel`, `zeek`, `tcpflow` to apt block | Small |
| 8 | Add `libbde-utils`, `libpst-utils`, `libguestfs-tools`, `qemu-utils` to apt block | Small |
| 9 | Add `plyvel`, `pefile`, `python-magic`, `lief` to pip block | Small |
| 10 | Add `WxTCmd`, `RecentFileCacheParser`, `RBCmd`, `SQLECmd` to Zimmerman block | Small |
| 11 | Add `apfs-fuse` install (PPA or build) | Medium |
| 12 | Add `pyinstxtractor` + `uncompyle6` to pip block | Small |
| 13 | Add `dive` install (GitHub release) | Small |

### Fix When Possible (Playbook documentation quality)

| # | Action | Effort |
|---|---|---|
| 14 | Add PowerShell 4104 multi-block reassembly workflow to PB-002, PB-010 | Small |
| 15 | Add WMI OBJECTS.DATA parsing workflow to PB-003 | Small |
| 16 | Add JA3/JA3S tshark commands to PB-019 | Small |
| 17 | Add timestomping MFTECmd workflow to PB-012 | Small |
| 18 | Add rootkit detection (`chkrootkit`/`rkhunter`) to PB-014 | Small |
| 19 | Add SQLite WAL recovery procedure to PB-021 | Small |
| 20 | Add `python-cim` WMI parsing commands to PB-003, PB-010 | Small |

---

## Appendix — Tool-to-Playbook Reference Map

| Tool | Status | Playbooks That Need It |
|---|---|---|
| `iLEAPP` | ❌ Not installed | PB-021 |
| `ALEAPP` | ❌ Not installed | PB-021 |
| `foremost` | ❌ Not installed | PB-026 |
| `scalpel` | ❌ Not installed | PB-026 |
| `zeek` | ❌ Not installed | PB-019, TOOLS.md |
| `tcpflow` | ❌ Not installed | PB-018 |
| `libbde-utils` | ❌ Not installed | PB-029 |
| `readpst` | ❌ Not installed | PB-023 |
| `libguestfs-tools` | ❌ Not installed | PB-032 |
| `qemu-utils` | ❌ Not installed | PB-032 |
| `apfs-fuse` | ❌ Not installed | PB-024, PB-029 |
| `plyvel` | ❌ Not installed | PB-030, PB-031 |
| `pyinstxtractor` | ❌ Not installed | PB-009 |
| `uncompyle6` | ❌ Not installed | PB-009 |
| `pefile` | ❌ Not installed | PB-008, PB-017, PB-018 |
| `python-magic` | ❌ Not installed | PB-008, PB-018 |
| `lief` | ❌ Not installed | PB-017, PB-018 |
| `WxTCmd` | ❌ Not in Zimmerman block | PB-028 |
| `RecentFileCacheParser` | ❌ Not in Zimmerman block | PB-028 |
| `RBCmd` | ❌ Not in Zimmerman block | PB-012, PB-026 |
| `SQLECmd` | ❌ Not in Zimmerman block | PB-022, PB-030, PB-031 |
| `dive` | ❌ Not installed | PB-033 |
| `bulk_extractor` | ⚠️ SIFT default, not verified | PB-008, PB-026 |
| `photorec` | ⚠️ SIFT default, not verified | PB-001, PB-008, PB-026 |
| `dc3dd` | ⚠️ SIFT default, not verified | Chain of custody |
| `NetworkMiner` | ⚠️ SIFT default, not verified | PB-019 |
| `vol` (Volatility3) | ✅ Installed | PB-005, PB-008, PB-027 |
| `vol.py` (Volatility2) | ✅ Installed | PB-018, legacy OS |
| `EvtxECmd` | ✅ Zimmerman | PB-002, PB-003, PB-028 |
| `MFTECmd` | ✅ Zimmerman | PB-009, PB-020 |
| `PECmd` | ✅ Zimmerman | PB-002, PB-010, PB-028 |
| `JLECmd` | ✅ Zimmerman | PB-015, PB-028 |
| `LECmd` | ✅ Zimmerman | PB-015, PB-028 |
| `AmcacheParser` | ✅ Zimmerman | PB-002, PB-003, PB-028 |
| `AppCompatCacheParser` | ✅ Zimmerman | PB-002, PB-028 |
| `SrumECmd` | ✅ Zimmerman | PB-007, PB-013, PB-028 |
| `ShellBagsExplorer` | ✅ Zimmerman | PB-003, PB-013, PB-028 |
| `oledump` | ✅ pip (oletools) | PB-017, PB-018, PB-023 |
| `floss` | ✅ pip | PB-017, PB-018 |
| `pdfid` | ✅ pip wrapper | PB-017, PB-018 |
| `js-beautify` | ✅ pip (jsbeautifier) | PB-017, PB-018 |
| `clamscan` | ✅ apt | PB-008, PB-017, PB-018 |
| `yara` | ✅ via remnux/apt | PB-008, PB-017, PB-018 |
| `tshark` | ✅ apt | PB-009, PB-018, PB-019 |
| `exiftool` | ✅ apt | PB-001, PB-017, PB-018, PB-021 |
| `ssdeep` | ✅ apt | PB-008, PB-017, PB-018 |
| `hashdeep` | ✅ apt | PB-008, PB-017, PB-018 |
| `radare2` | ✅ apt | PB-017, PB-018 |
| `upx` | ✅ apt | PB-017, PB-018 |
| `die` | ✅ apt + wrapper | PB-017, PB-018 |
| `peframe` | ✅ pip | PB-017, PB-018 |
