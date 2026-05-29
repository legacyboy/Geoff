# Geoff DFIR Framework — Evidence Audit Report

**Date:** 2026-05-24  
**Auditor:** Claude (Sonnet 4.6)  
**Sources:** SIFT VM `/home/sansforensics/Geoff/src/` + local `EVIDENCE_AUDIT.md`  
**Scope:** Evidence classification, device grouping, playbook routing, and architectural gaps

---

## Executive Summary

Geoff has a solid three-stage classification pipeline (fast → header → LLM), a well-designed device discovery system, and an impressive 35-playbook coverage model. However, **22 of 28 NAS evidence directories have never been processed**, and several systemic architectural gaps would cause material evidence to be missed even in cases that ARE processed. The most critical issues are:

1. Disk images extracted from archives are silently demoted to `other_files` rather than promoted to `disk_images`
2. RAR archives are never extracted — their contents are permanently inaccessible
3. Chip-off physical images receive no mobile-aware analysis
4. Header analysis is capped at 20 files regardless of case size
5. Mobile PB-SIFT-021 runs ALL iOS AND Android steps on every mobile backup with no OS detection guard, and cannot run on chip-off disk images at all

---

## Finding 1 — Disk Images Inside Archives Are Never Processed as Disk Images

**Impact: HIGH**

### Problem Statement

When Geoff extracts a ZIP or 7z archive, extracted files are re-classified by magic bytes (`_detect_file_type_from_header`). However, the re-routing logic only promotes `sqlite_db` files to `mobile_backups` and `elf_binary`/`pe_binary`/`macho_binary` to `other_files`. Everything else — including extracted `.E01`, `.img`, and `.dd` disk images — is dumped into `other_files`.

### Code Location

`pipeline_phases.py`, Phase 1c extraction loop (~line 870):

```python
for fpath in extracted_files[:_file_cap]:
    fheader = _detect_file_type_from_header(fpath)
    if fheader == "sqlite_db":
        inventory["mobile_backups"].append(fpath)
    elif fheader in ("elf_binary", "pe_binary", "macho_binary"):
        inventory["other_files"].append(fpath)
    else:
        inventory["other_files"].append(fpath)   # <-- E01/IMG/DD land here
```

`_detect_file_type_from_header` in `geoff_models.py` correctly returns `"ewf_disk_image"` for EWF/E01 files (EVF magic bytes). But that return value is never checked in the extraction routing.

### Affected Cases

- `stolen-sauce`: 10 ZIPs containing DC01 and DESKTOP disk images — if extracted, disk images would go to `other_files` and receive only REMnux analysis, no SleuthKit/Plaso/Volatility
- `APT 2015`: win7-32/win7-64 ZIPs — same
- `linux-forensics`: nist-linux-scenario.zip containing an `.img` — same
- `dfrws2017`: ZIP archives of IoT device images — same

### Recommended Fix

Extend the re-routing switch in Phase 1c:

```python
fheader = _detect_file_type_from_header(fpath)
if fheader in ("ewf_disk_image", "vmdk_image", "dmg_image", "iso_image"):
    inventory["disk_images"].append(fpath)
elif fheader in ("pcap",):
    inventory["pcaps"].append(fpath)
elif fheader in ("registry_hive",):
    inventory["registry_hives"].append(fpath)
elif fheader in ("memory_dump",):
    inventory["memory_dumps"].append(fpath)
elif fheader == "sqlite_db":
    inventory["mobile_backups"].append(fpath)
...
```

Then call `DeviceDiscovery.discover()` again after extraction to rebuild the device map with the newly-promoted evidence types.

**Complexity:** Quick fix (15–20 lines) + device discovery re-run (architectural consideration)

---

## Finding 2 — RAR Archives Are Never Extracted

**Impact: HIGH**

### Problem Statement

The archive extraction pipeline uses `_detect_file_type_from_header` to identify archives, then checks:

```python
if header_type in ("zip_archive", "gzip_archive", "tar_archive", "7zip_archive"):
    result = _extract_archive(archive_path, job_id=job_id)
```

The RAR magic bytes (`Rar!\x1a\x07`) are **not** in `_detect_file_type_from_header` (`geoff_models.py` ~line 240). RAR files also don't appear in that function's return values. Consequently, any `.rar` file in the evidence directory:

1. Gets classified to `other_files` by `_fast_classify` (`.rar` is not in any known-type set)
2. Gets no header analysis promotion (no RAR in `_map_header_to_type`)
3. Passes through Phase 1c without extraction
4. Receives REMnux analysis (die_scan, ClamAV, etc.) as an opaque binary — the CONTENTS are never seen

Note that `archive_exts` in the playbook queuing section (line 1637) **does** include `.rar`, so Data Staging (PB-SIFT-015) gets queued. But the actual extraction never happens.

### Affected Cases

- `memory-images`: Contains a RAR archive of memory dumps — the individual memory images inside are never analyzed by Volatility
- Any other RAR-compressed evidence on the NAS

### Recommended Fix

Add RAR detection to `_detect_file_type_from_header` in `geoff_models.py`:

```python
# RAR archives (RAR 4.x and 5.x)
if header[:7] == b'Rar!\x1a\x07\x00' or header[:7] == b'Rar!\x1a\x07\x01':
    return "rar_archive"
```

Add RAR to the extraction condition in Phase 1c (`pipeline_phases.py`):

```python
if header_type in ("zip_archive", "gzip_archive", "tar_archive", "7zip_archive", "rar_archive"):
```

Add unrar/7z backend to `_extract_archive`:

```python
elif archive_type == "rar_archive":
    result = subprocess.run(["unrar", "x", "-y", archive_path, extract_dir],
                            capture_output=True, timeout=600)
```

**Complexity:** Quick fix — requires `unrar` on SIFT (already installed on SIFT workstations)

---

## Finding 3 — No Recursive Archive Extraction

**Impact: MEDIUM**

### Problem Statement

After Phase 1c extracts archives, extracted files go into `inventory["other_files"]`. The extraction loop processes `inventory.get("mobile_backups", []) + inventory.get("other_files", [])` at Phase 1c start — but by the time extracted files are appended to `other_files`, the loop has already passed those entries.

Result: nested archives (ZIP containing ZIP, tar.gz containing E01, 7z containing .img) are never recursively extracted. The inner archive lands in `other_files` and receives only REMnux analysis.

### Code Location

`pipeline_phases.py`, Phase 1c, the `for archive_path in ...` loop. New entries appended inside the loop body are not visited by the loop.

### Affected Cases

- `stolen-sauce`: Each ZIP may itself contain nested ZIPs (DC01 structure has multiple layers)
- `sans-hackathon`: SANS_Hackathon_2026.zip likely contains further archives
- `registry-forensics`: 7z archives likely contain further compressed hive files

### Recommended Fix

Replace the single-pass loop with a work queue pattern:

```python
archives_to_process = deque(
    inventory.get("mobile_backups", []) + inventory.get("other_files", [])
)
seen = set()
while archives_to_process:
    archive_path = archives_to_process.popleft()
    if archive_path in seen:
        continue
    seen.add(archive_path)
    header_type = _detect_file_type_from_header(archive_path)
    if header_type in EXTRACTABLE_ARCHIVE_TYPES:
        result = _extract_archive(archive_path, ...)
        for fpath in result.get("files", []):
            fheader = _detect_file_type_from_header(fpath)
            if fheader in EXTRACTABLE_ARCHIVE_TYPES:
                archives_to_process.append(fpath)   # recurse
            else:
                _route_extracted_file(fpath, inventory)
```

Cap recursion depth at 3–4 levels to prevent zip-bomb loops.

**Complexity:** Moderate refactor of Phase 1c

---

## Finding 4 — Header Analysis Capped at 20 Files

**Impact: HIGH**

### Problem Statement

`AIEvidenceClassifier._header_classify()` in `evidence_classifier.py` explicitly slices:

```python
other_files = inventory["other_files"][:20]  # Process first 20 to avoid overload
```

In a large case (e.g., stolen-sauce with 10 ZIPs each containing hundreds of files, or the 2018 case with mixed evidence), hundreds of files could land in `other_files`. Only the first 20 receive magic-byte header analysis and potential reclassification. The remaining files stay in `other_files` with 0.3 confidence and are eventually only analyzed by the blunt-instrument REMnux pipeline.

### Code Location

`evidence_classifier.py`, `_header_classify()`, line ~290:

```python
other_files = inventory["other_files"][:20]  # Process first 20 to avoid overload
```

### Impact

- Registry hives with non-standard names (e.g., `NTUSER.1` or a copied-out `SOFTWARE`) beyond position 20 will never be reclassified
- EVTX logs with non-standard names (e.g., `archive.evtx`) won't be promoted
- Disk images within large archives won't be promoted after Finding 1 fix is applied (if there are >20 files)

### Recommended Fix

Remove the hard cap; instead, run header analysis on all files but skip very small (<16 bytes) or very large (>1GB) files that can't benefit from magic-byte checks:

```python
other_files = [
    f for f in inventory["other_files"]
    if 16 <= os.path.getsize(f) <= 1_073_741_824  # 16 bytes to 1GB
]
```

For the LLM stage, keep the batch cap (5 per call) but add a total cap with a log warning at e.g. 500 files.

**Complexity:** Quick fix (1 line change + size filter)

---

## Finding 5 — Chip-Off Physical Images Get No Mobile-Aware Analysis

**Impact: HIGH**

### Problem Statement

`mobile-chipoff` contains HTC phone raw NAND dumps with `.img` extensions. The `_fast_classify` function categorizes `.img` as `disk_images` (correct extension match). Device discovery then creates a standard `disk_images` device for them.

The pipeline runs the standard disk analysis chain:
- `mmls` (partition table) — **fails**: raw NAND has no MBR/GPT
- `fls` (filesystem listing) — **fails**: no standard filesystem at offset 0
- Carving trigger: the large-image-with-minimal-filesystem check fires, queuing PB-SIFT-026 (photorec)

**What does NOT happen:**
- PB-SIFT-021 (Mobile Analysis) only runs on `inventory["mobile_backups"]`, not `disk_images`
- No YAFFS2/UBIFS-aware filesystem analysis
- No JTAG/chip-off specific tools (e.g., `yaffs2utils`, `ubi_reader`, `f3d`)
- No Android-specific SQLite recovery from raw NAND
- No mobile forensic tool suite (ALEAPP, iLEAPP) invocation

Chip-off images are physically acquired mobile images — the most forensically rich mobile evidence type — yet Geoff treats them as corrupted hard drives.

### Code Location

`evidence_classifier.py`, `_fast_classify()`: `.img` → `disk_images`

`pipeline_phases.py`, playbook queuing:
```python
if inventory["mobile_backups"]:
    execution_plan.append("PB-SIFT-021")
# chip-off .img files are in disk_images, not mobile_backups → never reach here
```

### Recommended Fix

**Option A (Quick):** In `_fast_classify`, add path-context heuristics to detect chip-off images:

```python
# If file is in a directory with "chipoff", "chip_off", "mobile", "phone", "htc", "android"
# and extension is .img, classify as mobile_backups instead of disk_images
if ext == '.img' and any(kw in name_lower or kw in parent_lower 
                         for kw in ['chipoff', 'chip_off', 'mobile', 'phone', 'htc', 'android', 'iphone']):
    inventory["mobile_backups"].append(str(item))
```

**Option B (Better):** Add a chip-off specific sub-type to the inventory schema:
```python
inventory["chip_off_images"] = []  # Raw NAND/eMMC dumps
```
and add PB-SIFT-021 to trigger on `chip_off_images` with a dedicated NAND forensics step using YAFFS2/UBI tools.

**Complexity:** Option A is a quick fix; Option B is an architectural change (new evidence type + new specialist tools)

---

## Finding 6 — PB-SIFT-011 (Web Shell) Triggered by PCaps, Steps Use None

**Impact: MEDIUM**

### Problem Statement

The playbook queuing logic in `pipeline_phases.py` triggers PB-SIFT-011 when PCaps are present:

```python
if inventory["pcaps"]:
    execution_plan.append("PB-SIFT-011")
```

But `PLAYBOOK_STEPS["PB-SIFT-011"]` in `geoff_config.py` only defines steps for `evtx_logs` and `disk_images`:

```python
"PB-SIFT-011": {
    "evtx_logs": [("logs", "parse_evtx", ...)],
    "evt_logs":  [("logs", "parse_evt",  ...)],
    "disk_images": [("sleuthkit", "list_files", ...)],
}
```

There are NO `pcaps` steps in PB-SIFT-011. A case with **only** PCap files (e.g., `network-forensics`) would have PB-SIFT-011 queued, but it would execute zero steps because the playbook executor only runs steps whose evidence type key exists in the current device's evidence.

Additionally, the playbook name is "Web Shell" — web shell detection via PCap alone would require HTTP body inspection, which isn't in any network playbook.

### Code Location

`geoff_config.py`, `PLAYBOOK_STEPS["PB-SIFT-011"]` — missing `pcaps` key  
`pipeline_phases.py`, playbook queuing section — PB-SIFT-011 trigger condition

### Recommended Fix

Either:
- Remove the `if inventory["pcaps"]` trigger for PB-SIFT-011 (web shells are detected on-host via logs/filesystem, not network captures), OR
- Add a `pcaps` step to PB-SIFT-011 using `extract_http` to find web shell POST patterns:

```python
"PB-SIFT-011": {
    ...
    "pcaps": [
        ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
        ("network", "extract_http", {"pcap_file": "{pcap}"}),
    ],
}
```

**Complexity:** Quick fix

---

## Finding 7 — LOG Files Receive Wrong Analysis Pipeline

**Impact: MEDIUM**

### Problem Statement

`SCHARDT.LOG` in the hacking-case is the critical application log capturing the threat actor's activity. Files with `.log` extension are not in any of `_fast_classify`'s known-type sets and land in `other_files`.

From `other_files`, they are routed to:
- `die_scan` — binary format detection (useless for text logs)
- `radare2_analyze` — binary disassembly (useless for text logs)
- `peframe_scan` — PE analysis (useless for text logs)
- `floss_strings` — string extraction (marginally useful)
- `scan_document_pii` — PII scan (useful but not forensic-log-specific)

What they do NOT receive:
- `parse_syslog` (requires classification as `syslogs`)
- IOC extraction (IP addresses, domains, file paths from log content)
- Timeline contribution (no log2timeline parser runs on raw .log files)
- Pattern matching against known attack patterns

The `syslogs` category in `_fast_classify` only matches exact filenames: `syslog`, `auth.log`, `kern.log`, `messages`, `secure`, `daemon.log`. Any other log filename (application logs, IIS logs, Apache logs, custom logs) gets zero log-specific analysis.

### Code Location

`evidence_classifier.py`, `_fast_classify()`, `syslog_names` set (~line 260):

```python
syslog_names = {'syslog', 'auth.log', 'kern.log', 'messages', 'secure', 
                'auth.log.1', 'daemon.log'}
```

`_header_classify` → `_map_header_to_type`: for `ascii text` files, returns `None` — punts to LLM.

LLM stage batches 5 files at a time; under load, logs may not be classified correctly.

### Recommended Fix

Extend syslog classification to include common log extensions:

```python
# In _fast_classify
log_extensions = {'.log', '.LOG'}
log_name_patterns = ['access_log', 'error_log', 'audit.log', 'application.log',
                     '.log.', '-log', '_log']
if ext in log_extensions or any(p in name_lower for p in log_name_patterns):
    inventory["syslogs"].append(str(item))
```

Add a `PB-SIFT-013_plus` step or extend PB-SIFT-013 (Insider Threat) to run IOC extraction on all `syslogs`:

```python
"syslogs": [
    ("logs", "parse_syslog",         {"log_file": "{syslog}"}),
    ("logs", "extract_iocs_from_log", {"log_file": "{syslog}"}),  # IPs, domains, hashes
]
```

**Complexity:** Quick fix for classification; moderate for adding IOC extraction step

---

## Finding 8 — Encrypted Archives Fail Silently, Content Unanalyzed

**Impact: HIGH (security)**

### Problem Statement

If an archive is password-protected (AES-256 ZIP, encrypted 7z, RAR with password), `_extract_archive` will fail. The failure path in Phase 1c is:

```python
else:
    _fe_log(job_id, f"  ⚠ Extraction failed for {Path(archive_path).name}: {result.get('error', 'unknown')}")
```

The archive remains in `other_files` and receives REMnux scanning of the outer container only. The encrypted contents are **never examined**. More critically:

1. There is no alert to the analyst that extraction failed due to encryption (vs. corruption)
2. No attempt is made to find the password in the evidence (e.g., in memory dumps, registry, browser saved passwords)
3. No brute-force or dictionary attack is attempted even for simple passwords

This is an active malware evasion technique: attackers zip payloads with simple passwords (e.g., "infected", "virus", "malware") that evade AV scanning.

### Affected Scenarios

- Malware delivery via encrypted ZIP in email attachments (common in phishing campaigns)
- Exfiltration staging: attacker compresses data with a known password before exfil
- Evidence packaging: some investigators package evidence in encrypted archives for transport

### Code Location

`pipeline_phases.py`, Phase 1c, extraction failure handler  
No password-discovery-and-retry logic exists anywhere in the codebase

### Recommended Fix

1. **Distinguish encryption failures**: Parse the extraction error to detect `"wrong password"`, `"encrypted"`, `"CRC failed"` signals. Log these as `"encrypted_archive_found"` findings with HIGH severity.

2. **Dictionary attack on simple passwords**: Try a hardcoded list of common malware distribution passwords:
```python
MALWARE_ARCHIVE_PASSWORDS = ["infected", "virus", "malware", "password", "123456",
                              "sample", "analyze", "sandbox", "threat", "evil"]
```

3. **Cross-reference memory for passwords**: If memory dumps are present, run FLOSS on them and attempt extracted strings as passwords.

**Complexity:** Moderate — requires changes to `_extract_archive` and a new password-recovery strategy

---

## Finding 9 — No ADS, Steganography, or Alternate Content Detection

**Impact: MEDIUM**

### Problem Statement

Three categories of malware evasion are completely unaddressed:

**A. Alternate Data Streams (ADS):** NTFS supports multiple data streams per file. Malware commonly hides executables in ADS (e.g., `legit.txt:hidden.exe`). No playbook runs `icat -a` or `fls -a` to enumerate ADS. PB-SIFT-012 (Anti-Forensics) doesn't include ADS detection.

**B. Steganography:** No stego detection tools (steghide, stegseek, zsteg, outguess) in any playbook. Cases involving insider threats or APT operators commonly use steganography in images. The `mobile-chipoff` photos, the photos in mobile backups, and any JPEG/PNG files in `other_files` receive only exiftool metadata scan.

**C. Polyglot files and renamed extensions:** `_header_classify` does run magic-byte detection on `other_files`, but only for the first 20 files (Finding 4). A renamed executable (`malware.pdf` with MZ header) beyond position 20 receives only content-inappropriate analysis.

### Code Location

`geoff_config.py`, `PLAYBOOK_STEPS["PB-SIFT-012"]` — no ADS enumeration steps  
`geoff_config.py`, `PLAYBOOK_STEPS["PB-SIFT-017"]` — no steganography detection  
`evidence_classifier.py`, `_header_classify()` — 20-file cap (see Finding 4)

### Recommended Fix

Add to PB-SIFT-012 (Anti-Forensics):
```python
"disk_images": [
    ...
    ("sleuthkit", "list_files_ads", {"image": "{image}", "offset": "{offset}"}),  # fls -a
]
```

Add to PB-SIFT-017 or new PB-SIFT-036_stego:
```python
"other_files": [
    ("remnux", "stegseek_scan", {"target_file": "{file}"}),  # fast steg detection
    ("remnux", "binwalk_scan",  {"target_file": "{file}"}),  # embedded content
]
```

**Complexity:** Moderate — needs new specialist methods for steganography and ADS tools

---

## Finding 10 — Mobile PB-SIFT-021 Runs iOS + Android Steps on Every Mobile Backup

**Impact: MEDIUM**

### Problem Statement

`PLAYBOOK_STEPS["PB-SIFT-021"]` in `geoff_config.py` lists approximately 35 iOS steps followed by ~15 Android steps, ALL under the `mobile_backups` evidence type key. The playbook executor runs ALL steps for every mobile backup, regardless of whether it's an iOS or Android device.

Consequences:
1. **Performance:** Every iOS backup runs all 15 Android steps (wasted calls that return "not found" or errors)
2. **False findings:** Android-specific tools on iOS data can return false positives
3. **No differentiation:** The 6 mobile evidence directories (android13, android14, ios16, ios17, chipoff) each need a completely different toolchain

Device discovery DOES attempt to detect OS from Info.plist, build.prop, manifest.db, etc. (`device_discovery.py`, `_enrich_device`). The `dev["os_type"]` is set to "ios" or "android". But the playbook executor doesn't use `os_type` to filter steps within PB-SIFT-021.

### Code Location

`geoff_config.py`, `PLAYBOOK_STEPS["PB-SIFT-021"]` — all steps share the `mobile_backups` key  
`pipeline_phases.py`, playbook executor — does not filter steps by `dev["os_type"]`

### Recommended Fix

Split PB-SIFT-021 into `mobile_ios_backups` and `mobile_android_backups` evidence type keys within the same playbook:

```python
"PB-SIFT-021": {
    "mobile_ios_backups": [
        ("mobile", "analyze_ios_backup", {"backup_dir": "{mobile}"}),
        ...iOS steps...
    ],
    "mobile_android_backups": [
        ("mobile", "analyze_android", {"data_dir": "{mobile}"}),
        ...Android steps...
    ],
}
```

Then in device discovery, reclassify each mobile backup entry into the appropriate sub-type based on `os_type`.

Alternatively, keep the current structure but gate steps in the playbook executor:
```python
if step_os_hint and dev.get("os_type") not in (step_os_hint, "unknown"):
    skip step
```

**Complexity:** Moderate — changes to playbook executor step filtering OR to evidence type taxonomy

---

## Finding 11 — Device Grouping Breaks on IoT Evidence (google-drive-case)

**Impact: MEDIUM**

### Problem Statement

`google-drive-case` has this structure:
```
google-drive-case/
  arlo/        ← IP camera
  echo/        ← Amazon Echo
  ismartalarm/ ← alarm system
  network/     ← network captures
  samsung/     ← Samsung smart TV
  wink/        ← smart hub
```

`device_discovery.py` Strategy 1 checks `evidence_path.iterdir()` for subdirectories. It then checks whether each subdir contains files in the inventory. The inventory is built from `evidence_classifier._fast_classify()` which recursively walks with `rglob('*')`. If the files inside these IoT subdirs are in unrecognized formats (custom IoT protocols, proprietary firmware dumps, XML configs), they ALL land in `other_files`.

`subdir_has_evidence` checks `if str(fpath).startswith(str(sd))` — since `other_files` ARE tracked, the subdirs would be detected as containing evidence and each IoT device would get a separate device entry. **This part works correctly.**

However, the device enrichment `_enrich_device()` only handles Windows, Linux, macOS, iOS, Android. IoT devices get `os_type: "unknown"` and `device_type: "unknown"`. No IoT-specific enrichment or playbook routing exists.

The 6 IoT devices would all run the same generic Windows-centric playbooks (PB-SIFT-001 through PB-SIFT-015), none of which are appropriate for embedded Linux firmware, Echo voice logs, or Arlo camera footage.

### Code Location

`device_discovery.py`, `_enrich_device()` — no IoT OS types  
`pipeline_phases.py`, playbook queuing — no IoT-specific playbook trigger  
`geoff_config.py` — no IoT forensics playbook

### Recommended Fix

Add IoT device detection in `_enrich_device`:

```python
iot_indicators = {'firmware', 'nvram', 'flash', 'squashfs', 'cramfs', 
                  'jffs2', 'ubifs', 'yaffs', '.bin', '.fw', 'alexa', 'echo'}
if any(ind in str(dev["evidence_files"]).lower() for ind in iot_indicators):
    dev["device_type"] = "iot_device"
    dev["os_type"] = "iot_embedded_linux"
```

Add new playbook PB-SIFT-034_iot (or extend PB-SIFT-033/Container):
```python
"PB-SIFT-034": {  # IoT/Embedded Forensics
    "other_files": [
        ("remnux", "binwalk_scan",    {"target_file": "{file}"}),
        ("logs",   "parse_syslog",    {"log_file": "{file}"}),
        ("remnux", "strings_scan",    {"target_file": "{file}"}),
    ]
}
```

**Complexity:** Moderate for detection; new playbook is architectural change

---

## Finding 12 — PCAP Analysis Lacks C2 Pattern Detection and DNS Extraction in Playbooks

**Impact: MEDIUM**

### Problem Statement

`sift_specialists_extended.py` has a solid `analyze_pcap` implementation that extracts DNS queries (via `_parse_dns_queries`), protocol hierarchy, and TCP streams. `extract_http` and `extract_flows` also exist.

However, several important capabilities are missing from the playbook steps:

1. **No JA3/JA3S TLS fingerprinting**: TLS connections (HTTPS C2) are invisible to HTTP extraction. No tool invocation for JA3 fingerprinting.
2. **No Zeek/Suricata integration**: No IDS rule application against the PCAP.
3. **DNS-over-HTTPS (DoH) detection**: Modern C2 uses DoH; tshark DNS parsing only catches cleartext DNS.
4. **PB-SIFT-019 (C&C)** runs `analyze_pcap` and `extract_flows` but doesn't specifically look for C2 beacon patterns (periodic small outbound connections, domain generation algorithms, low-TTL DNS).
5. **`network-forensics`** directory (3 pcap files) has NEVER been processed — PB-SIFT-036 (PCAP Network Forensics) is referenced in the queuing code but is not defined in `PLAYBOOK_STEPS` in `geoff_config.py` (jumps from PB-SIFT-033 to PB-SIFT-035).

### Code Location

`geoff_config.py`, `PLAYBOOK_NAMES` — PB-SIFT-036 listed but not in `PLAYBOOK_STEPS`  
`geoff_config.py`, `PLAYBOOK_STEPS["PB-SIFT-019"]` — no C2 beacon detection logic

### Recommended Fix

Add PB-SIFT-036 to `PLAYBOOK_STEPS`:

```python
"PB-SIFT-036": {  # PCAP Network Forensics — full deep analysis
    "pcaps": [
        ("network", "analyze_pcap",    {"pcap_file": "{pcap}"}),
        ("network", "extract_http",    {"pcap_file": "{pcap}"}),
        ("network", "extract_flows",   {"pcap_file": "{pcap}", "output_dir": "{output_dir}/flows"}),
        ("network", "extract_dns",     {"pcap_file": "{pcap}"}),
        ("network", "detect_c2_beacons", {"pcap_file": "{pcap}"}),  # requires new specialist
        ("remnux",  "inetsim_check",   {"target_file": "{pcap}"}),
    ],
}
```

**Complexity:** Quick fix for PB-SIFT-036 definition; new beacon detection specialist is moderate

---

## Finding 13 — Multi-Host Correlation Only Fires for disk_images > 1

**Impact: MEDIUM**

### Problem Statement

PB-SIFT-016 (Cross-Image Correlation) is queued when `len(inventory["disk_images"]) > 1`. This works for cases like the 2018 enterprise case (6 E01s) once they are processed.

However, several gaps exist:

1. **Mixed evidence types not correlated**: A case with 3 disk images + 3 memory dumps + 2 PCaps could have critical IOC overlap (same IP in PCAP and in disk image's event log), but the correlation only runs Plaso timelines on disk images. Memory and network evidence are not fed into the cross-host correlation.

2. **HostCorrelator**: The module exists and is imported, but its role in the Pass 2 pipeline depends on the Super Timeline being complete first. Pass 2 triggers (`PASS2_TRIGGER_PLAYBOOK_MAP`) include `ioc_correlation` → PB-SIFT-103, which does cross-device IOC searching. This is well-designed but requires Pass 1 to complete fully first — which means multi-host correlation is always the LAST thing that runs (correct) but won't catch early stopping or phase failures.

3. **The stolen-sauce case** (10 ZIPs, DC01 + DESKTOP multi-host enterprise incident) has never been processed. The ZIPs must be extracted first, disk images identified inside, THEN correlation can run. But due to Finding 1 (disk images from archives go to `other_files`), these disk images would never reach `inventory["disk_images"]` and PB-SIFT-016 would not fire.

### Recommended Fix

Extend PB-SIFT-016 trigger condition:

```python
total_evidence_items = (len(inventory["disk_images"]) + 
                        len(inventory["memory_dumps"]) + 
                        len(inventory["pcaps"]))
if total_evidence_items > 1:
    execution_plan.append("PB-SIFT-016")
```

**Complexity:** Quick fix for trigger; architectural for true multi-type correlation

---

## Finding 14 — The Linear Pipeline Should Be Iterative After Archive Extraction

**Impact: HIGH (architectural)**

### Problem Statement

The current pipeline is:

```
classify → discover devices → extract archives → queue playbooks → execute → Pass 2 → report
```

Archive extraction (Phase 1c) fundamentally changes the evidence inventory. Currently:
- Device discovery runs BEFORE extraction (it sees archives, not their contents)
- Phase 1f partially updates device maps with extracted files, but it's a patch on an incorrect initial structure
- Re-classification after extraction (Phase 1d: `_validate_inventory_classification`) catches some cases but doesn't re-run the full AI classification pipeline

The correct architecture is:

```
classify → extract archives (recursive, see Finding 3) → re-classify → 
discover devices → queue playbooks → execute → Pass 2 → report
```

Or with checkpointing:

```
[classify + extract + re-classify]* until stable → discover → queue → execute → report
```

### Evidence

Phase 1f in `pipeline_phases.py` (~line 968) attempts to patch device maps after extraction:
```python
# Phase 1f: Update device maps with extracted archive contents
for archive_info in extracted_archives:
    if archive_path in dev.get("evidence_files", []):
        extracted_files = archive_info.get("files", [])
        ...
        if archive_path in dev["evidence_files"]:
```
This is a band-aid. The device type, OS type, and evidence type lists are all derived from the pre-extraction inventory.

### Recommended Fix

Separate the ingestion pipeline from the analysis pipeline:

**Stage A — Ingestion (idempotent, re-runnable):**
1. Scan for files
2. Extract all archives recursively
3. Classify all evidence (including contents of archives)
4. Discover devices and build device map

**Stage B — Analysis:**
5. Queue and execute playbooks based on stable inventory
6. Build Super Timeline
7. Run Pass 2 correlation
8. Generate report

Stage A should be re-runnable with checkpointing — running it again should add newly discovered evidence without re-processing already-classified items.

**Complexity:** Architectural refactor — significant but the existing checkpoint system (`_ckpt_*` functions) already provides the foundation

---

## Finding 15 — "other_files" Gets Redundant Dual-REMnux Analysis

**Impact: LOW (efficiency)**

### Problem Statement

Files in `other_files` receive REMnux analysis TWICE:
- PB-SIFT-017 (REMnux Malware Analysis): die_scan, exiftool, clamav, ssdeep, hashdeep, floss, radare2, peframe, upx_unpack, pdfid_scan, pdf_parser, oledump_scan, js_beautify
- PB-SIFT-025 (Generic File Analysis): die_scan, exiftool, clamav, ssdeep, floss, radare2, strings, pii_scan

Both are queued when `other_files` is non-empty (PB-SIFT-025) or when malware analysis is warranted (PB-SIFT-017), which is also triggered by non-empty `other_files`. The overlap is ~7 tools.

### Code Location

`geoff_config.py`, `PLAYBOOK_STEPS["PB-SIFT-017"]` and `PLAYBOOK_STEPS["PB-SIFT-025"]`

### Recommended Fix

Deduplicate: PB-SIFT-025 should only run tools NOT in PB-SIFT-017, or the two playbooks should be merged with PB-SIFT-025 as the "first pass" and PB-SIFT-017 as the "deep malware analysis" triggered by suspicious findings from PB-SIFT-025.

**Complexity:** Quick cleanup

---

## Summary Table

| # | Finding | Impact | Fix Complexity | Files Affected |
|---|---------|--------|----------------|----------------|
| 1 | Disk images from archives go to `other_files` | HIGH | Quick (15 lines + re-discovery run) | `pipeline_phases.py` |
| 2 | RAR never extracted | HIGH | Quick | `geoff_models.py`, `pipeline_phases.py` |
| 3 | No recursive archive extraction | MEDIUM | Moderate refactor | `pipeline_phases.py` |
| 4 | Header analysis capped at 20 files | HIGH | Quick (1 line) | `evidence_classifier.py` |
| 5 | Chip-off gets no mobile analysis | HIGH | Option A quick; B architectural | `evidence_classifier.py`, `pipeline_phases.py` |
| 6 | PB-SIFT-011 triggered by PCap but has no PCap steps | MEDIUM | Quick | `geoff_config.py` |
| 7 | LOG files routed to wrong pipeline | MEDIUM | Quick | `evidence_classifier.py`, `geoff_config.py` |
| 8 | Encrypted archives fail silently | HIGH | Moderate | `pipeline_phases.py` |
| 9 | No ADS, steganography, embedded content detection | MEDIUM | Moderate | `geoff_config.py`, `sift_specialists_extended.py` |
| 10 | Mobile PB-SIFT-021 runs all iOS+Android steps blindly | MEDIUM | Moderate | `geoff_config.py`, `pipeline_phases.py` |
| 11 | IoT evidence gets no appropriate toolchain | MEDIUM | Architectural | `device_discovery.py`, `geoff_config.py` |
| 12 | PB-SIFT-036 defined in name list but missing from PLAYBOOK_STEPS | MEDIUM | Quick | `geoff_config.py` |
| 13 | Multi-host correlation misses non-disk evidence and archive-wrapped disks | MEDIUM | Quick trigger fix + architectural | `pipeline_phases.py` |
| 14 | Linear pipeline should be iterative after archive extraction | HIGH | Architectural | `pipeline_phases.py`, `find_evil()` |
| 15 | Dual REMnux analysis on `other_files` (redundancy) | LOW | Quick cleanup | `geoff_config.py` |

---

## Quick Wins (Implement First)

These five changes require <50 lines of code and fix HIGH-impact issues:

1. **Remove the `[:20]` cap** in `evidence_classifier.py` `_header_classify()` (Finding 4)
2. **Add RAR magic bytes** to `_detect_file_type_from_header` and RAR to the extraction condition (Finding 2)
3. **Promote extracted disk images** to `inventory["disk_images"]` in Phase 1c routing (Finding 1)
4. **Add PB-SIFT-036 to PLAYBOOK_STEPS** in `geoff_config.py` (Finding 12)
5. **Fix PB-SIFT-011 trigger** — remove the pcap-triggered queuing or add pcap steps (Finding 6)

---

## Cases That Would Become Processable After Fixes

| Case | Current Status | After Fixes |
|------|---------------|-------------|
| `stolen-sauce` | NO (ZIPs never extracted to disk_images) | YES after Findings 1+3 |
| `APT 2015` | NO (ZIPs never extracted) | YES after Finding 1 |
| `memory-images` | NO (RAR never extracted) | YES after Finding 2 |
| `mobile-chipoff` | NO (disk_images, no mobile analysis) | YES after Finding 5 |
| `network-forensics` | NO (PB-SIFT-036 missing) | YES after Finding 12 |
| `hacking-case` | PARTIAL (SCHARDT.LOG not log-parsed) | IMPROVED after Finding 7 |
| `linux-forensics` | NO (ZIP not extracted to disk_image) | YES after Finding 1 |
| `dfrws2017` | NO (ZIPs not extracted to disk_images) | YES after Finding 1 |

