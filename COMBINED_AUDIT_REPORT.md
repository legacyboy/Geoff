# Geoff DFIR Framework — Combined Evidence Audit Report

**Date:** 2026-05-24  
**Auditors:** Claude (Sonnet 4.6) + Qwen 3.5 (397B Cloud)  
**Merged by:** Steve4  
**Sources:** SIFT VM `/home/sansforensics/Geoff/src/`, local git, EVIDENCE_AUDIT.md, NAS inventory

---

## Executive Summary

Two independent agents reviewed Geoff's evidence processing pipeline end-to-end. Both found the same core issues and reached the same conclusions independently. The combined findings fall into three tiers:

**CRITICAL (fix now):** Offset/mount architecture is fundamentally broken — two competing code paths that disagree, ewfmount called 2-3× per image with FUSE leaks, checkpoint caching of wrong offsets, and the whole "mount then walk" approach is more fragile than TSK-direct.

**HIGH (fix next):** Disk images from archives silently lost to `other_files`, RAR never extracted, header analysis capped at 20 files, chip-off images get no mobile analysis, encrypted archives fail silently, pipeline order wrong (discover before extract).

**MEDIUM (fix after):** No recursive archive extraction, PCAP analysis shallow, LOG files misrouted, IoT evidence has no toolchain, mobile playbook runs all OS steps blindly, dual REMnux redundancy.

**Bottom line:** 22 of 28 NAS evidence directories have never been processed. The 5 quick wins below would make 8 of those processable immediately.

---

## CRITICAL: Offset Detection & Mount Failure Cascade

*Both agents flagged this as the #1 systemic problem. Findings merged below.*

### The Root Cause

There are **two parallel offset detection code paths that disagree with each other**:

1. **`_detect_partition_offsets()`** (`geoff_discovery.py:402-820`) — called during Phase 1b, tries: ewfmount+mmls → TSK specialist → direct mmls → LLM heal → COMMON_LEGACY_OFFSETS [2048, 63, 0, 32256]
2. **Inline pipeline detection** (`pipeline_phases.py:1022-1059`) — runs independently, tries: TSK specialist → direct mmls → LLM heal → hardcoded 63

The pipeline **ignores** whatever `_detect_partition_offsets()` found and runs its own detection. When these disagree:
- Pipeline falls back to offset **63** (MBR legacy)
- `_detect_partition_offsets` falls back to **2048** (GPT standard)
- **One of them is always wrong for any given image**, and whichever runs second wins

### Why It Keeps Breaking

**1. Checkpoint caching masks errors.** If a prior run cached wrong offset 63, all subsequent runs reuse it from checkpoint. The user reruns thinking it'll fix itself, but the cached wrong offset persists forever.

**2. Only one offset stored per image.** `image_offsets` is `{image_path: start_sector}` — dual-boot or multi-partition images get only the first partition. The second partition's evidence is silently lost.

**3. The fallback chain gives up too early.** When mmls fails, Geoff guesses [2048, 63, 0]. It never tries signature-based scanning (`sigfind` for NTFS boot sectors, EXT superblocks). It never tries `fsstat` to validate an offset before committing to it. It just picks a number and hopes.

**4. ewfmount is called 2-3× per image.** `_detect_partition_offsets` mounts via ewfmount, runs mmls, forgets to clean up. `_mount_and_discover` mounts again at a different temp dir. VSS adds yet another mount. FUSE handles leak, stale dirs accumulate in /tmp, eventually hitting "too many open fuse devices."

**5. The mount-then-walk approach is fundamentally fragile.** SIFT's NTFS-3G often fails on corrupted or feature-rich NTFS volumes. When mount fails, Geoff falls back to `fls` (TSK direct) anyway — so why mount at all? Mount is a convenience for tools that need a filesystem path (exiftool, clamav), not a prerequisite for forensic analysis.

### Recommended Fix

| Fix | Effort | Impact |
|-----|--------|--------|
| **Unify offset detection into ONE function** — remove inline detection from pipeline_phases.py, always call `_detect_partition_offsets()` | 1-2 days | Eliminates conflicting offsets |
| **Store ALL partition offsets** — change to `{image_path: [sector1, sector2, ...]}` | 1 day | Multi-partition coverage |
| **Add signature-based scanning** — use `sigfind` for NTFS/EXT/HFS signatures as a real detection strategy, not a guess | 1 day | Data-driven fallbacks |
| **Validate offsets with fsstat before committing** — quick check: does the filesystem respond at this offset? | 0.5 day | No more silent misalignment |
| **Add `_guess: true` flag to checkpoint** — on rerun, invalidate guessed offsets and retry | 0.5 day | No cached bad offsets |
| **Cache ewfmount per image** — mount once, reuse for all TSK ops, unmount once | 1 day | No FUSE exhaustion |
| **Default to TSK-direct, mount only when needed** — fls/icat work on raw E01, no mount required | 3-5 days | Eliminates mount failures entirely |

---

## HIGH: Disk Images Extracted From Archives Go to `other_files`

*Both agents found this independently.*

### Problem

When Geoff extracts a ZIP/7z, the re-routing switch (`pipeline_phases.py` ~line 870) only promotes `sqlite_db` and `elf/pe/macho` binaries. Everything else — including `.E01`, `.img`, `.dd` disk images — gets dumped into `other_files` and receives only REMnux analysis, not SleuthKit/Plaso/Volatility.

### Affected Cases

- **stolen-sauce**: 10 ZIPs containing DC01 and DESKTOP disk images → never analyzed as disk images
- **APT 2015**: win7-32/win7-64 ZIPs → same
- **linux-forensics**: nist-linux-scenario.zip → same
- **dfrws2017**: ZIP archives of IoT device images → same

### Fix (Quick, 15-20 lines)

Extend the re-routing switch to promote disk images, pcaps, registry hives, memory dumps:

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
```

Then re-run `DeviceDiscovery.discover()` after extraction to rebuild the device map.

---

## HIGH: RAR Archives Never Extracted

*Both agents found this independently.*

### Problem

`_detect_file_type_from_header` in `geoff_models.py` has no RAR magic bytes (`Rar!\x1a\x07`). RAR files land in `other_files`, get classified as opaque binaries, and receive only REMnux scanning. The contents are never seen.

### Affected Cases

- **memory-images**: RAR archive of memory dumps → Volatility never runs on the contents
- Any other RAR-compressed evidence on the NAS

### Fix (Quick)

Add RAR detection to `_detect_file_type_from_header`, add `rar_archive` to the extraction condition in Phase 1c, add `unrar` backend to `_extract_archive`.

---

## HIGH: Header Analysis Capped at 20 Files

*Both agents found this independently.*

### Problem

`_header_classify()` slices `inventory["other_files"][:20]`. In large cases (stolen-sauce has 10 ZIPs × hundreds of files), hundreds of files never get magic-byte reclassification. They stay in `other_files` with 0.3 confidence.

### Fix (Quick, 1 line)

Remove the `[:20]` cap. Replace with size filter:

```python
other_files = [f for f in inventory["other_files"]
               if 16 <= os.path.getsize(f) <= 1_073_741_824]
```

---

## HIGH: Chip-Off Images Get No Mobile Analysis

*Both agents found this independently.*

### Problem

`mobile-chipoff` contains HTC phone raw NAND dumps (`.img`). These get classified as `disk_images` (correct by extension). But PB-SIFT-021 (Mobile Analysis) only triggers on `inventory["mobile_backups"]`. The pipeline runs standard disk analysis: mmls fails (no MBR/GPT on raw NAND), fls fails, carving fires. No YAFFS2/UBIFS analysis, no ALEAPP, no mobile-specific SQLite recovery.

### Fix

**Quick option:** Path-context heuristics in `_fast_classify` — if `.img` is in a directory named "chipoff", "mobile", "phone", "htc", classify as `mobile_backups`.

**Better option:** Add `chip_off_images` inventory type + PB-SIFT-021 trigger on that type + NAND forensics specialist using YAFFS2/UBI tools.

---

## HIGH: Encrypted Archives Fail Silently

*Claude identified this; Qwen's report mentions archive extraction failures generally.*

### Problem

Password-protected archives fail extraction, but the failure is logged as a generic "extraction failed" warning. No distinction between encryption and corruption. No attempt to try common malware passwords ("infected", "virus", "malware"). No cross-reference with memory dumps for potential passwords.

### Fix

1. Parse extraction errors for encryption signals ("wrong password", "encrypted", "CRC failed")
2. Log as `"encrypted_archive_found"` finding with HIGH severity
3. Try hardcoded list of common malware-distribution passwords
4. If memory dumps present, extract strings and try as passwords

---

## HIGH: Linear Pipeline Order Wrong — Discover Before Extract

*Both agents flagged this as architectural.*

### Problem

Current: `classify → discover devices → extract archives → queue playbooks → execute`

Device discovery runs BEFORE archive extraction. The device map is built on the archive files, not their contents. Phase 1f patches the map but incompletely — device type, OS type, and evidence types are all derived from the pre-extraction inventory.

Correct: `classify → extract archives (recursive) → re-classify → discover devices → queue playbooks → execute`

### Fix

Architectural: Separate ingestion (scan, extract, classify, discover) from analysis (playbooks, timeline, correlation, report). Make ingestion idempotent and re-runnable.

---

## MEDIUM: No Recursive Archive Extraction

*Both agents found this independently.*

### Problem

Phase 1c uses a single-pass loop. Extracted files appended to `other_files` during the loop are never visited. Nested archives (ZIP→ZIP, tar.gz→E01, 7z→.img) are never extracted.

### Fix

Replace with work queue pattern (`deque`), cap recursion at 3-4 levels, add max depth and max expansion size guards.

---

## MEDIUM: PCAP Analysis Shallow / PB-SIFT-036 Missing

*Both agents found this independently.*

### Problem

- `PB-SIFT-036` (PCAP Network Forensics) is listed in `PLAYBOOK_NAMES` but NOT defined in `PLAYBOOK_STEPS`
- `PB-SIFT-011` (Web Shell) triggers on pcaps but has no pcap steps
- No JA3/JA3S TLS fingerprinting, no Zeek/Suricata integration, no C2 beacon detection
- `network-forensics` directory (3 pcaps) has never been processed

### Fix

Define PB-SIFT-036 in `PLAYBOOK_STEPS` with deep pcap analysis. Fix PB-SIFT-011 trigger. Add C2 beacon detection specialist.

---

## MEDIUM: LOG Files Misrouted

*Claude identified this specifically.*

### Problem

`.log` files land in `other_files`. The `syslogs` category only matches exact filenames (`syslog`, `auth.log`, `kern.log`, etc.). Application logs, IIS logs, Apache logs, custom logs get zero log-specific analysis (no IOC extraction, no timeline contribution, no pattern matching).

### Fix

Add `.log` extension and common log name patterns to `_fast_classify`. Add IOC extraction step to PB-SIFT-013.

---

## MEDIUM: IoT Evidence Has No Toolchain

*Both agents identified this.*

### Problem

6 IoT devices in `google-drive-case` (Arlo, Echo, iSmartAlarm, Samsung TV, Wink hub, network). Device discovery creates entries correctly, but `_enrich_device` only handles Windows/Linux/macOS/iOS/Android. IoT gets `os_type: "unknown"` and runs Windows-centric playbooks.

### Fix

Add IoT device detection in `_enrich_device`. Add PB-SIFT-034 for IoT/embedded forensics (binwalk, syslog parsing, strings scan).

---

## MEDIUM: Mobile Playbook Runs All iOS + Android Steps Blindly

*Claude identified this specifically.*

### Problem

PB-SIFT-021 lists ~35 iOS steps + ~15 Android steps under `mobile_backups`. All run regardless of OS. Device discovery detects `os_type` but the playbook executor doesn't filter by it.

### Fix

Split into `mobile_ios_backups` / `mobile_android_backups` evidence type keys, or add `os_type` gate to playbook executor.

---

## MEDIUM: ewfmount Mount-Twice Pattern & Resource Leak

*Qwen identified this in depth; Claude touched on it via the offset/mount issue.*

### Problem

ewfmount called 2-3× per EWF image at different temp dirs. Cleanup via `fusermount -u` fails silently if handles are still open. No verification of unmount. Stale dirs accumulate → FUSE exhaustion.

### Fix

Cache ewfmount per image at a stable path. Reuse for all TSK ops. Unmount once. Verify unmount success. Use `fusermount -uz` (lazy) with retry.

---

## MEDIUM: Self-Healing Wasteful for Trivial Errors

*Qwen identified this.*

### Problem

Every mount/offset failure triggers an LLM call (3-10s). Common errors like "wrong fs type" and "no FILE magic" have deterministic fixes (try next offset). The LLM is wasteful here.

HealCache uses file-based cache with no invalidation — a wrong LLM diagnosis gets cached forever across cases.

### Fix

Add deterministic fix strategies for common mount/offset errors to `classify_error_fast()`. Add case-specific cache key + TTL to HealCache. Don't block pipeline on healing — queue and continue.

---

## LOW: No ADS, Steganography, or Alternate Content Detection

*Claude identified this.*

No ADS enumeration (`fls -a`, `icat -a`), no stego tools (stegseek, zsteg), no polyglot file handling. PB-SIFT-012 (Anti-Forensics) doesn't include these.

## LOW: Dual REMnux Analysis on `other_files`

*Claude identified this.*

PB-SIFT-017 and PB-SIFT-025 both run ~7 overlapping tools on `other_files`. Deduplicate.

---

## Quick Wins (<50 lines, HIGH impact)

Implement these five changes first:

1. **Remove the `[:20]` cap** in `evidence_classifier.py` `_header_classify()`
2. **Add RAR magic bytes** to `_detect_file_type_from_header` and extraction condition
3. **Promote extracted disk images** to `inventory["disk_images"]` in Phase 1c routing
4. **Define PB-SIFT-036** in `PLAYBOOK_STEPS` (pcap deep analysis)
5. **Fix PB-SIFT-011 trigger** — remove pcap trigger or add pcap steps

---

## Cases That Become Processable After Quick Wins

| Case | Current | After Quick Wins |
|------|---------|-----------------|
| stolen-sauce | NO (ZIPs → other_files) | YES (#1 + #3) |
| APT 2015 | NO (ZIPs → other_files) | YES (#3) |
| memory-images | NO (RAR never extracted) | YES (#2) |
| mobile-chipoff | NO (no mobile analysis) | YES (after chip-off fix) |
| network-forensics | NO (PB-SIFT-036 missing) | YES (#4) |
| hacking-case | PARTIAL (LOG misrouted) | IMPROVED |
| linux-forensics | NO (ZIP → other_files) | YES (#3) |
| dfrws2017 | NO (ZIPs → other_files) | YES (#3) |

---

## Priority Order

| Priority | Issue | Effort |
|----------|-------|--------|
| **P0** | Unify offset detection into one function | 1-2 days |
| **P0** | Fix ewfmount resource leak / mount-twice | 1 day |
| **P1** | Add sigfind-based offset scanning | 1 day |
| **P1** | Default to TSK-direct, mount only when needed | 3-5 days |
| **P1** | Promote extracted disk images + recursive extraction | 1 day |
| **P1** | Add RAR extraction | 0.5 day |
| **P1** | Remove header cap at 20 | 0.5 day |
| **P2** | Chip-off mobile analysis | 1 day |
| **P2** | Define PB-SIFT-036 + fix PB-SIFT-011 | 0.5 day |
| **P2** | Log file classification + IOC extraction | 0.5 day |
| **P2** | Encrypted archive detection + common passwords | 1 day |
| **P2** | Add deterministic fallback to self-heal | 0.5 day |
| **P3** | IoT device detection + PB-SIFT-034 | 1-2 days |
| **P3** | Mobile OS-aware playbook filtering | 1 day |
| **P3** | ADS/stego detection | 1 day |
| **P4** | Architectural: iterative pipeline (extract → re-classify → discover) | 3-5 days |

---

*Report merged from independent Claude (Sonnet 4.6) and Qwen 3.5 (397B Cloud) analyses. Both reached the same conclusions on all critical findings.*