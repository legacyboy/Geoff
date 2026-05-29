# Geoff DFIR Framework — Prioritized Implementation Plan

**Date:** 2026-05-24  
**Author:** Steve4  
**Based on:** COMBINED_AUDIT_REPORT.md + EVIDENCE_AUDIT_CLAUDE.md + GEOFF_SYSTEMIC_AUDIT.md  
**Strategy:** Dan's 4-phase approach — scan → extract → dual-pass images → merge results  
**Priority:** Quick wins first, then structural fixes in dependency order

---

## Strategy Alignment: Dan's 4-Phase Plan vs. 15 Audit Findings

Dan's plan reframes the entire pipeline:

```
Phase 1: Scan → classify everything by extension + header magic bytes
Phase 2: Extract archives (ZIP, RAR, 7z, tar.gz) recursively, re-classify
Phase 3: Process images BOTH ways:
  a) Mount → filesystem-level (RegRipper, Plaso, clamav)
  b) Direct TSK → corrupt mounts, deleted files, hidden data
Phase 4: Merge results — two methods catch different things
```

This is fundamentally the right architecture. The current pipeline does a weak version of this with the order swapped (discover before extract) and only one image-processing path (mount-or-fallback). Below is a remapping of every audit finding to this plan, with effort estimates.

---

## Finding Remapping

| Audit Finding | Under This Plan | Effort | Phase |
|---|---|---|---|
| F1: Disk images from archives → other_files | Becomes irrelevant — Phase 2 extraction re-routes all extracted content via unified header scan | 0 (resolved by Phase 2) | 2 |
| F2: RAR never extracted | Phase 2 sub-task — add RAR header detection + extraction | 0.5 hr (quick win) | 2 |
| F3: No recursive archive extraction | Phase 2 sub-task — work queue pattern with depth guards | 2 hr | 2 |
| F4: Header analysis capped at 20 | Phase 1 sub-task — remove cap, size filter instead | 0.25 hr (quick win) | 1 |
| F5: Chip-off → no mobile analysis | Phase 1 sub-task — path-context heuristics classify chip-off as mobile | 1 hr (quick win) | 1 |
| F6: PB-SIFT-011 pcap trigger wrong | Phase 4 sub-task — fix playbook triggers + define PB-SIFT-036 | 1 hr | 4 |
| F7: LOG files misrouted | Phase 1 sub-task — add .log/.LOG extension + name patterns to syslog classification | 0.5 hr (quick win) | 1 |
| F8: Encrypted archives fail silently | Phase 2 sub-task — detect encryption, try common passwords, flag analyst | 2 hr | 2 |
| F9: No ADS/stego detection | Phase 4 sub-task — new playbook steps for ADS + stego tools | 4 hr | 4 |
| F10: Mobile PB-SIFT-021 runs all steps | Phase 4 sub-task — split iOS/Android keys, gate by os_type | 3 hr | 4 |
| F11: IoT has no toolchain | Phase 4 sub-task — add IoT detection + PB-SIFT-034 | 6 hr | 4 |
| F12: PB-SIFT-036 undefined | Phase 4 sub-task — define in PLAYBOOK_STEPS | 0.5 hr (quick win) | 4 |
| F13: Multi-host correlation incomplete | Phase 4 sub-task — extend trigger, wire HostCorrelator | 4 hr | 4 |
| F14: Pipeline order wrong (discover before extract) | **Becomes the key refactor** — iterative: extract → classify → discover. This IS the new pipeline. | 1-2 days | 2 |
| F15: Dual REMnux on other_files | Phase 4 sub-task — deduplicate PB-SIFT-017 and PB-SIFT-025 | 0.5 hr (quick win) | 4 |
| CRIT-1: Offset detection dual paths | **Resolved by Phase 3 design** — TSK-direct handles EWF natively, mount is optional. Unify into `_detect_partition_offsets()` only. | 2 days | 3 |
| CRIT-2: ewfmount mount-twice + leak | **Resolved by Phase 3 design** — single ewfmount per image, cache + reference count | 1 day | 3 |
| HIGH-1: NTFS-on-SIFT reliability | **Resolved by Phase 3** — TSK-direct first, mount only for tools that need paths. Try ntfs3 kernel module. | 1 day | 3 |
| HIGH-2: Mount+Walk vs TSK Direct | **IS Phase 3** — hybrid: TSK-direct listing + selective extraction, mount only when required | 3-5 days | 3 |
| HIGH-3: Classification blind spots (PE/ELF etc.) | Phase 1 sub-task — add dedicated evidence types + second-pass MIME classification | 3 hr | 1 |
| MED-1: Self-heal LLM waste | Phase 3 sub-task — deterministic fallbacks for common errors before LLM, cache TTL | 1 day | 3 |
| MED-2: Mobile shallow (.ab, iOS backup) | Phase 4 sub-task — Android Backup extractor, iOS backup parser | 3 hr | 4 |
| MED-3: PCAP structured analysis | Phase 4 sub-task — HTTP objects, TLS certs, DNS JSON | 2 hr | 4 |
| LOW: HostCorrelator dead code | Phase 4 sub-task — wire into pipeline | 1 day | 4 |
| LOW: Nested archive extraction | Phase 2 sub-task — deque work queue with depth cap | covered by F3 | 2 |

---

## A. Quick Wins (Can Do Today, <1hr Each)

These are high-impact, minimal-risk changes that fix real evidence loss immediately.

### QW1. Remove header cap — `evidence_classifier.py` (Finding 4)
**Effort:** 15 min  
**Change:** Replace `other_files[:20]` with size filter `16 <= size <= 1GB`  
**Impact:** Registry hives, evtx, disk images beyond position 20 get reclassified correctly

### QW2. Add RAR extraction — `geoff_models.py` + `pipeline_phases.py` (Finding 2)
**Effort:** 30 min  
**Changes:**
- Add RAR magic bytes to `_detect_file_type_from_header()`: `b'Rar!\x1a\x07\x00'`, `b'Rar!\x1a\x07\x01'`
- Add `"rar_archive"` to extraction condition in Phase 1c
- Add `unrar x -y` backend to `_extract_archive()`
**Impact:** `memory-images` RAR becomes processable (Volatility can run)

### QW3. Fix PB-SIFT-011 trigger — `geoff_config.py` (Finding 6)
**Effort:** 15 min  
**Change:** Remove `if inventory["pcaps"]` trigger for PB-SIFT-011 (Web Shell). Web shells are host-detected, not pcap-detected.

### QW4. Define PB-SIFT-036 in PLAYBOOK_STEPS — `geoff_config.py` (Finding 12)
**Effort:** 30 min  
**Change:** Add full pcap playbook definition with analyze_pcap, extract_http, extract_flows, extract_dns steps  
**Impact:** `network-forensics` case (3 pcaps) becomes processable

### QW5. Add .log extension to syslog classification — `evidence_classifier.py` (Finding 7)
**Effort:** 15 min  
**Change:** Add `{'.log', '.LOG'}` to log detection + name patterns like `access_log`, `error_log`  
**Impact:** SCHARDT.LOG in hacking-case gets IOC extraction instead of radare2 on a text file

### QW6. Deduplicate REMnux playbooks — `geoff_config.py` (Finding 15)
**Effort:** 15 min  
**Change:** Make PB-SIFT-025 run only tools NOT in PB-SIFT-017, or merge and gate  
**Impact:** Saves ~50% runtime on `other_files` processing

### QW7. Chip-off path-context heuristics — `evidence_classifier.py` (Finding 5)
**Effort:** 30 min  
**Change:** In `_fast_classify`, if `.img` in a dir named `chipoff`, `mobile`, `phone`, `htc`, `android`, reclassify as `mobile_backups`  
**Impact:** `mobile-chipoff` NAND dumps get ALEAPP/iLEAPP/YAFFS2 analysis

### QW8. Add PE/ELF/Mach-O evidence type — `geoff_config.py` + `evidence_classifier.py`
**Effort:** 45 min  
**Change:** Add `executables` inventory key. Route PE/ELF/Mach-O headers there. Add YARA scan playbook step.  
**Impact:** Malware currently invisible in `other_files` gets PE analysis (imports, sections, compile timestamp)

### Total QW time: ~3 hours

---

## B. Phase 1 — Unified Scan + Extract Pipeline Overhaul (1-3 Days)

The goal: **Make Phase 1 idempotent, comprehensive, and re-runnable.**

### Current state (broken):
```
classify → discover → extract → queue → execute
```
Discovery runs BEFORE extraction. The device map is built on archive files, not their contents.

### Target state:
```
scan → (classify → extract → re-classify)ⁿ → discover → queue → execute
```
The inner loop runs until no new archives found (or max depth reached). Only then does discovery run.

### B1. Separate ingestion from analysis
**Effort:** 1 day  
**Change:**
- Move ingestion phases (1a-1d) into a standalone `run_ingestion()` function
- Make it idempotent: re-running adds new evidence without trashing old classifications
- Store ingestion state in a persistent JSON manifest (not ephemeral checkpoints)
- Analysis phases (playbooks, timeline, correlation, report) consume the manifest

### B2. Fix pipeline ordering — discovery after extraction (Finding 14)
**Effort:** 1 day  
**Change:**
- Move `DeviceDiscovery.discover()` call to after archive extraction and re-classification
- Remove the Phase 1f band-aid that partially-patches device maps
- The device map is now built from the complete, post-extraction inventory

### B3. Add recursive archive extraction with guardrails (Finding 3)
**Effort:** 3-4 hours  
**Change:**
- Replace single-pass loop with `deque` work queue
- After extracting an archive, scan extracted files for further archives
- Push new archives onto the queue, up to max depth 4 and max total size 50GB
- Track extracted archive checksums to prevent re-extraction on rerun
- ZIP bomb guard: abort if growth ratio > 100× or time exceeded

### B4. Add comprehensive header-type classification (Finding 5 black hole)
**Effort:** 3 hours  
**Change:**
- Remove the 20-file cap (QW1)
- Add MIME-type second pass via `file -b` for all files still in `other_files`
- Dedicated evidence types for: executables, images, configs, crypto, shell artifacts, prefetch, $MFT
- Header-based detection for: AmCache, SRUM database, $MFT (FILE signature), Prefetch (.pf)

### B5. Add encrypted archive handling (Finding 8)
**Effort:** 3 hours  
**Change:**
- Parse extraction errors for encryption vs. corruption signals
- Log `"encrypted_archive_found"` with HIGH severity — flag analyst
- Try hardcoded malware-distribution passwords list
- If memory dumps present, run FLOSS strings and try as passwords
- Don't block pipeline on encrypted archives — queue finding and continue

### B6. Encrypted archive dictionary attack
**Effort:** 2 hours  
**Change:** As above — includes `MALWARE_ARCHIVE_PASSWORDS` list, error parsing, and FLOSS cross-ref

### Total Phase 1 time: 2-3 days

---

## C. Phase 2 — Dual-Pass Image Processing: Mount + TSK-Direct (3-5 Days)

This is the big one. The entire image processing architecture gets rebuilt around Dan's insight: **process every image both ways, merge results.**

### C1. TSK-Direct: The Primary Path
**Effort:** 2-3 days  
**Why:** TSK handles EWF natively, works on corrupted NTFS, needs no sudo mount, no FUSE leaks

**Implementation:**
```
For each E01/IMG/DD at each valid offset:
  1. mmls -o <offset>  → get partition layout
  2. fls -r -m / -o <offset>  → full filesystem listing with timestamps, inodes, sizes (2-5 min for 500GB)
  3. From listing, batch-extract key artifacts via icat:
     - Registry hives (SOFTWARE, SYSTEM, SAM, SECURITY, NTUSER.DAT)
     - Event logs (*.evtx)
     - Browser SQLite (history, cookies, logins)
     - Prefetch files (*.pf)
     - $MFT, $J, $LogFile, $Secure
     - AmCache.hve
     - SRUDB.dat
  4. Run analysis on extracted artifacts
  5. Also save the full fls listing as structured JSON (path, size, mtime, atime, ctime, crtime, inode)
```

**Key design decisions:**
- Use `fls -r -m /` (machine-readable) for the listing — it's the fastest way to enumerate everything
- Extract files to `CASES_WORK_DIR/tsk_extracts/<image_hash>/<partition_offset>/` by artifact type
- Store virtual paths as `image::image_hash::partition::path` for cross-referencing with mount results
- Use `fls -d` after walk to enumerate deleted files — these are mount-invisible

**Benefit:** This path NEVER fails for forensically valid images. TSK handles EWF, RAW, AFF. No mount required. No sudo. No FUSE leaks. Fast failure on wrong offset (seconds).

### C2. Mount: The Secondary Path (Only When Needed)
**Effort:** 1 day  
**When:** Only for tools that need real filesystem paths: RegRipper (expects mounted hive path), Plaso/log2timeline (prefers paths), ClamAV (scans real files)

**Implementation:**
```
For each partition that TSK successfully listed:
  1. Try mount via:
     a. ewfmount + mount -t ntfs3 -o ro,loop,offset=X (kernel ntfs3 driver — most reliable)
     b. ewfmount + mount -t ntfs-3g -o ro,loop,offset=X (user-space, fallback)
     c. ewfmount + mount -o ro,loop,offset=X (kernel auto-detect, least reliable)
  2. If mount succeeds:
     - Run RegRipper on mounted registry hives
     - Run Plaso on mounted paths
     - Run ClamAV for real-time scanning
     - Run tools that do os.walk/Path.iterdir internally
  3. If mount fails:
     - Run RegRipper on TSK-extracted hives (icat copies work)
     - Run Plaso on TSK-extracted evtx files
     - Log "mount unavailable, using TSK artifacts" — this is NOT a pipeline failure
```

**Key design decisions:**
- Mount is NOT a prerequisite. The pipeline should never block on mount failure.
- Mount is a value-add. If it works, you get better tool outputs. If it fails, TSK artifacts are already staged.
- Single ewfmount per image at a stable path: `CASES_WORK_DIR/ewf_mounts/<image_hash>/`
- Reference-counted: unmount only when all partition mounts are done

### C3. Fix Offset Detection (CRIT-1, CRIT-2)
**Effort:** 2 days  
**Changes:**
- **Unify into ONE function** — remove inline detection from `pipeline_phases.py`. Always call `_detect_partition_offsets()`.
- **Store ALL offsets** — `{image_path: [sector1, sector2, ...]}` not `{image_path: sector1}`
- **Signature-based scanning** — `sigfind` for NTFS $MFT mirror (`0x!BOOT`) and EXT superblock (`0x53EF`)
- **Validate with fsstat** — before committing to an offset, run `fsstat -o X <image>` and check for `File System: NTFS` or `File System: Ext`

### C4. Fix ewfmount Architecture (CRIT-2)
**Effort:** 1 day  
**Changes:**
- Mount once per image at stable path
- Share mount dir across all TSK operations (mmls, fls, icat on ewf1)
- Unmount once at cleanup
- Verify unmount success — check `/proc/mounts`, retry with `fusermount -uz`
- Reference counting: `{image_hash: (mount_dir, refcount)}`
- Skip EWF for mmls/fls on E01 files (TSK handles natively) — eliminates the first ewfmount entirely

### C5. Merge Results — Cross-Reference
**Effort:** 1 day  
**Implementation:**
```
For each image, for each partition:
  tsk_listing = fls -rm (TSK-direct path listing)
  mount_listing = os.walk(mount_point) if mount succeeded

  files_in_both = tsk_listing ∩ mount_listing  (paths that exist both ways)
  files_tsk_only = tsk_listing - mount_listing  (deleted files, corrupt mount, hidden streams)
  files_mount_only = mount_listing - tsk_listing  (should be empty for healthy images)

  For files_tsk_only:
    - Extract via icat, analyze separately
    - Flag as "mount-invisible: deleted/alternate-stream/hidden"
    - These are priority targets for threat hunting

  For files_in_both:
    - Use mount path for tools that need paths
    - Use TSK metadata (inode, flags) to detect ADS or other anomalies
```

**Deliverable:** `merge_report.json` per case — shows what each method caught that the other missed. This is the forensic value Dan is looking for — knowing what you'd miss with just mount or just TSK.

### Total Phase 2 time: 3-5 days

---

## D. Phase 3 — Self-Heal Fixup (1-2 Days)

Make the self-healing system deterministic, fast, and non-blocking.

### D1. Deterministic fallbacks for common errors
**Effort:** 1 day  
**Change:**
- `classify_error_fast()` currently handles ~6 error classes
- Extend it to cover: `"Record 0 has no FILE magic"`, `"Invalid superblock"`, `"wrong fs type"`, `"no such device"`
- All of these have the same fix: try offset 2048 → 63 → 0 → try without offset
- No LLM call needed for these — they're trivially fixable

### D2. HealCache invalidation + TTL
**Effort:** 3 hours  
**Change:**
- Add case-specific cache key: `heal_cache[case_id][error_hash]`
- 24h TTL on cached decisions
- `_guess: true` flag on guessed offsets — invalidate cache on rerun
- If LLM diagnosis was "try offset 63" and fsstat validates it, store as confident (`_guess: false`)

### D3. Non-blocking healing
**Effort:** 3 hours  
**Change:**
- Queue heal attempts, don't block pipeline
- Continue processing other evidence while LLM diagnoses
- Apply healed result when available (or on next pipeline pass)
- Analyst-visible: "Heal pending: awaiting LLM diagnosis for image X"

### Total Phase 3 time: 1-2 days

---

## E. Phase 4 — Remaining Gaps (2-4 Days)

Everything that doesn't fit into the core pipeline refactor. These are important but don't block the structural changes.

### E1. Mobile analysis overhaul (Findings 5, 10)
**Effort:** 4 hours  
**Changes:**
- Add Android Backup (.ab) parser — detect `ANDROID BACKUP` header, decompress via `abe` or built-in zlib
- Integrate iOS backup parser — at minimum extract Manifest.db and map SHA1 filenames
- Split PB-SIFT-021 into `mobile_ios_backups` / `mobile_android_backups` evidence keys
- Gate playbook executor by `dev["os_type"]`

### E2. IoT device detection + playbook (Finding 11)
**Effort:** 6 hours  
**Changes:**
- Add IoT indicators to `_enrich_device()`: firmware, nvram, squashfs, ubifs, echo, alexa, binwalk signals
- Create PB-SIFT-034 for IoT/embedded forensics: binwalk, strings, syslog parse, firmware unpack
- 6 IoT devices in google-drive-case become processable

### E3. PCAP deep analysis (Finding 12, Systemic Finding 7)
**Effort:** 3 hours  
**Changes:**
- Define PB-SIFT-036 fully in PLAYBOOK_STEPS
- Add: HTTP object extraction, TLS certificate dump, DNS JSON output, credential extraction
- Add C2 beacon detection: periodic small connections, DGA patterns, low-TTL DNS
- Wire PB-SIFT-036 queuing from `inventory["pcaps"]`

### E4. ADS, steganography detection (Finding 9)
**Effort:** 4 hours  
**Changes:**
- Add `fls -a` step to PB-SIFT-012 for ADS enumeration on NTFS
- Add `icat -a` for ADS extraction
- Add stego detection tools: stegseek, zsteg, binwalk for embedded content
- Run on images in `other_files` + mobile backups (photos)

### E5. Wire HostCorrelator into pipeline (Systemic Finding 8)
**Effort:** 4 hours  
**Changes:**
- Build unified timeline from all per-device playbook outputs
- Normalize timestamps, event types, severities
- Call `HostCorrelator.correlate()` with device map and user map
- Add to Phase 4 or Phase 5 of the pipeline (post-playbook, pre-report)

### E6. Fix LOG routing + IOC extraction (Finding 7)
**Effort:** 2 hours  
**Changes:**
- After .log classification, add IOC extraction step to PB-SIFT-013
- Extract IPs, domains, file paths, registry paths, user names from log content
- Feed IOCs into timeline for cross-reference with other devices

### E7. Deduplicate REMnux analysis (Finding 15)
**Effort:** 30 min  
**Change:** Already a quick win (QW6), but list here for completeness

### Total Phase 4 time: 2-4 days

---

## Total Project Timeline

| Phase | Description | Effort | Dependencies |
|---|---|---|---|
| **QW** | Quick wins (8 items) | ~3 hours | None — can start immediately |
| **P1** | Unified scan + extract pipeline | 2-3 days | QW1-5, QW8 (components leveraged) |
| **P2** | Dual-pass image processing | 3-5 days | P1 (extract pipeline complete) |
| **P3** | Self-heal fixup | 1-2 days | P2 (image processing stable) |
| **P4** | Remaining gaps | 2-4 days | P2 (core architecture settled) |
| | **Total** | **9-14 days** | |

### Parallel Work That's Safe:
- QW1-8: all independent, can be done in any order
- E6 (LOG routing) + E7 (REMnux dedup): independent of any phase
- P4 items: independent of each other once P2 is done

### Critical Path:
```
QW1-8 → P1 (extract pipeline) → P2 (image processing) → P3 (self-heal) + P4 (gaps)
```

P3 and P4 can run in parallel once P2 is complete.

---

## Cases That Become Fully Processable

| Case | Current | After QW | After P1 | After P2 | After P4 |
|------|---------|----------|----------|----------|----------|
| stolen-sauce | ❌ | ❌ | ✅ | ✅ | ✅ |
| APT 2015 | ❌ | ❌ | ✅ | ✅ | ✅ |
| memory-images | ❌ | ✅ (RAR) | ✅ | ✅ | ✅ |
| mobile-chipoff | ❌ | ✅ (path heuristic) | ✅ | ✅ | ✅ |
| network-forensics | ❌ | ✅ (PB-SIFT-036) | ✅ | ✅ | ✅ |
| hacking-case | ⚠️ partial | ✅ (LOG route) | ✅ | ✅ | ✅ |
| linux-forensics | ❌ | ❌ | ✅ | ✅ | ✅ |
| dfrws2017 | ❌ | ❌ | ✅ | ✅ | ✅ |
| google-drive-case | ❌ | ❌ | ❌ | ❌ | ✅ (IoT) |

---

## Key Architectural Decisions Enshrined

1. **TSK-direct is the primary path, mount is optional.** TSK handles EWF natively. No sudo mount required for listing/extraction. Mount exists only for tools that need real filesystem paths.

2. **Extraction before discovery.** Always extract first, classify contents, THEN build device map. No more Phase 1f band-aid patches.

3. **Iterative ingestion loop.** (scan → extract → classify)ⁿ until no new archives. Idempotent and re-runnable.

4. **Dual outputs for every image.** TSK listing + mount listing, merged into a delta report showing what each method caught. This is the forensic value proposition.

5. **Self-heal is fast and deterministic first, LLM second.** Common errors (wrong offset, wrong FS type) get deterministic fixes without blocking on the LLM. Heal has TTL and case-scoped cache keys.

6. **New evidence types, not overloaded `other_files`.** Executables, images, configs, crypto material all get their own inventory key and playbook path. `other_files` shrinks to what's genuinely unknown.

---

*This plan supersedes the previous priority table from COMBINED_AUDIT_REPORT.md. The audit findings remain valid; this is a reordering and restructuring around Dan's 4-phase approach.*
