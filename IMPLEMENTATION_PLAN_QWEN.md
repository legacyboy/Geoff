# Geoff DFIR Framework — Qwen Implementation Plan

**Date:** 2026-05-24  
**Author:** Qwen  
**Sources:** COMBINED_AUDIT_REPORT.md, GEOFF_SYSTEMIC_AUDIT.md, EVIDENCE_AUDIT_CLAUDE.md  
**Strategy Owner:** Dan  
**Strategy:** Scan → Extract → Process (mount + TSK-direct) → Merge

---

## Overview: How Dan's Plan Maps to the Audit Findings

Dan's greenlit plan has 4 phases:

1. **Scan** — classify everything by extension + header magic bytes
2. **Extract** — all archive types recursively, re-classify extracted contents
3. **Process both ways** — mount approach (filesystem-level) + TSK-direct (corrupt/deleted/hidden)
4. **Merge results**

Below, every finding from the three audit reports is remapped to this plan. Findings become either irrelevant, sub-tasks of a phase, or gaps the plan doesn't cover.

---

## Finding-by-Finding Remapping

### Finding A1: Two parallel offset detection paths (CRITICAL)
- **Status:** Sub-task of Phase 3 (both mount and TSK-direct need a single source of truth for offsets)
- **Phase:** Phase 3 — dual-pass image processing
- **Effort:** 1-2 days
- **Detail:** Unify `_detect_partition_offsets()` in `geoff_discovery.py` and inline detection in `pipeline_phases.py` into one function. Both mount and TSK paths call the same offset function.

### Finding A2: ewfmount mount-twice + resource leak (CRITICAL)
- **Status:** Sub-task of Phase 3 — mount approach
- **Phase:** Phase 3 — dual-pass image processing
- **Effort:** 1 day
- **Detail:** Cache ewfmount per image at stable path, reference-count handles, verify unmount. Directly supports the "mount approach" path.

### Finding A3: NTFS-on-SIFT mount reliability (HIGH)
- **Status:** Sub-task of Phase 3 — mount approach
- **Phase:** Phase 3 — dual-pass image processing
- **Effort:** 0.5 day
- **Detail:** Try ntfs-3g / ntfs3 kernel module explicitly before falling back. Detect SIFT capability at startup.

### Finding A4: Mount+walk vs TSK-direct architecture (HIGH)
- **Status:** THIS IS THE PLAN — dual-pass processing
- **Phase:** Phase 3 — dual-pass image processing
- **Effort:** 3-5 days
- **Detail:** The entire audit finding is "mount is fragile, use TSK-direct." Dan's plan says "do both." The plan subsumes this finding by making both paths coexist and merge results.

### Finding A5: Classification blind spots / `other_files` black hole (HIGH)
- **Status:** Sub-task of Phase 1 — scan
- **Phase:** Phase 1 — unified scan pipeline overhaul
- **Effort:** 2-3 days
- **Detail:** Add dedicated evidence types for executables, images, archives, logs, crypto material, filesystem metadata. MFT, $J, AmCache, Prefetch, SRUM detection.

### Finding A6: Mobile evidence — shallow coverage (MEDIUM)
- **Status:** Gap — partially covered by Phase 3
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 2-3 days
- **Detail:** Android Backup (.ab) parsing, iOS backup parser, Cellebrite UFED detection, chip-off mobile analysis. Not directly addressed by scan/extract/process pipeline.

### Finding A7: PCAP analysis shallow / PB-SIFT-036 missing (MEDIUM)
- **Status:** Sub-task of Phase 4
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 1-2 days
- **Detail:** Define PB-SIFT-036, add HTTP object extraction, TLS certificate extraction, C2 beacon detection. Not in scope of the 4-phase plan; PCAPs are a separate evidence type.

### Finding A8: Multi-host correlation incomplete (LOW)
- **Status:** Sub-task of Phase 4
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 1 day
- **Detail:** Wire HostCorrelator into pipeline. Depends on Phase 3 merge results being available.

### Finding A9: Nested archive extraction gap (LOW)
- **Status:** Sub-task of Phase 2 — extract
- **Phase:** Phase 2 — extract pipeline overhaul
- **Effort:** 0.5 day
- **Detail:** Replace single-pass loop with work queue pattern. Cap recursion at 3-4 levels.

### Finding A10: Self-heal LLM fragility (LOW)
- **Status:** Sub-task of Phase 3 — self-heal fixup
- **Phase:** Phase 3 — self-heal fixup
- **Effort:** 1 day
- **Detail:** Add deterministic fix strategies for common errors, invalidate HealCache per-case, add TTL, don't block pipeline.

### Finding C1: Disk images from archives go to `other_files` (HIGH)
- **Status:** Sub-task of Phase 2 — extract
- **Phase:** Phase 2 — extract pipeline overhaul
- **Effort:** 0.5 day
- **Detail:** Extend re-routing switch to promote disk images, pcaps, registry hives, memory dumps. Then re-run DeviceDiscovery.

### Finding C2: RAR never extracted (HIGH)
- **Status:** Sub-task of Phase 2 — extract
- **Phase:** Phase 2 — extract pipeline overhaul
- **Effort:** 0.5 day
- **Detail:** Add RAR magic bytes, extraction condition, unrar backend.

### Finding C3: No recursive archive extraction (MEDIUM)
- **Status:** Same as A9. Sub-task of Phase 2.
- **Phase:** Phase 2 — extract pipeline overhaul
- **Effort:** 0.5 day

### Finding C4: Header analysis capped at 20 files (HIGH)
- **Status:** Sub-task of Phase 1 — scan
- **Phase:** Phase 1 — unified scan pipeline overhaul
- **Effort:** 0.5 day
- **Detail:** Remove `[:20]` cap, replace with size filter (16 bytes to 1GB).

### Finding C5: Chip-off gets no mobile analysis (HIGH)
- **Status:** Gap — not covered by scan/extract/process plan
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 1 day
- **Detail:** Add chip-off image sub-type with NAND forensics tools (YAFFS2/UBI). Path-context heuristics for quick classification.

### Finding C6: PB-SIFT-011 triggered by PCaps with no PCap steps (MEDIUM)
- **Status:** Quick win — done today
- **Phase:** A — Quick wins
- **Effort:** <1 hour
- **Detail:** Remove pcap trigger from PB-SIFT-011 or add pcap steps.

### Finding C7: LOG files misrouted (MEDIUM)
- **Status:** Sub-task of Phase 1 — scan
- **Phase:** Phase 1 — unified scan pipeline overhaul
- **Effort:** 0.5 day
- **Detail:** Add `.log` extension and common log name patterns to `_fast_classify`.

### Finding C8: Encrypted archives fail silently (HIGH)
- **Status:** Sub-task of Phase 2 — extract
- **Phase:** Phase 2 — extract pipeline overhaul
- **Effort:** 1 day
- **Detail:** Distinguish encryption vs corruption errors, dictionary attack on common passwords, cross-reference memory dumps for passwords.

### Finding C9: No ADS, steganography, embedded content (MEDIUM)
- **Status:** Gap — partially covered by TSK-direct path (TSK can list ADS)
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 1-2 days
- **Detail:** Add `fls -a` / `icat -a` to TSK-direct path. Add stego tools (stegseek, zsteg, binwalk). The TSK-direct path makes ADS enumeration natural.

### Finding C10: Mobile PB-SIFT-021 runs iOS+Android steps blindly (MEDIUM)
- **Status:** Gap — covered in Phase 4
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 1 day
- **Detail:** Split PB-SIFT-021 evidence type keys or gate steps by os_type.

### Finding C11: IoT evidence has no toolchain (MEDIUM)
- **Status:** Gap
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 1-2 days
- **Detail:** Add IoT device detection in `_enrich_device`, add PB-SIFT-034 for IoT/embedded forensics.

### Finding C12: PB-SIFT-036 missing from PLAYBOOK_STEPS (MEDIUM)
- **Status:** Quick win — done today
- **Phase:** A — Quick wins
- **Effort:** <1 hour

### Finding C13: Multi-host correlation misses non-disk evidence (MEDIUM)
- **Status:** Gap
- **Phase:** Phase 4 — remaining gaps
- **Effort:** 0.5 day
- **Detail:** Extend correlation trigger to count all evidence types.

### Finding C14: Linear pipeline should be iterative after extraction (HIGH)
- **Status:** Sub-task of Phase 2 — extract
- **Phase:** Phase 2 — extract pipeline overhaul
- **Effort:** 2-3 days
- **Detail:** Separate ingestion (scan, extract, classify, discover) from analysis (playbooks, timeline, correlation, report). Make ingestion idempotent.

### Finding C15: Dual REMnux analysis on `other_files` (LOW)
- **Status:** Quick win — done today
- **Phase:** A — Quick wins
- **Effort:** <1 hour

---

## Implementation Plan

### A. Quick Wins (<1hr each, do TODAY)

These are the 5 original quick wins from the merged report plus 2 more that don't need architectural changes.

| # | Task | Finding | Lines | File |
|---|------|---------|-------|------|
| Q1 | **Remove `[:20]` cap** from `_header_classify()` — replace with size filter (16B–1GB) | C4 | 1 line | `evidence_classifier.py` |
| Q2 | **Add RAR magic bytes** to `_detect_file_type_from_header` + extraction condition + `_extract_archive` backend | C2 | ~15 lines | `geoff_models.py`, `pipeline_phases.py` |
| Q3 | **Promote extracted disk images** — extend re-routing switch in Phase 1c for E01/IMG/DD/ISO/VMDK/DMG | C1 | ~20 lines | `pipeline_phases.py` |
| Q4 | **Define PB-SIFT-036** in `PLAYBOOK_STEPS` in `geoff_config.py` (skeleton with existing specialist calls) | C12 | ~15 lines | `geoff_config.py` |
| Q5 | **Fix PB-SIFT-011 trigger** — remove `if inventory["pcaps"]` queuing or add pcap steps | C6 | 2 lines | `pipeline_phases.py` |
| Q6 | **Add LOG file classification** — `.log` extension + common log name patterns to `_fast_classify` | C7 | ~10 lines | `evidence_classifier.py` |
| Q7 | **Deduplicate REMnux analysis** — remove redundant tools from PB-SIFT-025 when PB-SIFT-017 also runs | C15 | ~5 lines | `geoff_config.py` |

**Total effort:** ~3-4 hours (one focused afternoon)  
**Impact:** Fixes the highest-severity classification/extraction bugs. Makes stolen-sauce, APT 2015, linux-forensics, dfrws2017, memory-images, network-forensics immediately processable.

---

### B. Phase 1 — Unified Scan + Extract Pipeline Overhaul (1-3 days)

This is Dan's phases 1 and 2 combined: scan everything, extract everything, re-classify.

#### B1. Add new evidence types (1 day)
- Executables (PE, ELF, Mach-O) with dedicated playbook
- Images (JPEG, PNG, GIF) for stego analysis
- Log files (application logs, IIS logs, custom logs)
- Config files, crypto material
- Filesystem metadata (MFT, $J, AmCache, Prefetch, SRUM)

**Files:** `evidence_classifier.py`, `geoff_models.py`, `geoff_config.py`  
**Dependency:** Q1 done (no cap), Q6 done (log classification)

#### B2. Nested archive extraction with work queue (0.5 day)
- Replace single-pass loop with `deque` work queue
- Cap recursion at 3-4 levels with max expansion guards

**Files:** `pipeline_phases.py` (Phase 1c)  
**Dependency:** Q2 done (RAR), Q3 done (disk image promotion)

#### B3. Encrypted archive handling (1 day)
- Distinguish encryption vs corruption errors
- Dictionary attack on common passwords
- Cross-reference memory dumps for passwords

**Files:** `pipeline_phases.py`, `geoff_discovery.py`  
**Dependency:** Q2 done (extraction backend)

#### B4. Iterative pipeline — separate ingestion from analysis (1-3 days)
- Restructure: `scan → extract (recursive) → re-classify → discover → analyze`
- Make ingestion phase idempotent with proper checkpointing
- Re-run DeviceDiscovery after extraction

**Files:** `pipeline_phases.py`, `find_evil()`  
**Dependency:** B1, B2 done

**Total effort:** 2-5 days (B4 is the variable; if we don't fully refactor the pipeline, B1+B2+B3 is ~2 days)

---

### C. Phase 2 — Dual-Pass Image Processing (3-5 days)

This is Dan's Phase 3. Both mount and TSK-direct paths run on every disk image, producing results that are merged.

#### C1. Unify offset detection into one function (1-2 days)
- Remove inline detection from `pipeline_phases.py`
- Always call `_detect_partition_offsets()` from `geoff_discovery.py`
- Store ALL partition offsets (`{image_path: [sector1, sector2, ...]}`)
- Add `_guess: true` flag for checkpoint invalidation on rerun

**Files:** `geoff_discovery.py`, `pipeline_phases.py`

#### C2. Add sigfind-based offset scanning (1 day)
- Scan for NTFS boot sector ($MFT mirror), EXT superblock, HFS volume header signatures
- Validate offsets with `fsstat` before committing
- Real detection strategy, not guess-based fallback

**Files:** `geoff_discovery.py` (`_detect_partition_offsets`)

#### C3. TSK-direct path — file listing + selective extraction (2-3 days)
- `fls -r -m /` for full timestamped directory listing
- Selective `icat` extraction of registry hives, event logs, browser SQLite
- All other files marked as `image::path` virtual path
- `fls -d` for deleted file recovery
- `fls -a` for ADS enumeration

**Files:** `geoff_discovery.py`, `sift_specialists.py`, new TSK-direct module

#### C4. Mount path — only when needed (1 day)
- Try kernel mount (ntfs-3g → ntfs3 → fls fallback)
- Cache ewfmount per image, reference-count handles
- Verify unmount success, use `fusermount -uz` with retry
- Detect SIFT's NTFS capability at startup

**Files:** `geoff_discovery.py` (`_mount_and_discover`)

#### C5. Merge results — unified inventory from both paths (1-2 days)
- Files found by TSK but not mount → mark as `[tsk_only]`
- Files found by mount but not TSK → mark as `[mount_only]`
- Files found by both → deduplicate, prefer mount path for metadata
- Deleted files → separate `[deleted]` section
- Build merged device map combining both views

**Files:** New merge module or extend pipeline phases

**Total effort:** 5-9 days (C3 is the biggest piece)

---

### D. Phase 3 — Self-Heal Fixup (1-2 days)

#### D1. Deterministic fallback strategies (0.5 day)
- `classify_error_fast()` handles common mount/offset errors deterministically
- Try offset 2048 → 63 → 0 → sigfind scan → LLM (last resort)
- No LLM call for trivial "wrong fs type" or "no FILE magic" errors

**Files:** `geoff_self_heal.py`, `geoff_critic.py`

#### D2. HealCache invalidation (0.5 day)
- Case-specific cache key
- TTL on entries (24h or version change)
- Don't block pipeline on healing — queue and continue

**Files:** `geoff_self_heal.py`, `geoff_critic.py`

#### D3. Cache ewfmount per image (0.5 day)
- Mount once at stable path (`CASES_WORK_DIR/mounts/<case>/<img>_ewf1`)
- Reuse for all TSK ops (mmls, fls, icat)
- Unmount once at cleanup, verify success

**Files:** `geoff_discovery.py` (move ewfmount out of both `_detect_partition_offsets` and `_mount_and_discover`)

**Total effort:** 1-2 days

---

### E. Phase 4 — Remaining Gaps (2-4 days)

These are findings not directly covered by the scan/extract/process plan:

#### E1. Chip-off mobile analysis (1 day)
- Add `chip_off_images` inventory type
- NAND forensics tools (YAFFS2 utils, ubi_reader)
- Path-context heuristics for classification

#### E2. Mobile iOS/Android OS-aware filtering (1 day)
- Split PB-SIFT-021 evidence type keys by OS
- Gate steps by `dev["os_type"]`

#### E3. Mobile backup parsers (0.5 day)
- Android Backup (.ab) format via `abe` or built-in zlib
- iOS backup parser (Manifest.db → SHA1 filename mapping)

#### E4. PCAP deep analysis (1-2 days)
- HTTP object extraction via `tshark --export-objects http`
- TLS certificate extraction
- DNS query logging as structured JSON
- C2 beacon pattern detection

#### E5. IoT evidence detection + playbook (1-2 days)
- `_enrich_device` IoT detection
- PB-SIFT-034 for IoT/embedded forensics (binwalk, strings, squashfs extraction)

#### E6. Multi-host correlation wiring (0.5 day)
- Wire `HostCorrelator.correlate()` into pipeline
- Build unified timeline from all playbook outputs
- Extend trigger to count all evidence types

#### E7. ADS/steganography (1 day)
- Add `fls -a` / `icat -a` to TSK-direct path (C3 covers this)
- Add stego detection tools to PB-SIFT-012 or new specialist
- Polyglot file detection

**Total effort:** 5-8 days (E4+E5 are biggest)

---

## Priority Implementation Order

```
Day 1:      [QUICK WINS] Q1-Q7 (~4 hours total)
Days 2-4:   [PHASE 1] B1 + B2 + B3 (~3 days)
Days 3-7:   [PHASE 2] C1 + C2 + C4  (parallel with Phase 1) (~3 days)
Days 5-8:   [PHASE 2] C3 (TSK-direct, biggest piece) (~3 days)  
Days 6-8:   [PHASE 3] D1 + D2 + D3 (parallel with TSK-direct) (~2 days)
Days 8-9:   [PHASE 2] C5 (merge results) (~2 days)
Days 10-14: [PHASE 4] E1-E7 (~5 days)
```

Total timeline: ~14 days for full implementation. Quick wins on day 1 unblock 6 cases immediately.

---

## What Each Phase Unlocks

| Phase | Cases Unblocked | New Capability |
|-------|----------------|----------------|
| **Quick wins** | stolen-sauce, APT 2015, linux-forensics, dfrws2017, memory-images, network-forensics | Archive extraction, RAR, disk image promotion, PB-SIFT-036 |
| **Phase 1** | registry-forensics, sans-hackathon | Recursive extraction, encrypted archives, log analysis |
| **Phase 2** | All disk-image cases with corrupt mounts | TSK-direct walk works on anything; mount adds metadata depth |
| **Phase 3** | All cases (pipeline reliability) | No more cached bad offsets, no more FUSE exhaustion |
| **Phase 4** | mobile-chipoff, google-drive-case, network-forensics deep | Mobile, IoT, PCAP, ADS, stego, cross-host correlation |

**End state:** All 28 NAS evidence directories processable, with two complementary image processing views merged into one forensic result.
