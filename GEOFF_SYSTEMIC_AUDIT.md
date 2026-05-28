# Geoff DFIR Framework — Systemic Audit Report

**Date:** 2026-05-24  
**Scope:** Core pipeline source (geoff_discovery.py, pipeline_phases.py, geoff_config.py, evidence_classifier.py, sift_specialists.py, geoff_self_heal.py, geoff_critic.py, sift_specialists_extended.py, device_discovery.py, host_correlator.py)  
**Auditor:** Steve4

---

## Table of Contents

1. [CRITICAL: Offset Detection & Mount Failure Cascade](#1-critical-offset-detection--mount-failure-cascade)
2. [CRITICAL: ewfmount — Mount-Twice Pattern & Resource Leak](#2-critical-ewfmount--mount-twice-pattern--resource-leak)
3. [HIGH: NTFS-on-SIFT Mount Reliability](#3-high-ntfs-on-sift-mount-reliability)
4. [HIGH: The "Mount + Walk" vs "TSK Direct" Architecture Question](#4-high-the-mount--walk-vs-tsk-direct-architecture-question)
5. [HIGH: Classification Blind Spots — The "other_files" Black Hole](#5-high-classification-blind-spots--the-other_files-black-hole)
6. [MEDIUM: Mobile Evidence — Shallow Coverage](#6-medium-mobile-evidence--shallow-coverage)
7. [MEDIUM: Network Evidence — PCAP as a Dead Letter](#7-medium-network-evidence--pcap-as-a-dead-letter)
8. [LOW: Multi-Host Correlation — Incomplete Surface](#8-low-multi-host-correlation--incomplete-surface)
9. [LOW: Archive Extraction — Nested Archive Gap](#9-low-archive-extraction--nested-archive-gap)
10. [LOW: Self-Healing — LLM-Driven Fragility & Cache Inconsistency](#10-low-self-healing--llm-driven-fragility--cache-inconsistency)

---

## 1. CRITICAL: Offset Detection & Mount Failure Cascade

**Location:** `geoff_discovery.py:402-820` (`_detect_partition_offsets`), `pipeline_phases.py:1001-1111` (call site), `geoff_discovery.py:820-1900` (`_mount_and_discover`)

### The Failure Pattern

This is the most frequently broken part of Geoff, and the failures cascade because:

**1a. There are two parallel offset detection code paths that don't communicate**

- `_detect_partition_offsets()` (geoff_discovery.py:402) — called during Phase 1b via `pipeline_phases.py:1001`
- BUT the **pipeline itself** also runs its own inline offset detection at `pipeline_phases.py:1022-1059` using `SLEUTHKIT_Specialist.analyze_partition_table()` directly — **this is a completely different code path** from `_detect_partition_offsets()`

The inline path in `pipeline_phases.py` is:
1. `SLEUTHKIT_Specialist.analyze_partition_table()` — uses TSK natively (may not handle EWF well)
2. Falls to direct `mmls` if specialist fails
3. Falls to LLM self-heal (`_attempt_heal` with `function="detect_partitions"`)
4. Falls to hardcoded `63` (DOS/MBR legacy)

The `_detect_partition_offsets()` path uses:
1. EWF: `ewfmount` + `mmls` on ewf1 (more reliable for EWF)
2. `SLEUTHKIT_Specialist.analyze_partition_table()` — same specialist call
3. Direct `mmls` with `-t gpt|dos|mac|bsd` fallbacks
4. LLM self-heal
5. `COMMON_LEGACY_OFFSETS = [2048, 63, 0, 32256]`

**Problem:** When pipeline Phase 1b runs, it ignores whatever `_detect_partition_offsets()` may have found previously and runs its own standalone detection. These two paths differ in their fallback order:
- Pipeline inline: default fallback = `63`
- `_detect_partition_offsets()`: default fallback = `2048` (first in `COMMON_LEGACY_OFFSETS`)

If a GPT-partitioned image (offset 2048) fails in the pipeline's inline detection path, it gets offset 63, and the subsequent mount attempt will fail with `wrong_fs_type`.

**1b. The checkpoint caching masks errors**

At `pipeline_phases.py:1005`:
```python
if _ckpt_phase_done(ckpt, "partition_offsets"):
    image_offsets = json.loads(ckpt_offsets_file.read_text())
```

If a **prior run** used offset 63 (because the EWF path failed), all **subsequent runs** reuse that wrong offset from cache. The user sees the error once and assumes it's fixed by rerunning, but the system silently uses the cached wrong offset.

**1c. Offset is stored per-image, not per-partition**

`image_offsets` is `{image_path: start_sector}` — a **single offset per image**. This means:
- Dual-boot images get only one partition detected
- GPT images with multiple data partitions only get the first one mounted
- The second partition, which may contain different evidence, is missed entirely

The `_mount_and_discover` function at line ~990 **independently re-runs mmls** to get all partitions anyway, but uses the single `image_offsets` value as the base offset. If the single cached offset is wrong, the entire partition enumeration via mmls may be misaligned too.

**1d. The fallback chain undermines itself by skipping carving**

The fallback order is:
```
ewfmount+mmls → TSK specialist → direct mmls → LLM heal → COMMON_LEGACY_OFFSETS
```

When every real detection method fails, Geoff falls back to `2048` or `63` as a guess. But the fallback **never tries to carve** — it doesn't attempt `bulk_extractor` to find filesystem metadata, doesn't scan for NTFS boot sectors at alternative offsets, doesn't use `sigfind` to locate NTFS signatures. It just picks the common offset and hopes.

If offset 2048 is wrong but mount still works (returning errors but not crashing), the filesystem walk proceeds on a misaligned mount, producing garbage file paths or missing files silently.

**1e. The inline pipeline code has a race condition in checkpoint logic**

At `pipeline_phases.py:1005-1011`:
```python
if _ckpt_phase_done(ckpt, "partition_offsets"):
    image_offsets = json.loads(ckpt_offsets_file.read_text())
    _fe_log(job_id, "  [CKPT] Skipping partition scan — loaded from checkpoint")
else:
    _ckpt_mark_phase(ckpt, "partition_offsets", "running")
    _ckpt_save(case_work_dir, ckpt)
# Next line: force empty if not checkpoint-complete
image_offsets = image_offsets if _ckpt_phase_done(ckpt, "partition_offsets") else {}
```

The `_ckpt_phase_done()` check runs **twice** — once inside the if-block, once after. If another process or error state changes the checkpoint between these two reads, `image_offsets` gets wiped to `{}` even though we just loaded valid data. The comment says "fix B-3" suggesting this was a known issue that was only partially fixed.

### Recommended Fixes

1. **Unify offset detection into one function.** The `_detect_partition_offsets()` function should be the single source of truth. Remove the duplicated inline detection from `pipeline_phases.py:1022-1059`. The pipeline should call the function, then just use the result.

2. **Store all partition offsets, not just the first.** Change `image_offsets` to `{image_path: [start_sector_1, start_sector_2, ...]}` so multi-partition images get full coverage.

3. **Add signature-based offset scanning as a real detection strategy, not a guess.** Use `sigfind` (part of TSK) to locate NTFS boot sectors ($MFT mirror), EXT superblocks, or HFS volume headers. When mmls fails entirely, this gives a data-driven fallback instead of guessing.

4. **Checkpoint invalidation:** When offset detection fails and falls back to a guess, store a `_guess: true` flag in the checkpoint. On rerun, invalidate the cache and retry detection — don't reuse a guess that was wrong.

5. **Validate offsets before proceeding.** After determining an offset, do a quick fsstat to verify the filesystem is readable at that offset. If fsstat returns garbage or "Record 0 has no FILE magic", discard and fall through to the next strategy.

---

## 2. CRITICAL: ewfmount — Mount-Twice Pattern & Resource Leak

**Location:** `geoff_discovery.py:545-605`, `820-1160`, `1700-1860`

### The Problems

**2a. ewfmount is called at least twice per EWF image**

In `_detect_partition_offsets()`:
1. `ewfmount E01 mount_dir` → run `mmls` on `ewf1` → store offset → **forget to unmount** (see resources section below)

In `_mount_and_discover()`:
2. `ewfmount E01 mount_dir` → mount the partition via `sudo mount -o ro,loop,offset=X ewf1 mount_point`
3. If step 2 fails, another `ewfmount E01 mount_dir` happens in the sleuthkit/icat fallback path
4. For EWF images with VSS: yet another `vshadowmount` + possibly `ewfmount`

Each ewfmount creates a FUSE mount (`/tmp/geoff_ewf_<pid>_<hash>`). Geoff tracks these via `_ewf_mount_dirs` and attempts cleanup at the end of `_detect_partition_offsets()` (line 747), but:

**2b. ewfmount cleanup is unreliable**

At `geoff_discovery.py:747-752`:
```python
subprocess.run(["fusermount", "-u", ewf_dir], capture_output=True, text=True, timeout=15)
subprocess.run(["umount", ewf_dir], capture_output=True, text=True, timeout=15)
```

- `fusermount -u` is for FUSE mounts, but ewfmount uses FUSE internally. However, if the mount is held open by another process (e.g., mmls still has handles via the ewf1 device), this fails silently.
- `umount` is tried second, but `fusermount -u` and `umount` are mutually exclusive for FUSE mounts — if `fusermount` fails, `umount` won't help.
- No verification that the unmount actually succeeded. No retry logic.

Over a long pipeline run (multiple EWF images), stale ewfmount directories accumulate in `/tmp`, consuming FUSE threads and eventually causing "too many open fuse devices" errors.

**2c. ewfmount on the same image with different directories**

`_detect_partition_offsets()` uses `/tmp/geoff_ewf_offset_<pid>_<hash>`  
`_mount_and_discover()` uses `/tmp/geoff_ewf_<pid>`  
The VSS fallback uses `tempfile.mkdtemp(prefix="geoff_efb_")`

Each is a **different temporary directory** for the **same image**. This means ewfmount decompresses the entire EWF image multiple times — expensive for large images. Each decompression reads the entire EWF stream from disk again.

**2d. E02 continuation segments are inconsistently resolved**

In `_mount_and_discover()` at line 880:
```python
resolved = _resolve_e01_path(img_path)
if resolved != img_path:
    _fe_log(job_id, f"  SKIP Continuation segment " + ...)
    continue
```

This correctly skips E02/E03 segments. But the **inline pipeline code** at `pipeline_phases.py` does NOT call `_resolve_e01_path` before processing — it iterates over `dev.get("evidence_files", [])` directly which may include E02 segments. These get passed to `SLEUTHKIT_Specialist` which does resolve them, but the log message and offset storage key differ.

### Recommended Fixes

1. **Cache the ewfmount.** Mount once per image at a stable path like `CASES_WORK_DIR/mounts/<case>/<img>_ewf1` and keep it mounted throughout the lifetime of `_mount_and_discover()`. All TSK operations (mmls, fls, icat) use the same ewf1 device. Unmount once at cleanup.

2. **Use FUSE-avoidant TSK for simple operations.** TSK (sleuthkit) handles EWF natively. The code already knows this (note at `sift_specialists.py:33`). For offset detection (mmls), run mmls on the E01 directly — skip ewfmount unless mmls fails natively. This avoids the first ewfmount entirely.

3. **Verify unmount success.** After `fusermount -u`, check `mount | grep <dir>` (or `/proc/mounts`) to confirm unmount. Retry with `fusermount -uz` (lazy unmount) after 1s delay. Only then remove the directory.

4. **Track ewfmount handles globally.** Add EWF mount info to a shared dict `{image_hash: (mount_dir, process_count)}` with reference counting so the same image's ewf1 handle is reused.

---

## 3. HIGH: NTFS-on-SIFT Mount Reliability

**Location:** `geoff_discovery.py:1180-1210` (mount commands), `geoff_self_heal.py:124-129` (error classification)

### The Problem

SIFT (SANS Investigative Forensic Toolkit) — Geoff's target platform — often has incomplete NTFS-3G support, especially on ARM-based or newer Kali derivatives. The mount pattern:

```bash
sudo mount -o ro,loop,offset=1048576 ewf1 /mount/point
```

Fails with `wrong fs type` when:
- NTFS-3G is not installed or misconfigured
- The kernel's built-in NTFS driver is read-only but doesn't support certain NTFS features (compression, encryption, $UsnJrnl, $Secure with large ACLs)
- The NTFS volume has corruption that Linux's NTFS driver rejects but Windows reads fine

### What Geoff Does on Failure

At `geoff_discovery.py:1210-1310`:
1. Classifies the error via `classify_error_fast()` — catches "wrong fs type"
2. **Immediately falls back to sleuthkit (fls) walk** instead of trying to mount via ntfs-3g explicitly
3. If fls fails too — calls LLM self-healing which may or may not help

### The Real Problem: The Fallback Loses Filesystem Semantics

The sleuthkit fallback (fls + icat) works for individual files but loses:
- **File metadata** — timestamps, permissions, ownership, ACLs
- **Directory structure** for analysis tools that expect real paths (RegRipper for registry hives, Plaso for evtx)
- **Mounted path semantics** — downstream tools that use os.walk or Path.iterdir can't work with fls output
- **Streaming access** for large files — icat on a 5GB $MFT or 8GB pagefile.sys requires piping entire contents

### Recommended Fixes

1. **Try ntfs-3g explicitly before falling back.** The kernel module `ntfs3` (Paragon's driver, available in recent kernels) handles NTFS much better. Try:
   ```bash
   sudo mount -t ntfs3 -o ro,loop,offset=X device mount_point
   ```
   before falling to fls.

2. **Detect SIFT's NTFS capability at startup.** Cache whether `ntfs-3g` or `ntfs3` kernel module works. If neither, **default to TSK-direct walk** from the start instead of trying and failing to mount.

3. **For the TSK fallback path: batch-extract key metadata files.** Instead of walking files and extracting individual registry hives/evtx via icat, use TSK's `fls -rmp` (machine-readable format) to dump the full directory listing + metadata with timestamps in one pass. Then use `icat` to extract only the files actually needed. This avoids the fls-per-directory perf issue.

---

## 4. HIGH: The "Mount + Walk" vs "TSK Direct" Architecture Question

**Location:** Entire mount/detect flow in `geoff_discovery.py:820-1900`, `sift_specialists.py`

### The Current Architecture

```
disk_image → ewfmount → mount partition (kernel) → os.walk(mount_point) → classify each file
```

### Why This Fails Systematically

1. **One mount failure kills the whole image.** If any partition fails to mount, the entire image's filesystem walk is replaced by the fls fallback, which is slower and produces non-standard paths.

2. **Path representation mismatch.** Mounted paths look like `/mnt/cases/<case>/<img>_p2048/WINDOWS/system32/config/SOFTWARE` which is native and good. But when fls fallback produces paths like `/tmp/geoff_extract_<case>_<img>/software_1234` — downstream tools get different path structures, breaking path-based deduplication and checkpoint caching.

3. **The os.walk is unlimited.** `_MAX_FILES_PER_IMAGE = 50000` is a soft cap enforced per-image, but a large image (2TB with 5M files) takes hours to walk. There's no early-exit heuristic for "stop walking once you've found all interesting artifact types."

4. **Permission escalation.** `sudo mount` is required. If sudo expires mid-pipeline, the mount fails catastrophically. The error message "no such device" is misleading.

### The Alternative: TSK-Direct Walk

TSK handles EWF natively. The path:
```
E01 + offset → fls -r → icat selected files
```

Pros:
- No `sudo mount` required (runs as user)
- No kernel NTFS driver dependency
- No FUSE mounts to leak
- No partition table parsing errors (TSK's mmls is the same tool)
- Works on corrupted NTFS that Linux won't mount
- Faster for targeted artifact extraction

Cons:
- No native path access for tools (icat extraction path is virtual)
- Need manual handling for deleted files (fls -d + icat)
- Slower for bulk "list ALL files" patterns

### Recommended Architecture Rethink

**Hybrid approach, not either/or:**

1. **Phase A: TSK-direct file listing.** Run `fls -r -m /` to get a timestamped file listing with sizes, inodes, and paths. This produces the same metadata that os.walk would, but works even when mount fails. It's fast — `fls -r` on a 500GB NTFS partition typically finishes in 2-5 minutes.

2. **Phase B: Selective extraction.** Based on the fls listing, extract only the files needed for analysis:
   - Registry hives → `icat` to temp dir
   - Event logs → `icat` to temp dir
   - Browser SQLite DBs → `icat` to temp dir
   - Everything else → mark as available at `image::path` virtual path

3. **Phase C: Mount only when needed.** Try the kernel mount only for tools that require real filesystem access (e.g., external scripts that do `os.walk`). If mount fails, the TSK-direct artifacts are already available from Phase A/B.

This eliminates the offset guess cascade. TSK always uses the correct offset (from `fls -o`), and if the offset is wrong, fls fails fast (seconds) instead of wasting time on a broken mount that produces garbage results.

---

## 5. HIGH: Classification Blind Spots — The "other_files" Black Hole

**Location:** `evidence_classifier.py:250-460`, `geoff_discovery.py:1900-2190` (`_inventory_evidence`)

### The Scale of the Problem

Every file that doesn't match a known extension, header signature, or file name gets dumped into `other_files`. This includes:
- PE executables and DLLs (malware)
- Scripts (ps1, py, vbs, js, bash)
- Documents not in the doc_ext list
- Config files, log files, audit trails
- Binary data dumps
- Raw disk images found inside images
- OVA archives
- **Every single file that should have been recognized but wasn't**

In the `_HEADER_TYPE_MAP` at `geoff_discovery.py:67-95`:
```python
"elf_binary": "other_files",
"macho_binary": "other_files",
"pe_binary": "other_files",
"ova_archive": "other_files",
"jpeg_image": "other_files",
"png_image": "other_files",
```

ELF binaries, PE binaries, Mach-O binaries — these are **critical malware carriers** — all go to `other_files`. JPEG and PNG images could contain steganographic data. OVA archives contain entire virtual machines.

### Why It Undermines the Pipeline

In `pipeline_phases.py:823`:
```python
for archive_path in inventory.get("mobile_backups", []) + inventory.get("other_files", []):
```

Only `mobile_backups` and `other_files` are scanned for compressible archive content. But if a disk image contains a `.zip` that was correctly classified as `other_files`, its contents get extracted. If it contains a `.rar` or `.7z` that was classified as `other_files`, it also gets extracted.

But if it contains a PE binary (`malware.exe`), the PE goes to `other_files` and then:
- Only gets `strings -n 8 | head -c 500000` scan (in `_strings_scan`, `geoff_discovery.py:2480`)
- Gets no PE analysis (import table, section headers, compilation timestamp)
- Gets no YARA scan
- Gets no `pescan` metadata
- Gets no entropy analysis

**The pipeline has no dedicated malware analysis playbook for PE/ELF/Mach-O files.**

### Additional Missed Categories

| Artifact | Classified As | Should Be |
|---|---|---|
| PE executable (.exe, .dll) | `other_files` | `executables` |
| ELF binary | `other_files` | `executables` |
| Mach-O binary | `other_files` | `executables` |
| Java JAR files | `other_files` | `executables` (or archives) |
| OVA/OVF | `other_files` | `virtual_machines` |
| JPEG/PNG/GIF | `other_files` | `images` (for stego analysis) |
| .log files | `other_files` | `logs` |
| .conf/.cfg/.ini | `other_files` | `config_files` |
| Certificate/key files (.pem, .key, .pfx) | `other_files` | `crypto_material` |
| Shell history (.bash_history, .zsh_history) | `other_files` | `shell_artifacts` |
| Prefetch files (.pf) | `other_files` | `prefetch` |
| AmCache hive | `other_files` | `registry_hives` |
| SRUM database | `other_files` | `srum_db` |
| $MFT, $J, $LogFile, $Secure | `other_files` | `filesystem_metadata` |

The last three are especially painful — SRUM databases contain process execution history and network usage, $MFT is the master file table, $J is the USN journal. These are forensically critical files that Geoff should auto-detect.

### Recommended Fixes

1. **Add dedicated evidence types** for executables, images, archives, log files, config files, and crypto material. Each should have its own playbook path.

2. **Add header-based detection** for:
   - MFT / $MFT (signature `FILE`)
   - AmCache (signature `amcache`)
   - SRUM (check filename `SRUDB.dat`)
   - Prefetch files (filename pattern `*.pf`)
   - Certificate files (PEM/DER header detection)

3. **For `other_files` specifically:** After initial classification, run a second pass using `file -b` on each to categorize by MIME type. Files that are PE/ELF/Mach-O get reclassified as executables. Files that are `application/zip` get reclassified as archives. This should happen inline, not as a separate pass.

---

## 6. MEDIUM: Mobile Evidence — Shallow Coverage

**Location:** `evidence_classifier.py:300-360`, `pipeline_phases.py:963-986`

### The Problems

**6a. Mobile backup detection is filename-heuristic only**

At `evidence_classifier.py:311`:
```python
mobile_ext = {'.tar.gz', '.zip', '.ab'}  # Android/iOS backup archives
```

After detection, a file is classified as mobile backup if it contains `android`, `ios`, `backup`, `cellebrite`, etc. in the filename. This misses:
- Cellebrite UFED physical extractions (tar/zip with generic names like `extraction_1.zip`)
- JTAG/chip-off dumps (raw binary, no filename hints)
- Android backups created via `adb backup` (`.ab` format, may not have "backup" in name)
- Signal, WhatsApp, Telegram backups (usually with app name but not "mobile" or "backup")

**6b. .ab (Android Backup) format is not processed**

The `.ab` extension is in `mobile_ext` but the archive extractor (`_extract_archive` at `geoff_discovery.py:2233`) doesn't handle `.ab` files. It checks for ZIP/PK header, gzip, tar, and 7z. Android Backup files have a custom `ANDROID BACKUP` header followed by deflate-compressed tar. Geoff will classify them as `other_files` but cannot extract them.

**6c. No iOS backup parser integration**

iOS backups (iTunes backups stored as `Manifest.db` + SHA1-hashed files) are identified by filename matching `manifest.db` or `manifest.plist` (line 311 area), but there's no actual iOS backup parser that reconstructs the backup into readable artifacts. The hashed filenames (e.g., `3d0d7e5fb2ce288813306e4d4636395e047a3d28`) are meaningless without the Manifest.db mapping.

### Recommended Fixes

1. **Detect Android Backup header** (magic bytes `ANDROID BACKUP`) and route through `abe` (Android Backup Extractor) or the built-in `dd` + `zlib` decompression.
2. **Integrate an iOS backup parser** (or at minimum extract Manifest.db via SQLite and map SHA1 filenames to original paths).
3. **Add Cellebrite extraction detection** — Cellebrite UFED produces a specific directory structure with `data.log`, `extraction.xml`, and numbered tar/zip segments.
4. **Classify raw chip-off dumps** as mobile evidence based on directory context or companion files (`.xml` manifest from the extraction tool).

---

## 7. MEDIUM: Network Evidence — PCAP as a Dead Letter

**Location:** `pipeline_phases.py:1663-1666`

### The Problem

When PCAPs are present:
```python
if inventory["pcaps"]:
    _fe_log(job_id, f"  PB-SIFT-036: PCAP Network Forensics queued ({len(inventory['pcaps'])} capture(s))")
```

The PCAP network forensics playbook is **queued** but the actual analysis is never validated. Looking at the playbook steps in `geoff_config.py`:

```python
# playbook steps reference {pcap} placeholder without actual tool invocation patterns
```

The `PB-SIFT-036` playbook maps to `geoff_config.py` steps that invoke `tcpdump`, `tshark`, `zeek`, or `strings` — but the analysis steps appear to be **skeleton definitions that log intent** without extracting useful forensic artifacts:
- No HTTP object extraction (files transferred over HTTP)
- No TLS certificate extraction
- No DNS query logging
- No conversation statistics
- No protocol hierarchy
- No extracted email/FTP credentials

The playbook's output is essentially the tshark/zeek raw output dumped into the findings log — no structured analysis, no IOC extraction from PCAP.

### Recommended Fixes

1. **Add HTTP object extraction** — `tshark --export-objects http,outdir` extracts files transferred over HTTP.
2. **Add TLS certificate extraction** — `tshark -Y "ssl.handshake.certificate" -T fields -e x509sat.printableString`
3. **Add credential extraction** — Scan for HTTP basic auth, FTP login, SMTP AUTH in PCAP payloads.
4. **Add DNS analysis** — Extract all DNS queries/responses as structured JSON.

---

## 8. LOW: Multi-Host Correlation — Incomplete Surface

**Location:** `host_correlator.py` (full file), `pipeline_phases.py:1170-1220`

### The Problem

The `HostCorrelator` is capable but disconnected from the actual pipeline output. It expects structured findings (`timeline_events` list) but:

1. **The pipeline doesn't build a unified timeline.** `pipeline_phases.py` processes per-device playbooks individually. The output is per-device findings lists. No single `timeline_events` list is constructed that aggregates events across devices with normalized timestamps.

2. **HostCorrelator is never actually called by the pipeline.** Searching the codebase: `HostCorrelator.correlate()` appears only in the class definition and unit tests — **not in any pipeline flow**. The correlator is dead code.

3. **Even if called, the data requirements are mismatched.** `correlate()` expects `findings: List[dict]` and `timeline_events: List[dict]` with specific fields. The pipeline produces findings in a different schema — nested dicts with `evidence_type`, `image`, `internal_path`, etc. No adapter exists.

### Recommended Fixes

1. Wire `HostCorrelator.correlate()` into Phase 4 or Phase 5 of the pipeline, passing the aggregated per-device findings.
2. Build the timeline as a flat list of `{timestamp, device_id, event_type, description, severity}` from all per-device playbook outputs.
3. Add device_map and user_map as explicit inputs to the correlation call — they're already built by `_run_device_discovery()`.

---

## 9. LOW: Archive Extraction — Nested Archive Gap

**Location:** `geoff_discovery.py:2233-2363` (`_extract_archive`)

### The Problem

`_extract_archive()` works for single-layer archives. If an archive contains another archive inside:
```
evidence.zip
  └─ logs_backup.tar.gz    ← detected as gzip, extracted
       └─ daily_logs.7z    ← NOT extracted — this is just a file on disk in the extract dir
           └─ actual_data.txt ← never reached
```

Geoff extracts `evidence.zip` to `/tmp/extractions/evidence_1234/`, which now contains `logs_backup.tar.gz` as a regular file. But **Geoff never walks extraction directories looking for nested archives** — `_list_extracted_files()` just lists filenames without checking their types.

The extracted contents go into `inventory["other_files"]` via the `extracted_dir` entry, but the pipeline treats it as a directory, not a set of unpackable files.

### Recommended Fixes

1. After archive extraction, scan the extracted directory contents for new archives and recursively extract them (up to a max depth of 3-5).
2. Use `_detect_file_type_from_header()` on each extracted file, not just extension matching, to catch misnamed nested archives.
3. Add max depth and max expansion size guards to prevent ZIP bombs.

---

## 10. LOW: Self-Healing — LLM-Driven Fragility & Cache Inconsistency

**Location:** `geoff_self_heal.py`, `geoff_critic.py`

### The Problems

**10a. LLM healing is expensive and slow for trivial errors**

At `geoff_critic.py:849-910`, every failed mount/offset detection triggers an LLM call (Ollama, ~3-10s latency). For errors that `classify_error_fast()` can handle (wrong_fs_type, no_such_device, loop_device), the deterministic fix is always the same: try a different offset or try mount without offset. Invoking the LLM for these is wasteful.

The current behavior: `classify_error_fast()` catches ~6 error classes and returns `None` for everything else → LLM call. The "everything else" includes common errors like "Record 0 has no FILE magic" (wrong offset) or "Invalid superblock" (wrong offset) — both trivially fixable by trying offset 2048 → 63 → 0.

**10b. HealCache uses a file-based cache with no invalidation**

`HealCache` at `geoff_critic.py:120` stores decisions in `heal_cache.json` keyed by `error_context_hash`. Once a decision is cached, it's reused forever — even if the underlying tool, evidence, or environment changes. A single wrong LLM diagnosis (e.g., "offset should be 63" when it should be 2048) gets cached and repeated on every rerun.

**10c. self-heal runs sequentially with the pipeline**

Each `_attempt_heal()` call blocks the pipeline for 3-10s waiting for the LLM. For 10 images with failing offsets, this is 30-100s of wall time wasted on predictable "try next offset" logic.

### Recommended Fixes

1. **Add deterministic fix strategies** for all common mount/offset errors to `classify_error_fast()`. The pattern is always: try `-o 2048`, then `-o 63`, then `-o 0`, then try without offset. This shouldn't require an LLM.

2. **Invalidate HealCache per-case.** Add a case-specific cache key so cached decisions from one investigation don't taint another with different evidence.

3. **Add TTL to HealCache entries.** Entries older than 24h or from a different Geoff version are re-evaluated.

4. **Don't block the pipeline on healing.** Queue heal attempts and continue processing other evidence. Apply the healed result when available (or on next pipeline pass).

---

## Summary: Priority Order for Fixes

| Priority | Issue | Impact | Effort |
|---|---|---|---|
| **P0** | Unify offset detection paths (fix #1) | Fixes most mount failures permanently | 1-2 days |
| **P0** | Fix ewfmount resource leak / mount-twice (#2) | Prevents FUSE exhaustion crashes | 1 day |
| **P1** | Add signature-based offset scanning (sigfind) (#1d) | Removes guess-based fallback | 1 day |
| **P1** | Rewrite to TSK-direct + selective extraction (#4) | Eliminates mount dependence entirely | 3-5 days |
| **P1** | Prefer ntfs-3g / ntfs3 kernel module before fls fallback (#3) | Fixes mount failures on SIFT | 0.5 day |
| **P2** | Add PE/ELF/Mach-O evidence types + YARA scan (#5) | Catches malware currently in `other_files` | 2-3 days |
| **P2** | Add MFT, $J, AmCache, Prefetch, SRUM to evidence types (#5) | Recovers critical forensic data | 1-2 days |
| **P3** | Wire HostCorrelator into pipeline (#8) | Enables cross-host activity detection | 1 day |
| **P3** | Handle nested archives in extraction (#9) | Prevents data loss in nested zip bombs | 0.5 day |
| **P3** | Add deterministic fallback logic to self-heal (#10) | Wastes less time on LLM calls for simple errors | 1 day |
| **P4** | Parse Android Backup (.ab) files (#6) | Recovers mobile app data | 0.5 day |
| **P4** | Add HTTP object extraction from PCAPs (#7) | Recovers transferred files from network captures | 1 day |

---

*This audit was based on source code analysis of the Geoff DFIR framework as deployed on the SANS-SIFT VM. Each finding cites specific line numbers and function locations for targeted fixes.*
