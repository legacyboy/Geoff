# PB-SIFT-026: File Carving & Recovery
## File Carving — Automatic Recovery from Raw Images and Unallocated Space

**Objective:** Recover deleted, fragmented, or hidden files from disk images, memory dumps, and raw binary data when standard filesystem analysis yields insufficient results.

**Trigger Conditions:**
- Large disk image (>100MB) with minimal filesystem recovery
- Raw binary dumps (.bin, .img, .raw, .dd, .nand)
- Anti-forensics detected (wiped logs, timestomping)
- Evidence type identified as chip-off/NAND dump
- Filesystem appears empty or corrupted

---

### Phase 1 — Tool Selection & Preparation
- [ ] **Check Tools:** Verify photorec, foremost, and scalpel are available.
- [ ] **Output Directory:** Create dedicated carving output directory under case work dir.
- [ ] **Space Check:** Ensure sufficient disk space (carving can produce 2-5x the source size).

---

### Phase 2 — PhotoRec Carving (Primary)
- [ ] **Run PhotoRec:** `photorec.recover_files(image, output_dir)` — recover all file types from disk image.
- [ ] **Review Results:** Count recovered files by type. Flag suspicious file types (executables, scripts, archives).
- [ ] **Correlate:** Cross-reference recovered filenames with triage indicator hits.

---

### Phase 3 — Foremost Carving (Secondary)
- [ ] **Run Foremost:** `foremost -t all -i image -o output_dir` — alternative carving engine.
- [ ] **Compare Results:** Compare foremost output with photorec. Different engines recover different fragments.
- [ ] **Deduplicate:** Remove duplicate recovered files across both tools.

---

### Phase 4 — Scalpel Carving (Tertiary — Custom Signatures)
- [ ] **Custom Config:** If target file types known (e.g., specific malware family), configure scalpel with custom signatures.
- [ ] **Run Scalpel:** `scalpel -c config.conf -o output_dir image` — targeted deep carving.
- [ ] **Artifact Review:** Examine carved artifacts for anti-forensics tool residue.

---

### Phase 5 — Validation & Classification
- [ ] **Classify Recovered Files:** Run AI classifier on all carved files.
- [ ] **Hash Check:** Check recovered files against known-good and known-bad hash databases.
- [ ] **Flag Suspicious:** Flag executables, scripts, encoded data, or encrypted containers.
- [ ] **Add to Inventory:** Add validated carved files to evidence inventory for playbook processing.

---

### Phase 6 — Integration with Investigation
- [ ] **Timeline Integration:** Add carved file timestamps to super-timeline.
- [ ] **Correlation:** Correlate carved artifacts with existing findings.
- [ ] **Report:** Document carving results, including what was recovered and why carving was triggered.

---

## Tools Required
- `photorec` (testdisk package) — primary file carver
- `foremost` — secondary file carver
- `scalpel` — custom signature carver
- `file` — file type identification
- `md5sum` / `sha256sum` — hash validation

## Notes
- Carving is computationally expensive — only trigger when needed.
- PhotoRec is most reliable for general-purpose recovery.
- Foremost excels at specific file types (images, documents, executables).
- Scalpel is best for targeted recovery with known signatures.
- Always preserve original image — carving is read-only but verify.
- Anti-forensics + carving often reveals the "what they tried to hide."
