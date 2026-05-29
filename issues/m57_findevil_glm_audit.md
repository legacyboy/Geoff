# Find Evil Job Audit: fe-4017c4c4a10f (m57-patents)

**Date:** 2026-05-27 00:53 CDT  
**Auditor:** Steve4 (subagent)

---

## Verdict: MEANINGFUL WORK — Let it run, but note a side concern

The job is **not stuck in a useless loop**. It is making steady, measurable progress through PB-SIFT-001 across 86 disk images. However, there is a **separate problem**: an unrelated script (`add_log_v5.py`) has been consuming 100% CPU for over 26 hours, which is competing for resources.

---

## Evidence

### 1. Output files are growing and new files are being created

| File | Size | Last Modified |
|------|------|---------------|
| `findings.jsonl` | 158 MB | 2026-05-27 00:48 |
| `exec_cache.json` | 105 MB | 2026-05-27 00:51 |
| `output/PB-SIFT-001.json` | 107 MB | 2026-05-27 00:51 |
| `audit_trail.jsonl` | 3.2 KB | 2026-05-26 21:10 |

- `findings.jsonl` has **210 lines** (not just file listing junk — structured findings)
- `output/PB-SIFT-001.json` is 107 MB and growing
- `validations/` directory has **133 files** (66 sleuthkit + 67 dc3dd) with timestamps from 05:22 through 00:51 — continuously producing new validation records

### 2. Progress through PB-SIFT-001

The execution plan has **23 playbooks** to run:
```
PB-SIFT-001 through PB-SIFT-023 (with 007-010, 012-013, 015-018, 020-023)
```

PB-SIFT-001 iterates over **86 disk images**, running `sleuthkit.list_files` + `dc3dd.verify_image` on each. As of 00:51 CDT:

- **66 sleuthkit validations** completed (out of 86)
- **67 dc3dd validations** completed (out of 86)  
- Currently processing: `terry-2009-11-16.E01` (sleuthkit just finished, dc3dd in progress)
- That's roughly **77% through PB-SIFT-001**

The log shows continuous progression from charlie → jo → pat → terry drives, with each disk taking 10-30 minutes for the sleuthkit+dc3dd cycle. No repetition of the same disk.

### 3. The "self_correction" entries in audit_trail are NOT loops

The 18 `self_correction` entries in `audit_trail.jsonl` are **fail-forward recoveries** within sleuthkit, not re-processing:

```
sleuthkit.list_files: fls_auto fails → fls_offset0 fails → mmls_probe succeeds
```

This is the **designed fail-forward chain** — for disks where the partition table isn't at sector 0, it falls back through three methods until one works. Each disk gets processed exactly once.

### 4. Not a loop — clear forward progress

Server log shows sequential processing:
```
terry-2009-11-12.E01 → terry-2009-11-12start.E01 → terry-2009-11-16.E01 (current)
```

Each drive gets sleuthkit.list_files, then dc3dd.verify_image, then moves to the next drive. No drive is being processed twice.

### 5. CPU contention problem

Two **unrelated** `add_log_v5.py` processes (PIDs 339477, 339690) have been running since May 25, consuming **99.9% CPU each** (both cores maxed). These are modifying the Geoff source code, not part of the find-evil pipeline.

- Uptime: 8 days, load average: 2.19
- The Geoff server process (PID 406376) is using only **2.4% CPU** and **2.1% memory**

The add_log_v5.py scripts are competing with Geoff for CPU, likely slowing down the sleuthkit/dc3dd subprocess calls.

### 6. Phase 1 Critic rejected initial inventory analysis

The `phase1_critic_validation.json` shows the initial inventory analysis was **REJECTED** for hallucination (claiming file paths were "Offsets"). This was caught and corrected — the current pipeline is proceeding properly.

---

## Timeline Estimate

- **86 total drives** in PB-SIFT-001
- **66 drives completed** so far (~77%)
- Average ~15 min per drive (sleuthkit + dc3dd + critic validation)
- **~5 more hours** to finish PB-SIFT-001 at current rate
- Then 22 more playbooks remain (PB-SIFT-002 through PB-SIFT-023)
- **Total remaining**: could be many more hours to days depending on playbook complexity

---

## Recommendation

1. **Let the find-evil job continue** — it's doing real forensic work, not stuck
2. **Kill the `add_log_v5.py` processes** (PIDs 339477 and 339690) — they've been burning 100% CPU for 26+ hours and are competing with Geoff for resources. They appear to be a source code modification script that's either hung or in an infinite loop:
   ```bash
   kill 339477 339690
   ```
3. **Monitor progress** — PB-SIFT-001 should complete in ~5 hours, then watch for transition to PB-SIFT-002
4. **Consider checkpointing** — the job has robust checkpointing. If you need to reboot the VM to clear the CPU contention, the job should resume from where it left off

---

## Appendix: Key File Locations

| Item | Path |
|------|------|
| Case dir | `/mnt/evidence-storage-2/m57-patents_findevil_a36d505e8542/` |
| Checkpoint | `.geoff_checkpoint.json` |
| Execution plan | `execution_plan.json` |
| Audit trail | `audit_trail.jsonl` |
| Findings | `findings.jsonl` (210 entries, 158 MB) |
| Exec cache | `exec_cache.json` (105 MB) |
| PB-SIFT-001 output | `output/PB-SIFT-001.json` (107 MB) |
| Validations | `validations/` (133 files) |
| Custody chain | `custody/` |
| Server log | `/tmp/geoff_server.log` |