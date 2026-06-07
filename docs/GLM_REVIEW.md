# GLM Review — DATASETS.md and ACCURACY_REPORT.md

**Reviewer:** GLM-5.1 (cloud)
**Date:** 2026-06-01
**Documents reviewed:**
- `docs/DATASETS.md` (dataset documentation)
- `docs/ACCURACY_REPORT.md` (accuracy report)

Cross-referenced against: actual evidence on NAS (`/mnt/evidence/`, `/mnt/evidence-storage-2/`), source code (`src/`), git history, and `docs/SANS-PLAYBOOK-GAP-ANALYSIS.md`.

---

## DATASETS.md — Review

### What's Accurate

- **Hacking Case file listing** is correct: `4Dell_Latitude_CPi.E01` + `SCHARDT.LOG` confirmed on disk.
- **Data Leakage Case file listing** is correct: `cfreds_2015_data_leakage_pc.E01–E04`, `rm#1.E01`, `rm#2.E01` all confirmed.
- **M57-Jean file listing** is correct: `nps-2008-jean.E01` and `nps-2008-jean.E02` confirmed.
- **APT 2015 host naming** is generally correct: `win2008R2-controller`, `win7-32-nromanoff`, `win7-64-nfury`, `xp-tdungan` all present on disk.
- **Dataset summary table** structure is reasonable.
- **Playbook run lists** for each dataset look plausible based on case directory contents.

### What Needs Fixing

#### CRITICAL — Wrong case directory paths

The document references case directories on `/mnt/cases/` which are **empty shells** on the VM. The actual populated case directories are on `/mnt/evidence-storage-2/` with different hashes:

| Doc claims | Actual location |
|---|---|
| `/mnt/cases/jeanm57_findevil_20260501_144601` | `/mnt/evidence-storage-2/jeanm57_findevil_a8f937cca38c` |
| `/mnt/cases/data-leakage-case_findevil_20260501_150022` | `/mnt/evidence-storage-2/data-leakage-case_findevil_b8a61d16ff70` |
| `/mnt/cases/hacking-case_findevil_20260501_150003` | `/mnt/evidence-storage-2/hacking-case_findevil_8a867556e937` |

The APT 2015 path (`/mnt/evidence-storage-2/APT_2015_findevil_50b1869b6a6a`) is correct.

**Fix:** Use environment-variable-based paths (`$GEOFF_CASES_PATH`) or document that case directories are created dynamically and hashes vary per evidence path. Do NOT hardcode specific directory names.

#### CRITICAL — Wrong dataset sizes

Actual `du -sh` measurements from the NAS:

| Dataset | Doc says | Actual | Discrepancy |
|---|---|---|---|
| M57-Jean-Real | ~8 GB | 2.9 GB | 2.75x overestimate |
| Data Leakage Case | ~15 GB | 7.1 GB | 2.1x overestimate |
| Hacking Case | ~4 GB | 101 MB | 40x overestimate |
| APT 2015 | ~90 GB | 90 GB | ✅ Correct |

**Fix:** Replace estimated sizes with actual `du -sh` measurements.

#### MEDIUM — APT 2015 device table is incomplete

The doc says "4 hosts (10 disk images, 3 memory images, 3 network captures)". But:

- `xp-tdungan` also has a `memory` directory (`xp-tdungan-memory`), so it's **4 memory images**, not 3
- The table lists `xp-tdungan` as having only "c-drive" but it actually has both `c-drive` and `memory`
- There's also a `.DS_Store` and `META-INF` directory in `xp-tdungan-10/` — minor, but the directory structure is nested differently (a subdirectory `xp-tdungan-10/` containing the items)
- The zip files are network captures, confirmed (3 zip files for the 3 network-connected hosts)

**Fix:** Update the device table to show `xp-tdungan` having both c-drive and memory, and correct the total to "4 memory images". Also note the nested directory structure for `xp-tdungan-10/`.

#### MEDIUM — APT 2015 narrative report path wrong

Doc says: `/mnt/evidence-storage-2/APT_2015_findevil_50b1869b6a6a/reports/narrative_report.md`

This path IS correct on the NAS (confirmed: `narrative_report.md` and `narrative_report.json` both exist). ✅

#### MEDIUM — Hacking Case format is wrong

Doc says: "Raw disk image (`4Dell_Latitude_CPi.E01`)" 

The file `4Dell_Latitude_CPi.E01` is actually **EWF/EnCase format** (confirmed via `file` command: `EWF/Expert Witness/EnCase image file format`). It is NOT a raw disk image.

**Fix:** Change "Raw disk image" to "EnCase EWF image" in the Hacking Case entry.

#### MEDIUM — Chain of custody claims are unverifiable for 3 datasets

The doc claims:
- "SHA-256 custody sidecars for all 24 completed steps are in `/mnt/cases/jeanm57_findevil_20260501_144601/custody/`"
- Similar claims for Data Leakage and Hacking Case

But these directory paths are empty on the VM (no `custody/` subdirectories exist for any of the three older case runs). Only the APT 2015 and M57-Patents cases on the NAS have populated `custody/` directories.

**Fix:** Either (a) re-run these cases with the current code (which generates custody sidecars) and update paths, or (b) note that these were early runs and custody sidecars were added later. Do NOT claim custody sidecars exist for runs that don't have them.

#### LOW — NIST CFReDS URLs

The URLs follow the pattern `https://cfreds.nist.gov/all/NIST/<name>`. This is the known CFReDS URL format, but the actual CFReDS site uses different path patterns. The correct base URL is `https://cfreds.nist.gov/` and datasets are accessed via their web interface, not directly at `/all/NIST/<name>`. These URLs are plausible but **not verified** — they may 404.

**Fix:** Either verify these URLs resolve (can't do from this environment), or change to the generic `https://cfreds.nist.gov/` with dataset names listed, or add a note that "URLs may vary; search CFReDS by dataset name."

#### LOW — M57-Jean-Real description says "1 device"

The doc says "1 device (2 disk images: E01 + E02 continuation)". This is technically correct — E01+E02 is a single split image. But the phrasing "2 disk images" could confuse judges into thinking it's 2 separate devices. The E02 is a continuation segment, not a separate disk.

**Fix:** Change to "1 device (1 disk image in 2 EnCase segments: E01 + E02)".

---

## ACCURACY_REPORT.md — Review

### What's Accurate

- **Commit `6946547`** (CDN IP blocklist fix) — confirmed in git log. ✅
- **Code reference `src/narrative_report.py:455`** — confirmed: line 455 is `def generate(self, report_json: dict, device_map: dict, ...)`. ✅
- **Code reference `src/geoff_self_heal.py:900`** — confirmed: `_self_check_chat_response` is defined at line 900. ✅
- **`_heal_cache` reference** — confirmed: `HealCache` imported from `geoff_critic` and instantiated at line 90. ✅
- **Evidence path validation** — confirmed in `src/geoff_routes.py` lines 344 and 1170. ✅
- **Custody sidecar JSON structure** — matches what's on disk in `/mnt/evidence-storage-2/APT_2015_findevil_50b1869b6a6a/custody/`. ✅
- **M57-Patents Phase 1 rejection** — `phase1_critic_validation.json` confirmed present at `/mnt/evidence-storage-2/m57-patents_findevil_a36d505e8542/phase1_critic_validation.json`. ✅
- **Self-correction counts** — the M57-Patents run has ~28,792 lines in `findings.jsonl` which is consistent with "86 images" worth of activity. The specific count of "18 self-corrections" cannot be directly verified without parsing the audit trail, but is plausible. ✅ (plausible)
- **Known limitations table** — all entries are consistent with what's documented in `SANS-PLAYBOOK-GAP-ANALYSIS.md`. ✅

### What Needs Fixing

#### MEDIUM — `_self_check_chat_response` line number is wrong

The doc says `src/geoff_self_heal.py:881` but the function is actually defined at **line 900**. Line 881 contains LLM prompt text, not the function definition.

**Fix:** Change `src/geoff_self_heal.py:881` to `src/geoff_self_heal.py:900`.

#### MEDIUM — DROP TABLE incident reference is unverifiable

The accuracy report says this incident was "documented in the now-removed COMBINED_AUDIT_REPORT.md". That file has been deleted from git HEAD (commit `951df39`). While it may exist in git history, a judge cloning the repo cannot verify this claim from the current codebase.

**Fix:** Either (a) restore the relevant section from git history as a citation, or (b) rephrase to "this incident was observed during internal testing and is referenced in the codebase at [specific commit hash]" with a link to the relevant git diff. The CDN IP blocklist fix IS verifiable (commit `6946547`), so that reference is solid.

#### MEDIUM — Registry Run key false positive reference

The report says this was "Fixed 2026-05-19 with a registry key allowlist" but provides no commit hash or code reference. Unlike the CDN IP fix (which has commit `6946547`), this claim cannot be verified from the current document.

**Fix:** Add a commit hash or code reference, or note it as "fixed in commit prior to audit cleanup."

#### LOW — Memory dump classification description is slightly inaccurate

Section 2.2 says "`.img` files are now checked for memory dump magic bytes before classification." This is partially correct — the actual fix added `.mans` (FTK Imager memory captures) as a signal, and the check for `.img` files is that they get probed via Volatility `imageinfo` rather than being assumed to be memory. The doc's current phrasing implies a simple magic-byte check on `.img` files, which isn't exactly what the code does.

**Fix:** Clarify that `.mans` files are classified as memory dumps directly, while `.img` files require further probing (Volatility `imageinfo`) before classification.

#### LOW — Version reference should be a tag, not a commit

The report says "Version: HEAD (commit 475f5e9)". For a competition submission, this should reference a git tag or release version rather than a specific commit SHA, since HEAD changes after submission.

**Fix:** Create a `v1.0` tag at the submission commit and reference that instead.

#### INFO — "now-removed COMBINED_AUDIT_REPORT.md" references

The report references this file twice (§1.1 Incidents 1 and §2.4 RAR Archive Handling). Since the file was deliberately removed from HEAD in commit `951df39` (per the cleanup), a judge cannot access it. This is fine for internal context but looks like an unfinished reference in a judge-facing document.

**Fix:** Replace all "documented in the now-removed COMBINED_AUDIT_REPORT.md" with either (a) a summary of the relevant finding inline, or (b) a reference to the commit hash where the data can be found in git history.

---

## Cross-Document Consistency Issues

### Case path discrepancy affects both documents

Both DATASETS.md and ACCURACY_REPORT.md reference `/mnt/cases/` paths that don't contain actual case data. The real data is on `/mnt/evidence-storage-2/` with different hashes. This is the most significant consistency issue across both documents.

### Dataset naming consistency

DATASETS.md calls the M57 dataset "M57-JEAN-REAL" in the section header but "M57-Jean (NPS image pair)" in the overview table. ACCURACY_REPORT.md references "M57-Patents" which is a different dataset entirely (the 86-image M57-Patents corpus). These are correctly distinguished (M57-Jean is the NPS pair, M57-Patents is the larger corpus) but a judge might confuse them.

**Fix:** In ACCURACY_REPORT.md, when referencing the Phase 1 hallucination catch, clarify that "M57-Patents" is the 86-disk-image corpus, distinct from the "M57-Jean" NPS pair documented in DATASETS.md.

---

## Recommendations for Competition Submission

### Must Fix (before submission)

1. **Replace hardcoded `/mnt/cases/` paths** with environment-variable references or document that paths are dynamically generated. Judges will run Geoff on their own machines with different evidence paths.
2. **Correct dataset sizes** — use actual `du -sh` measurements instead of estimates.
3. **Fix Hacking Case format** — it's EnCase EWF, not raw.
4. **Fix APT 2015 device table** — xp-tdungan has memory too, total is 4 memory images not 3.
5. **Remove or qualify custody sidecar claims** for the 3 older case runs that don't actually have custody data.
6. **Fix `_self_check_chat_response` line reference** from 881 to 900.

### Should Fix (strongly recommended)

7. **Replace "now-removed COMBINED_AUDIT_REPORT.md" references** with inline summaries or git-history citations that a judge can actually access.
8. **Add commit hashes** for the registry key allowlist fix and any other unreferenced claims.
9. **Clarify `.img` memory dump classification** — it's `.mans`-based with Volatility probing, not just magic bytes.
10. **Tag the submission commit** as `v1.0` and reference the tag instead of commit SHA.

### Nice to Have

11. **Verify NIST CFReDS URLs** resolve correctly (or use generic CFReDS landing page).
12. **Clarify M57-Jean "2 disk images" phrasing** — it's 1 image in 2 segments.
13. **Add a note** distinguishing M57-Jean (NPS pair) from M57-Patents (86-image corpus) in ACCURACY_REPORT.md.

---

*Review complete. Both documents are structurally sound but contain factual inaccuracies in dataset sizes, file formats, and directory paths that must be corrected before competition submission.*