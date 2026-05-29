# NAS Evidence Inventory & Geoff Processing Audit

## Evidence on NAS (/mnt/nas-multimedia/evidence/)

### 28 evidence directories available:

| Directory | Key Files | Types | Processed by Geoff? |
|-----------|-----------|-------|---------------------|
| **2018** | 6x E01 disk images, 11x memory 7z, 1 img, 2 ZIP, 2 HACKATHON subdirs | Multi-host enterprise, disk+memory | YES (running, 5%) |
| **APT 2015** | xp-tdungan-10 dir, win7-32/64 ZIPs | Multi-host, archives | NO |
| **CIRCL_Wiped** | wiped_disk.E01, PDF report | Single disk, wiped | NO |
| **NPS_domexusers** | 3x E01 (multi-segment) | Single disk | Previously ran |
| **data-leakage-case** | 4x E01 (pc), 2x E01 (removable), PDF | Multi-device, data leakage | Previously ran |
| **dfrws2017** | 4x ZIP (IoT devices), extracted dir | IoT, ZIP archives | NO |
| **google-drive-case** | arlo, echo, ismartalarm, network, samsung, wink dirs | IoT/smart home | NO |
| **hacking-case** | E01 + SCHARDT.LOG | Single disk | Previously ran |
| **hacking-case-new** | (empty or TBD) | Unknown | NO |
| **jeanm57** | 2x E01 (multi-segment) | Single disk | NO |
| **linux-forensics** | nist-linux-scenario.zip | Linux, archive | NO |
| **linux-sift** | (empty) | Unknown | NO |
| **linux-test** | linux-test.img | Linux raw image | Previously ran |
| **m57-patents** | docs/, drives/, network/ dirs | Multi-format case | NO |
| **memory-images** | 6x raw .img files, RAR archive | Memory dumps only | NO |
| **mobile-android13** | Android_10 dir + ZIP | Mobile backup | NO |
| **mobile-android14** | tar.gz + extracted dir | Mobile backup | NO |
| **mobile-chipoff** | 2x .img (HTC phones) | Chip-off physical | NO |
| **mobile-ios16** | iOS_16 dir + 2x tar | Mobile backup | NO |
| **mobile-ios17** | extracted + 2x tar | Mobile backup | NO |
| **network-forensics** | 3x .pcap files | Network captures | NO |
| **registry-forensics** | 2x 7z archives | Registry hives | Previously ran |
| **rhino-hunt** | ZIP + extracted dir | Challenge/CTF | NO |
| **rocba** | E01 + PPTX + Memory ZIP | Single host + mobile | YES (rerunning fresh) |
| **sans-hackathon** | SANS_Hackathon_2026.zip | Archive | NO |
| **sans-hackathon-2026** | 2 raw files | Unknown | NO |
| **stolen-sauce** | 10x ZIP (DC01 + DESKTOP) | Multi-host enterprise | NO |
| **windows10-evaluation** | Win10_Eval.vhd | VHD virtual disk | NO |

## Geoff Evidence Classification Pipeline

### Current Flow:
1. **evidence_classifier.py** scans the evidence directory
   - `_fast_classify()`: filename/extension matching → categories (disk_images, memory_dumps, pcaps, mobile_backups, evtx_logs, registry_hives, other_files)
   - `_header_classify()`: python-magic on ambiguous files
   - `_llm_classify()`: LLM-based classification for remaining unknowns

2. **device_discovery.py** groups files into devices
   - Groups by filename prefix (e.g., "base-wkstn-01" → one device)
   - Creates device_map with device_id, evidence_files, os_type, device_type

3. **pipeline_phases.py** builds execution plan
   - Queues playbooks based on: os_type, evidence_types, device count
   - Skips playbooks when conditions not met

### Known Classification Gaps:
- **VHD files**: Win10_Eval.vhd not recognized as disk image (no .E01/.img/.dd extension)
- **Multi-segment E01**: Only .E01 detected, .E02/.E03 may be missed or treated as separate
- **Archives with nested evidence**: ZIP/7z containing disk images only extracted if detected as archives
- **IoT device dumps**: google-drive-case has device subdirs, not standard image files
- **Chip-off images**: .img files in mobile-chipoff treated as raw disk, not mobile physical
- **Mixed-type directories**: m57-patents has docs/drives/network subdirs, not flat evidence
- **LOG files**: SCHARDT.LOG in hacking-case not classified as anything useful
- **PDF reports**: Wiped disk PDF, leakage answers PDF treated as "other_files"
- **RAR archives**: memory-images.rar not recognized (only ZIP/7z/gz supported?)
- **VHD/VHDX**: windows10-evaluation .vhd not in extension list

### Known Processing Gaps:
- 22 of 28 evidence directories have NEVER been processed
- Only 4 have been run through Find Evil (2018, rocba, hacking-case, linux-test)
- Several require archive extraction BEFORE classification (dfrws2017, stolen-sauce, APT 2015)
- Mobile evidence (6 dirs) requires mobile-specific playbooks
- Network forensics (pcaps) requires PB-SIFT-011 which may not handle all pcap types
- VHD format not in the supported image type list

### Fallback Chain Issues:
- When fls fails with wrong offset → falls to carving instead of trying other offsets (BEING FIXED)
- bulk_extractor can't read E01 directly → needs ewfexport first (BEING FIXED)
- strings timeout on large images → adaptive timeout (BEING FIXED)
- Several modules referenced in playbooks don't exist (BEING FIXED)