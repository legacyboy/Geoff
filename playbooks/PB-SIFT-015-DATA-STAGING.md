# PB-SIFT-015: Data Staging Indicators Playbook
## Data Staging Indicators — Static Image Analysis

**Objective:** High-fidelity detection of data staging, collection, and preparation-for-exfiltration activity within a digital forensic image using the SIFT Workstation toolset.

**Specialist:** `cloud`, `browser`, `windows`, `memory`

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — File Collection & Archiving Activity
- [ ] **Archive Detection:** Search for `.zip`, `.rar`, `.7z`, `.tar.gz` files in unusual locations (`%TEMP%`, `%APPDATA%`, `/tmp`, `/var/tmp`).
- [ ] **Compression Tools:** Check browser history for visits to compression tool downloads (`7-zip.org`, `win-rar.com`).
- [ ] **Bulk Copy Indicators:** Look for `robocopy`, `xcopy`, `cp -r` usage in shell history or event logs.
- [ ] **USB/External Drive Staging:** Check `setupapi.dev.log`, USB connection logs, and `RecentFiles` for bulk file access patterns.

---

### Phase 3 — Cloud & Network Staging
- [ ] **Cloud Sync Abuse:** Detect large file uploads to OneDrive, Google Drive, Dropbox via sync client logs (`cloud.analyze_onedrive`, `cloud.analyze_googledrive`, `cloud.analyze_dropbox`).
- [ ] **FTP/SFTP Activity:** Check for `ftp`, `sftp`, `scp` usage in command history or process memory.
- [ ] **Web Upload Indicators:** Browser downloads of `mega.nz`, `wetransfer.com`, `file.io` upload clients.

---

### Phase 4 — Anti-Forensics in Staging
- [ ] **Archive Encryption:** Flag password-protected archives — attacker may encrypt staged data before exfiltration.
- [ ] **Name Obfuscation:** Check for renamed extensions (`.jpg` that are actually `.zip`).
- [ ] **Timestomping:** Compare archive modification times with filesystem creation times (`windows.analyze_timeline`).
- [ ] **Deletion of Staging Artifacts:** Check for recently deleted large files in Recycle Bin or Trash.

---

## Indicators of Interest

- Large archives created in `%TEMP%` or `/tmp` containing sensitive file types
- Multiple files copied to USB devices in short time windows
- Cloud sync clients uploading gigabytes of data outside business hours
- Browser visits to file-sharing services followed by large data transfers
- Compression utilities installed on systems that normally don't need them
- Encrypted archives with no business justification
- `robocopy` or `rsync` commands targeting external drives or network shares

## Output

```json
{
  "staging_indicators": {
    "archives_found": 12,
    "archives_suspicious": 3,
    "usb_transfers": 45,
    "cloud_uploads_gb": 2.3,
    "compression_tools_detected": ["7z", "winrar"],
    "suspicious_transfers": [
      {
        "timestamp": "2024-01-15T03:22:00Z",
        "source": "C:\\Users\\admin\\Documents",
        "destination": "E:\\staging\\archive.zip",
        "files": 1200
      }
    ]
  }
}
```

## Tools Required

- `strings` — extract strings from suspicious files
- `7z` / `unzip` / `unar` — inspect archive contents without full extraction
- `cloud` specialist — parse OneDrive, Google Drive, Dropbox sync databases
- `browser` specialist — extract history for file-sharing service visits
- `windows` specialist — analyze Prefetch, ShimCache, SRUM for bulk copy operations
- `memory` specialist — extract process lists showing archiving tools in memory
