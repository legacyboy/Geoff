# PB-SIFT-030 — Cloud Sync Artifacts

**Phase:** Collection / Analysis
**Auto-triggered when:** OneDrive, Google Drive, Dropbox, iCloud, or Box sync artifacts detected
**Specialist:** `cloud`

## Objective

Parse local cloud sync databases and cache files to reconstruct files that existed in cloud storage, detect exfiltration via cloud sync, identify deleted-but-synced files, and surface anti-forensics involving cloud services.

## Steps

### OneDrive Analysis (`cloud.analyze_onedrive`)

- Parse `LocalState` and `Global.ini` in `%LocalAppData%\Microsoft\OneDrive\`
- Extract synced account email, tenant ID, and sync folders
- Parse `LocalState` LevelDB for file metadata (path, size, hash, cloud state)
- Identify files with `placeholder` status (online-only, not locally cached)
- Flag files that were present in cloud but deleted locally after incident window
- Check for `Personal Vault` (encrypted section) usage indicators

### Google Drive Analysis (`cloud.analyze_googledrive`)

- Parse `snapshot.db` in `%LocalAppData%\Google\DriveFS\` (or `Drive` for older versions)
- Extract file ID, cloud path, local path, sync state, and last modified time
- Parse `content_cache` directory for actual file contents
- Identify files shared externally (shared_with_me, shared_by_me)
- Flag files with `trashed=true` in local DB but not purged from cloud
- Detect "Backup and Sync" vs "Drive for Desktop" configurations

### Dropbox Analysis (`cloud.analyze_dropbox`)

- Parse `filecache.db` in `%LocalAppData%\Dropbox\`
- Extract file path, revision hash, server modified time, and local state
- Parse `config.db` for linked account email and team information
- Identify files in `Dropbox (Selective Sync)` vs fully synced
- Flag files in `.dropbox.cache` (recently deleted but recoverable)
- Check for Dropbox Paper, Transfer, or Capture artifacts

### iCloud Sync Analysis (`cloud.analyze_icloud`)

- Parse `ubiquity` / `CloudDocs` containers on macOS/iOS
- Extract iCloud Drive file list with server timestamps and local paths
- Identify files in `Mobile Documents` that are "optimized" (cloud-only)
- Check `com.apple.cloudd` logs for upload/download activity
- Flag files deleted locally but still present in iCloud Trash
- Detect iCloud Keychain sync indicators

### Box Sync Analysis (`cloud.analyze_box`)

- Parse Box Sync databases in `%LocalAppData%\Box\Box Sync\`
- Extract file list with Box file IDs, versions, and sync state
- Identify collaborative folders and external shared links
- Flag files marked for deletion but still in Box Trash

### Exfiltration Detection (`cloud.detect_exfiltration`)

- Correlate cloud sync activity with incident window
- Identify large uploads to personal cloud accounts from corporate devices
- Detect bulk file movements to external sharing links
- Flag files with classification markings (CONFIDENTIAL, SECRET) in cloud paths
- Cross-reference with browser downloads (files downloaded then uploaded to cloud)
- Check email forensics for cloud sharing invitations sent during incident

## Indicators of Interest

- Large file upload to personal Google Drive during off-hours
- OneDrive placeholder files for data that "should" be local (selective anti-forensics)
- Dropbox `.dropbox.cache` contains files deleted after incident
- iCloud files deleted locally but uploaded just before deletion
- Shared links created to external domains during incident window
- Cloud sync clients installed shortly after compromise
- Files in cloud with names suggesting anti-forensics (e.g., `backup_final_delete.zip`)
- Multiple cloud services syncing the same files (redundancy = exfiltration)
- Google Drive file in Trash with recent restore activity
- OneDrive Personal Vault accessed during incident window

## Output

```json
{
  "cloud_services_found": ["onedrive", "googledrive"],
  "accounts": [
    {
      "service": "onedrive",
      "email": "user@company.com",
      "tenant": "company.onmicrosoft.com",
      "sync_folders": ["Documents", "Desktop"]
    },
    {
      "service": "googledrive",
      "email": "attacker.personal@gmail.com",
      "sync_folders": ["My Drive"]
    }
  ],
  "synced_files": 18432,
  "cloud_only_files": 2341,
  "deleted_local_but_cloud": 47,
  "external_shares": 12,
  "suspicious_uploads": [
    {
      "filename": "customer_database.xlsx",
      "size": 45678321,
      "upload_time": "2024-07-15T02:33:00Z",
      "service": "googledrive",
      "account": "attacker.personal@gmail.com"
    }
  ],
  "findings": []
}
```

## Tools Required

- `LevelDB` parser (Python `plyvel` or `leveldb`) — OneDrive LocalState
- `SQLite3` — Google Drive snapshot.db, Dropbox filecache.db, Box Sync DBs
- `plistlib` / `plutil` — macOS iCloud/ubiquity containers
- `strings` + regex — cloud account email extraction

## Notes

- Cloud sync databases are SQLite/LevelDB — parse with standard tools
- "Placeholder" files (OneDrive/Google Drive) indicate cloud-only data
- Many sync clients keep deleted files in cache/trash for 30+ days
- Cross-reference cloud artifact timestamps with browser/email for context
- Enterprise cloud (OneDrive for Business, Google Workspace) may have admin audit logs available
