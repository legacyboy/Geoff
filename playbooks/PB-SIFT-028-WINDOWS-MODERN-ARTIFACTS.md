# PB-SIFT-028 — Windows Modern Artifacts (10/11)

**Phase:** Collection / Analysis
**Auto-triggered when:** Windows 10 or Windows 11 OS detected (from SYSTEM hive or OS fingerprinting)
**Specialist:** `windows`

## Objective

Extract and analyze Windows 10/11 modern forensic artifacts including Prefetch, Jump Lists, LNK files, ShimCache, AmCache, SRUM, Windows Timeline, Defender detections, and BITS activity. These artifacts reveal user behavior, execution history, and anti-forensics that traditional registry/file analysis misses.

## Steps

### Prefetch Analysis (`windows.analyze_prefetch`)

- Parse all `.pf` files in `%SystemRoot%\Prefetch` using Windows Prefetch Parser (PECmd)
- Extract executable name, path, run count, last run time(s), and loaded DLLs
- Flag executables run from unusual paths (`\Temp`, `\Downloads`, `\Users\Public`)
- Flag prefetch entries with high run counts but no matching disk executable (evidence deletion)
- Cross-reference with execution timestamps from AmCache/ShimCache

### Jump Lists Analysis (`windows.analyze_jumplists`)

- Parse `AutomaticDestinations` in `%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\` (OLE Compound Document format)
- Parse `CustomDestinations` in `%AppData%\Microsoft\Windows\Recent\CustomDestinations\` (MS-SHLLINK format)
- **Specialist Method:** `windows.analyze_jumplists(user_profile_path)`
- Extract application IDs (AppID) — map AppIDs to application names using known AppID database
- Extract target file paths, access timestamps, and creation timestamps from each Jump List entry
- Creation timestamp = first item added; Modification timestamp = last item added
- Flag access to files that were later deleted (Jump Lists persist after deletion — **critical for anti-forensics**)
- Detect lateral movement: RDP mstsc.exe Jump Lists showing connections to internal IPs
- Identify document access patterns: correlate files opened by same application across Jump Lists
- **Deep Parsing — AutomaticDestinations:**
  - Each `.automaticDestinations-ms` file is an OLE compound document containing multiple streams
  - Stream `DestList` contains MRU list with timestamps and file paths
  - Parse with JLECmd for full extraction: `JLECmd.exe -d <path> --csv <output>`
- **Deep Parsing — CustomDestinations:**
  - Each `.customDestinations-ms` file contains raw LNK data concatenated
  - Parse with JLECmd: `JLECmd.exe -d <path> --csv <output>`
  - Custom entries show pinned items (user explicitly pinned = high significance)
- **SANS FOR500 Alignment:** Jump Lists are a **★★★★** priority artifact — one of the primary sources for user activity tracking and proving file access


### LNK File Analysis (`windows.analyze_lnk`)

- Parse all `.lnk` shortcut files in user profiles and recent items
- Extract target path, MAC timestamps, volume serial number, and network share paths
- Flag LNK files pointing to external or network-attached resources
- Detect LNK-based initial access vectors (LNK file with malicious target)
- Cross-reference with USB insertion artifacts (volume serial → USBDeview)

### ShimCache (AppCompatCache) Analysis (`windows.analyze_shimcache`)

- Parse `AppCompatCache` from `SYSTEM` registry hive
- Extract all executables that have ever run on the system (even if deleted)
- Extract last modified timestamp and full file path
- Flag executables in temp, public, or non-standard directories
- Detect anti-forensics: executables with suspicious modification times (timestomping)
- Note: ShimCache is an execution artifact — items listed here ran at least once

### AmCache Analysis (`windows.analyze_amcache`)

- Parse `Amcache.hve` (located in `%SystemRoot%\appcompat\Programs\`)
- Extract program installation history, first run time, SHA1 hash, and file path
- Cross-reference with ShimCache to confirm execution
- Flag programs with no known publisher or unusual install locations
- Detect anti-forensics: programs uninstalled but still in AmCache
- Note: AmCache is updated on program creation/modification, not execution


### USRCLASS.DAT ShellBags Analysis (`windows.analyze_shellbags`)

- Parse `USRCLASS.DAT` from `\Users\<username>\AppData\Local\Microsoft\Windows\` for ShellBags
- **Specialist Method:** `registry.extract_keys(usrclass_dat_path, 'Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU')`
- Extract folder navigation history including network paths (UNC), removable media, and Control Panel items
- Flag navigation to hidden directories, network shares, or deleted folders (ShellBags persist after deletion)
- Cross-reference ShellBags timestamps with Prefetch and Jump Lists for user activity corroboration
- Detect exotic items: mobile device paths, ZIP archives browsed as folders, Control Panel applets
- Note: USRCLASS.DAT ShellBags capture folder navigation that NTUSER.DAT ShellBags miss — both must be parsed
- **SANS FOR500 Alignment:** ShellBags are a **★★★★** priority artifact (SANS Windows Forensic Analysis poster) proving user folder navigation even after deletion

### SRUM (System Resource Usage Monitor) Analysis (`windows.analyze_srum`)

- Parse `SRUDB.dat` from `%SystemRoot%\System32\sru\`
- Extract per-application network usage, user context, and time online
- Identify applications that transmitted data during the incident window
- Flag high-bandwidth usage by suspicious processes
- Correlate user SID with application execution
- Note: SRUM retains ~30 days of data by default

### Windows Timeline/Activity History (`windows.analyze_timeline`)

- Parse `ActivitiesCache.db` from `%LocalAppData%\ConnectedDevicesPlatform\`
- Extract user activity across devices (file access, app usage, browsing, calls)
- Identify activity during the incident window by device and user
- Flag activity that was deleted or suppressed
- Cross-reference with Jump Lists and Prefetch for corroboration

### Windows Defender Detections (`windows.analyze_defender`)

- Parse `MpDetection.log` and `ProtectionHistory.uel` from Defender directories
- Extract detection name, threat level, file path, action taken, and timestamp
- Identify malware that Defender detected but may have been allowed
- Flag repeated detections on the same path (possible persistence)
- Cross-reference with carved/injected files found in memory

### BITS Activity (`windows.analyze_bits`)

- Parse BITS job database from `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\`
- Extract job name, URL, download path, bytes transferred, and timestamps
- Detect data exfiltration via BITS upload jobs (often used by APTs)
- Flag downloads from suspicious domains via BITS
- Note: BITS jobs persist across reboots and can resume

## Indicators of Interest

- Prefetch shows execution of tools from `%TEMP%` or `%PUBLIC%`
- Jump Lists show RDP connections to multiple internal systems
- LNK files with network paths that no longer exist (evidence of file shares)
- ShimCache entries for malware that was later deleted
- AmCache shows first-run timestamp AFTER incident window (anti-forensics)
- SRUM shows high outbound bandwidth from suspicious processes during off-hours
- Windows Timeline shows file access after deletion time (anti-forensics)
- Defender "allowed" a HIGH severity threat on a persistent path
- BITS jobs uploading data to external domains
- Execution artifacts predating the file creation time (timestomping)

## Output

```json
{
  "os_version": "Windows 10 22H2",
  "prefetch_entries": 187,
  "prefetch_suspicious": 4,
  "jumplists_entries": 342,
  "jumplists_flagged": 2,
  "lnk_files": 89,
  "lnk_suspicious": 1,
  "shimcache_entries": 1243,
  "shimcache_flagged": 7,
  "amcache_entries": 456,
  "amcache_unconfirmed": 3,
  "srum_apps": 67,
  "srum_high_bandwidth": 2,
  "timeline_entries": 18432,
  "timeline_deleted": 12,
  "defender_detections": 3,
  "defender_allowed": 1,
  "bits_jobs": 5,
  "bits_suspicious": 1,
  "findings": []
}
```

## Tools Required

- `PECmd` (Eric Zimmerman) — Prefetch parser
- `JLECmd` (Eric Zimmerman) — Jump Lists parser
- `LECmd` (Eric Zimmerman) — LNK parser
- `AppCompatCacheParser` (Eric Zimmerman) — ShimCache parser
- `AmcacheParser` (Eric Zimmerman) — AmCache parser
- `SRUMDump` or `SRUDB-Tools` — SRUM database parser
- `Windows Timeline Tools` — ActivitiesCache.db parser
- `BITS Parser` (PowerShell or Python) — BITS job parsing

## Notes

- These artifacts are highly volatile — Windows 11 may change storage locations
- AmCache and ShimCache complement each other: AmCache = creation time, ShimCache = execution
- SRUM requires SYSTEM privileges to access the live database
- BITS jobs may be hidden — check for orphaned `qmgr*.db` files
- Windows Timeline data may sync across devices — check for cloud artifacts
