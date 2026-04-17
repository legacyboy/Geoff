# PB-SIFT-009: Ransomware Indicators Playbook
## Ransomware Indicators — Static Image Analysis

**Objective:** High-fidelity detection and analysis of ransomware activity within a digital forensic image using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Process Enumeration:** Enumerate processes — flag anything spawning mass file I/O or encryption-related API calls.
- [ ] **Command Line Audit:** Check command lines — flag `vssadmin`, `wbadmin`, `bcdedit`, `wmic shadowcopy` usage.
- [ ] **Injection Detection:** Check for injected code regions — ransomware commonly injects into legitimate processes.
- [ ] **Network State:** Enumerate network connections — flag outbound to TOR exit nodes or unknown C2 infrastructure.
- [ ] **String Search:** Look for ransom note strings in memory regions.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Mass Modification:** Flag mass file modification events — large volume of files changed in a short window is a primary indicator.
- [ ] **Extension Changes:** Flag file extension changes — original extensions replaced or appended with unknown extensions.
- [ ] **Shadow Copy Audit:** Flag VSS / shadow copy deletion — near-universal ransomware behavior, treat as **CRITICAL**.
- [ ] **Recovery Sabotage:** Flag `bcdedit` or `wbadmin` execution — disabling recovery environment or backup deletion.
- [ ] **Patient Zero Identification:** Correlate first encrypted file timestamp back to initial access vector (email, RDP, download).

---

### Phase 4 — Disk Artifacts
- [ ] **Ransom Note Search:** Check for ransom notes on disk — flag any `.txt`, `.html`, `.hta` files dropped in multiple directories.
- [ ] **MFT Analysis:** Check for mass file rename or extension append events in MFT.
- [ ] **Execution History (Prefetch):** Flag execution of known ransomware droppers or encryptors.
- [ ] **Persistence Check:** Check autoruns — flag persistence mechanisms that may re-trigger encryption on reboot.
- [ ] **Backup Sabotage:** Check for deletion of backup-related binaries or configuration files.
- [ ] **Tool Staging:** Check for tools staged prior to encryption — `psexec`, `cobalt strike`, `anydesk`, `atera` — indicates human-operated ransomware.

---

### Phase 5 — Event Log Analysis
- [ ] **Log Tampering:** Flag log clearing events (EID 1102 / 104) — **CRITICAL**, common pre-encryption step.
- [ ] **Shadow Copy Deletion:** Flag VSS deletion via `vssadmin` or `wmic` (EID 4688 if process auditing enabled).
- [ ] **Access Vector:** Flag RDP logons from unusual sources (EID 4624 logon type 10) — common initial access.
- [ ] **Lateral Deployment:** Flag service creation used to deploy ransomware laterally (EID 7045).
- [ ] **File Access Audit:** Flag bulk file access events if object auditing is enabled.
- [ ] **Privilege Escalation:** Flag account privilege escalation prior to encryption window (EID 4672).

---

---

### Phase 6 — Encryption Scope Assessment
- [ ] **Impact Mapping:** Enumerate all files with unknown or appended extensions.
- [ ] **Directory Audit:** Identify which directories and drives were impacted.
- [ ] **Exclusion Analysis:** Identify any files explicitly excluded (e.g., `Windows\System32` to keep system bootable).
- [ ] **Encryption Method:** Check for partial encryption — some families encrypt only the first N bytes for speed.
- [ ] **Lateral Spread:** Note whether network shares or mapped drives show encryption.

---

### Phase 7 — Network IOC Extraction
- [ ] **IOC Harvesting:** Extract all IPs, domains, and URLs from disk image.
- [ ] **Darknet Analysis:** Flag any `.onion` addresses — ransom payment or negotiation sites.
- [ ] **Threat Intel Enrichment:** Enrich all IOCs against threat intel (VT, AbuseIPDB, internal blocklist).
- [ ] **Exfiltration Check:** Flag exfiltration artifacts — ransomware groups commonly exfiltrate before encrypting (double extortion).

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **Family Identification:** Identify ransomware family if possible based on signature, note style, and extension pattern.
- [ ] **Attack Timeline:** Establish attack timeline — initial access $\rightarrow$ privilege escalation $\rightarrow$ lateral movement $\rightarrow$ encryption.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.

---

## Appendix A: Advanced Ransomware Analysis (CTF Enhanced)

### A.1 — Weaponized Archive Detection (CVE-2023-38831)
- [ ] **Archive Analysis:** Inspect downloaded archives (ZIP, RAR, 7z) for double-extension files.
- [ ] **WinRAR Exploit Detection:** Flag archives containing files with trailing spaces or malicious file extensions masquerading as benign (e.g., `lottery.exe ` disguised as `lottery.pdf.exe`).
- [ ] **Masquerading Check:** Check for file icons inconsistent with extensions (e.g., PDF icon on executable).
- [ ] **Extraction Path Analysis:** Review extracted file paths in temp directories for suspicious executables.

### A.2 — PyInstaller Ransomware Analysis
- [ ] **PyInstaller Detection:** Flag executables packed with PyInstaller (look for `PYZ-00.pyz`, `struct` file signatures).
- [ ] **Extraction:** Use `pyinstxtractor` to extract Python bytecode from PyInstaller executables.
- [ ] **Decompilation:** Use `uncompyle6` or `pycdc` to decompile extracted `.pyc` files to source code.
- [ ] **Source Analysis:** Review decompiled Python for:
    - Encryption algorithms (AES, ChaCha20)
    - Hardcoded IV values (e.g., `b'urfuckedmogambro'`)
    - Key generation logic (random, time-based, hostname-based)
    - File target extensions and paths
    - Ransom note generation

### A.3 — Encryption Key Recovery
- [ ] **Key Material Hunt:** Search memory and temp directories for encryption keys:
    - `vol.py windows.filescan.FileScan` to find temporary files
    - Check `C:\Users\<user>\AppData\Local\Temp\` for key files
    - Search for files with high entropy (potential key material)
- [ ] **AES Key Extraction:** If key found in temp file, extract and convert to hex for decryption.
- [ ] **Memory Key Recovery:** Search process memory for 32-byte random values (AES-256 keys) using `vol.py windows.memmap.Memmap`.
- [ ] **Decryption Testing:** Attempt decryption of sample encrypted file with recovered key before full recovery.

### A.4 — USB HID Keylog Analysis
- [ ] **PCAP Review:** Analyze `keylog.pcapng` or similar USB keyboard traffic captures.
- [ ] **HID Data Extraction:** Export USB HID data from packets (tshark: `usb.data_flag == 0` and `usb.capdata`).
- [ ] **Keystroke Decoding:** Use PUK tool or custom scripts to decode HID keystroke scancodes to ASCII.
- [ ] **Password Recovery:** Reconstruct typed passwords, credentials, or secret messages from keystroke sequences.

### A.5 — Steganography Detection
- [ ] **SpamMimic Detection:** Flag suspicious "spam-like" text in documents or emails that may be steganographic.
- [ ] **Text Decoding:** Use SpamMimic decoder or similar tools to reveal hidden messages in seemingly random text.
- [ ] **Email Attachment Analysis:** Check email attachments for embedded data using steganographic techniques.

## VSS Deletion Analysis

- [ ] **VSS Enumeration:** Run `vss.list_vss(image)` to check if Volume Shadow Copies exist — ransomware commonly deletes VSS via `vssadmin delete shadows`.
- [ ] **VSS File Extraction:** If VSS snapshots survived, run `vss.extract_vss_files(image, output_dir)` to recover pre-encryption file versions.
- [ ] **VSS Timeline:** Run `vss.analyze_vss_timeline(image)` to determine when shadow copies were created/modified — compare against ransomware execution timeline.

## Zimmerman Analysis

- [ ] **AmCache Execution History:** Run `zimmerman.amcache_parse(hive, output_csv)` to identify ransomware binary execution history — even if the binary was deleted.
- [ ] **MFT Timeline:** Run `zimmerman.parse_mft(mft_file, output_csv)` for detailed file creation/modification timeline — tracks ransomware file encryption activity.
