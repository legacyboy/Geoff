## Source: https://github.com/tim-barc/ctf_writeups
### Key Techniques
- **Comprehensive Artifact Analysis**: This repository serves as a directory of methodologies across multiple DFIR domains:
    - **Endpoint Forensics**: Investigating compromised Windows/Linux hosts using MFT analysis (`MFTECmd`), Registry analysis (`Registry Explorer`), and Event Log parsing (`EvtxECmd`).
    - **Network Forensics**: Packet analysis using Wireshark, Zui, and Brim, specifically targeting CVE-based exploits (e.g., CVE-2024-27198, CVE-2023-32315).
    - **Memory Forensics**: Using Volatility 2/3 and MemProcFS to detect process injection, process hollowing, and credential dumping.
    - **Mobile Forensics**: Android investigation using ALEAPP and JADX for APK decompilation.
    - **SIEM/Log Analysis**: Using ELK, Splunk, and Wazuh to detect password spraying, RDP attacks, and Kerberoasting.
    - **Malware Analysis**: Combining static analysis (PE Studio, DIE, Floss) with dynamic analysis (ProcMon, ANY.RUN, ProcDOT).
    - **Email Analysis**: Extracting headers, decoding payloads, and verifying SPF/DKIM records.

### Tools Used
- **Disk/File Analysis**: FTK Imager, Autopsy, Registry Explorer, MFTECmd, LECmd, EvtxECmd, Timeline Explorer, DB Browser for SQLite.
- **Memory Analysis**: Volatility 2/3, MemProcFS.
- **Network Analysis**: Wireshark, Zui, NetworkMiner, Brim, Tshark.
- **Malware/Reverse Engineering**: PE Studio, Detect It Easy (DIE), dnSpy, Ghidra/Cutter, Capa, Floss, Olevba, oledump.
- **SIEM/Intelligence**: ELK, Splunk, Wazuh, VirusTotal, MalwareBazaar, Any.Run, Triage.
- **Mobile**: ALEAPP, CLEAPP, JADX.

### Lessons Learned
- **Tool Chaining**: Effective DFIR requires chaining tools (e.g., `EvtxECmd` $\rightarrow$ `Timeline Explorer` $\rightarrow$ `Registry Explorer`) to reconstruct a timeline of events.
- **CVE-Centric Analysis**: Matching observed network traffic or process behavior to known CVEs (like Log4j or WinRar 0-day) significantly accelerates the investigation.
- **Linux vs. Windows Forensics**: Contrast between using built-in Linux tools (`grep`, `awk`, `sed`, `cat`) for log analysis and specialized Windows forensic parsers.
- **Mobile Artifacts**: The use of ALEAPP for automated Android artifact extraction is critical for mobile investigations.

### Commands/Examples
- **Linux Log Processing**: `grep` $\rightarrow$ `awk` $\rightarrow$ `sort` $\rightarrow$ `uniq` (standard pattern for summarizing auth logs or web logs).
- **Event Log Parsing**: Use of `EvtxECmd` to convert `.evtx` files into CSV/JSON for analysis in `Timeline Explorer`.

### Geoff Application
- **Toolbox Expansion**: Incorporate `MemProcFS` for a "filesystem-like" view of memory, which can be faster for initial triage than Volatility plugins.
- **Timeline Reconstruction**: Adopt the workflow of parsing all available logs (MFT, Event Logs, Registry) into a single unified timeline using `Timeline Explorer`.
- **Cross-Platform Proficiency**: Maintain a set of "quick-win" Linux commands for rapid log analysis when dealing with non-Windows endpoints.
- **Mobile Triage**: Use ALEAPP as the first step in any Android forensic task to quickly identify user activity and installed apps.
