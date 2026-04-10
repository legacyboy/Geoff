# Alpha DFIR CTF Report - Sargonradiyeh

## Overview
A detailed DFIR report analyzing a simulated enterprise network breach (based on 'The Stolen Szechuan Sauce' from DFIRMadness). The investigation tracks a full attack lifecycle.

## Systems Investigated
- CITADEL-DC01: Domain Controller (Windows Server 2012 R2)
- DESKTOP-SDN1RPT: Domain-joined client (Windows 10 Enterprise)

## Forensic Artifacts Analyzed
- Disk Images (.E01): Analyzed MFT, USN Journal, Recycle Bin, and Registry hives.
- Memory Dumps (.mem): Used Volatility 2 & 3 for process injection and credential dumping.
- Network PCAPs (.pcap): Inspected with Wireshark and NetworkMiner.
- Timeline: Created super timelines using MFTECmd, Plaso, and Timeline Explorer.

## Attack Lifecycle Findings
- Initial Access: Brute-force RDP login using default Administrator credentials.
- Malware Execution: Deployment of coreupdater.exe (Meterpreter reverse shell).
- Persistence: Established via Registry run keys and malicious services (MITRE T1547.001, T1543.003).
- Lateral Movement: RDP from DC to client using reused credentials (MITRE T1021.001).
- Exfiltration: ZIP archives identified in memory artifacts and PCAP traffic.
- Evasion: Timestomping and process injection into spoolsv.exe (MITRE T1070.006, T1055).
- C2: HTTPS traffic to suspicious IP addresses (Russian and Thai IPs).

## Tools Summary
- Memory: Volatility 2/3
- Network: Wireshark, NetworkMiner
- Timeline: MFTECmd, Plaso
- Registry: Registry Explorer, Regripper
- Registry: Registry Explorer, Regripper
- Analysis: VirusTotal, Any.Run, Hybrid Analysis
- Triage: KAPE, EvtxECMD, SrumECmd
