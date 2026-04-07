# DFIR Learning Knowledge Base - Summary

This document serves as a comprehensive record of the Digital Forensics and Incident Response (DFIR) learning project. It synthesizes techniques, toolchains, and methodologies extracted from various CTF write-ups and professional resources.

## 🚀 Executive Summary
- **Objective**: Extract actionable forensic workflows from CTF challenges to build a high-fidelity technical playbook.
- **Total Sources**: 19 processed.
- **Core Domains**: Memory Forensics, Network Analysis, Disk/Artifact Forensics, Malware Reversal, and Specialized Steganography.

## 🛠️ Technical Tool-to-Task Matrix

| Category | Tool | Primary Use Case |
| :--- | :--- | :--- |
| **Memory** | Volatility 3 | Process tree reconstruction, NTLM hash extraction, network socket analysis. |
| **Memory** | MemProcFS | Virtual filesystem view of memory dumps for rapid triage. |
| **Network** | Wireshark | USB HID keystroke recovery, TLS decryption using session keys. |
| **Network** | Hayabusa | Rapid EVTX triage and timeline generation. |
| **Disk** | FTK Imager | Disk image mounting and raw file extraction. |
| **Disk** | MFTECmd / PECmd | $MFT parsing and Prefetch execution analysis. |
| **Registry** | ShellBags Explorer | Tracking folder navigation history (UsrClass.dat). |
| **Malware** | pyinstxtractor | Unpacking Python binaries to recover compiled bytecode. |
| **Malware** | uncompyle6 | Decompiling `.pyc` files back to readable Python source. |
| **Analysis** | CyberChef | Base64/Hex decoding, XOR operations, and data manipulation. |
| **Special** | SpamMimic | Decoding covert messages hidden in simulated spam emails. |

## 🧠 Key Forensic Workflows

### 1. PyInstaller Reversal Pipeline
`PyInstaller Binary` $\rightarrow$ `pyinstxtractor` $\rightarrow$ `.pyc` bytecode $\rightarrow$ `uncompyle6` $\rightarrow$ `Readable Source Code`.

### 2. USB HID Keystroke Recovery
- **Filter**: `usb.transfer_type == 0x01 && usb.dst == "host" && !(usb.capdata == 00:00:00:00:00:00:00:00)`
- **Process**: Isolate interrupt transfers $\rightarrow$ Export packets $\rightarrow$ Map HID bytes to keyboard layout.

### 3. Windows Execution Proofs
- **Windows.edb**: Analyzing the search database to prove a file existed even if deleted.
- **PCA Logs**: Program Compatibility Assistant logs to verify application launch times.
- **UserAssist**: Registry keys used to track how many times an app was run and when.

### 4. C2 & Network Masking
- **Cloudflare Reverse Proxy**: Identifying backend C2 servers by analyzing HTTP headers and redirection patterns.
- **TLS Decryption**: Utilizing `SSLKEYLOGFILE` to decrypt HTTPS traffic in real-time within Wireshark.

## 📂 Source Archive
The following sources were utilized to build this knowledge base:
- CAT Reloaded CTF 2025
- Connectors CTF 2025
- EG-CTF 2025 (TNKR.2)
- BITSCTF 2024 / SaranGintoki
- Africa DFIR 2021
- AboutDFIR Challenge Database
- CTFtime.org
- Top 100 Forensics Writeups
- CyberDefenders Labs
- bi0sCTF Repository
- tim-barc Writeups

---
*Full detailed documentation available in: `/home/claw/.openclaw/workspace/memory/dfir_learning_2026-04-05.md`*
