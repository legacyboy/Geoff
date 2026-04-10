# CyberDefenders: DeepDive Challenge Write-up

## Overview
Memory forensics challenge involving a compromised machine.
- Image Format: .mem file (526 MB)
- Primary Tool: Volatility

## Key Analysis & Techniques

### 1. Profiling and KDBG
- Image Info: Identified profile as Win7SP1x64_24000.
- KDBG Scan: Used kdbgscan to find the KDBG virtual address.

### 2. Process Analysis
- Hidden Process Detection: Used psxview to compare process listings. 
  - Hidden Process: vds_ps.exe.
  - Physical Address: 0x000000007d336950.
- Path Discovery: Used filescan to find the full path: C:\Users\john\AppData\Local\api-ms-win-service-management-l2-1-0\vds_ps.exe.

### 3. Malware Identification
- Dumping & Hashing: Dumped the executable using dumpfiles and calculated the MD5 hash.
- VirusTotal: Hash analysis identified the malware as Emotet.

### 4. Injected Code Analysis
- Detection: Used malfind to identify VADs with PAGE_EXECUTE_WRITECOPY or PAGE_EXECUTE_READWRITE protections.
- VAD Sizing: Used vadinfo to calculate the size of injected PE sections. Largest VAD size: 0x36FFF.

### 5. Advanced Process Linking
- DKOM Detection: The process was unlinked from the ActiveProcessLinks list.
- Technique: Used volshell to follow the Flink (Forward Link) of the unlinked process to find the next process in the chain.
- Next Process: SearchIndexer.exe.

### 6. Pool Analysis (Kernel Forensics)
- Structure: Analyzed the Pool Header, Object Header, and Object Body.
- Pool Tag: Extracted the pool tag from the pool header and converted it to a 4-byte string in reverse order.
- Result: Pool Tag R0oT.

## Flags Summary
- Profile: Win7SP1x64_24000
- KDBG Address: 0xf80002bef120
- Hidden Process: vds_ps.exe
- Process Physical Address: 0x000000007d336950
- Full Path: C:\Users\john\AppData\Local\api-ms-win-service-management-l2-1-0\vds_ps.exe
- Malware Type: Emotet
- Largest VAD Size: 0x36FFF
- Unlinked Process Link: SearchIndexer.exe
- Pool Tag: R0oT
- Pool Header Address: 0x7d3368f4
