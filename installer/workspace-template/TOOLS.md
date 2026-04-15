# TOOLS.md - GEOFF Forensic Tools

## SIFT Workstation Tools

GEOFF runs on SANS SIFT Workstation. Available tools:

### SleuthKit (sleuthkit_specialist)
- `mmls` — partition table analysis
- `fsstat` — filesystem statistics
- `fls` — file listing
- `icat` — file extraction by inode
- `istat` — inode metadata

### Volatility 3 (volatility_specialist)
- `windows.pslist` — process listing
- `windows.netscan` — network connections
- `windows.cmdline` — command line arguments
- `windows.registry.userassist` — program execution history
- `windows.hashdump` — credential extraction

### Plaso (plaso_specialist)
- `log2timeline.py` — timeline creation
- `psort` — timeline analysis and filtering

### REMnux (remnux_specialist, if installed)
- `die` — Detect It Easy static analysis
- `peframe` — PE framework analysis
- `pdfid`/`pdf-parser` — PDF analysis
- `radare2` — binary disassembly
- `floss` — string extraction from malware

### Network Analysis
- `tshark` — packet capture analysis
- `zeek` — network security monitoring

### String Analysis
- `strings` — ASCII/Unicode string extraction

## Model Profiles

| Profile | Manager | Forensicator | Critic |
|---------|---------|-------------|--------|
| Cloud | deepseek-v3.2:cloud | qwen3-coder-next:cloud | qwen3.5:cloud |
| Local | deepseek-r1:32b | qwen2.5-coder:14b | qwen2.5:14b |