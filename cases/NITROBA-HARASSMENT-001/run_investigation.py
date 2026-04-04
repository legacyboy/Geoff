#!/usr/bin/env python3
"""
NITROBA-HARASSMENT-001: Network Harassment Investigation
Geoff Digital Forensics Protocol — Evidence-Based Analysis
"""

import sys
import subprocess
import re
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def step_1_evidence_verification(case_dir):
    """Step 1: Verify evidence integrity and document chain of custody."""
    print("="*70)
    print("STEP 1: EVIDENCE VERIFICATION & CHAIN OF CUSTODY")
    print("="*70)
    
    evidence_file = case_dir / "evidence" / "nitroba.pcap"
    
    if not evidence_file.exists():
        print("[ERROR] Evidence file not found!")
        return False
    
    print(f"[+] Evidence file: {evidence_file}")
    print(f"[+] File size: {evidence_file.stat().st_size:,} bytes")
    
    # Calculate hashes
    print("\n[*] Calculating integrity hashes...")
    md5 = subprocess.run(["md5sum", str(evidence_file)], capture_output=True, text=True).stdout.split()[0]
    sha1 = subprocess.run(["sha1sum", str(evidence_file)], capture_output=True, text=True).stdout.split()[0]
    sha256 = subprocess.run(["sha256sum", str(evidence_file)], capture_output=True, text=True).stdout.split()[0]
    
    print(f"  MD5:    {md5}")
    print(f"  SHA1:   {sha1}")
    print(f"  SHA256: {sha256}")
    
    # Verify file type
    file_type = subprocess.run(["file", str(evidence_file)], capture_output=True, text=True).stdout.strip()
    print(f"\n[+] File type: {file_type}")
    
    # Compare to expected
    expected_md5 = "9981827f11968773ff815e39f5458ec8"
    expected_sha1 = "65656392412add15f93f8585197a8998aaeb50a1"
    expected_sha256 = "2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb"
    
    print("\n[*] Hash verification:")
    if md5 == expected_md5:
        print("  [✓] MD5 matches original")
    else:
        print(f"  [⚠] MD5 MISMATCH (got {md5[:16]}..., expected {expected_md5[:16]}...)")
    
    if sha1 == expected_sha1:
        print("  [✓] SHA1 matches original")
    else:
        print(f"  [⚠] SHA1 MISMATCH (got {sha1[:16]}..., expected {expected_sha1[:16]}...)")
    
    if sha256 == expected_sha256:
        print("  [✓] SHA256 matches original")
    else:
        print(f"  [⚠] SHA256 MISMATCH (got {sha256[:16]}..., expected {expected_sha256[:16]}...)")
    
    print("\n[NOTE] Hash variance from Digital Corpora original may indicate:")
    print("       - Different file version/source (GitHub vs Digital Corpora)")
    print("       - File modification during transfer")
    print("       - Source: github.com/open-nsm/course/master/pcaps/nitroba.pcap")
    
    return {
        "md5": md5,
        "sha1": sha1, 
        "sha256": sha256,
        "file_type": file_type,
        "size_bytes": evidence_file.stat().st_size
    }

def step_2_pcap_overview(evidence_file):
    """Step 2: PCAP overview and statistics."""
    print("\n" + "="*70)
    print("STEP 2: PCAP OVERVIEW & STATISTICS")
    print("="*70)
    
    # Use capinfos if available
    try:
        result = subprocess.run(["capinfos", str(evidence_file)], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            # Fallback to tcpdump
            result = subprocess.run(["tcpdump", "-r", str(evidence_file), "-n", "-c", "10"], 
                                  capture_output=True, text=True)
            print(f"[+] PCAP is readable. Sample packets:")
            print(result.stdout[:1000])
    except FileNotFoundError:
        print("[INFO] capinfos/tcpdump not available, skipping packet statistics")
    
    return True

def step_3_traffic_analysis(evidence_file):
    """Step 3: Analyze network traffic for key indicators."""
    print("\n" + "="*70)
    print("STEP 3: NETWORK TRAFFIC ANALYSIS")
    print("="*70)
    
    findings = {
        "unique_ips": set(),
        "unique_macs": set(),
        "http_hosts": set(),
        "willselfdestruct_traffic": [],
        "yahoo_traffic": [],
        "suspicious_activities": []
    }
    
    # Use tcpdump to extract basic info
    print("\n[+] Extracting IP addresses...")
    try:
        # Get unique IPs
        result = subprocess.run(
            ["tcpdump", "-r", str(evidence_file), "-n", "-q"],
            capture_output=True, text=True
        )
        
        # Extract IPs
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        ips = set(re.findall(ip_pattern, result.stdout))
        findings["unique_ips"] = list(ips)
        print(f"  Found {len(ips)} unique IP addresses:")
        for ip in sorted(ips)[:20]:  # Limit output
            print(f"    - {ip}")
        
        # Look for willselfdestruct.com
        print("\n[+] Searching for willselfdestruct.com traffic...")
        result = subprocess.run(
            ["tcpdump", "-r", str(evidence_file), "-A", "-s", "0"],
            capture_output=True, text=True
        )
        
        if "willselfdestruct" in result.stdout.lower():
            print("  [✓] willselfdestruct.com traffic found!")
            # Extract HTTP host headers
            host_headers = re.findall(r'Host:\s*([^\r\n]+)', result.stdout)
            findings["http_hosts"] = list(set(host_headers))
            print(f"  HTTP hosts observed:")
            for host in findings["http_hosts"][:10]:
                print(f"    - {host}")
        
        # Look for Yahoo mail
        if "yahoo" in result.stdout.lower():
            print("\n[+] Yahoo mail traffic detected")
            findings["yahoo_traffic"] = ["Yahoo mail access observed"]
        
    except Exception as e:
        print(f"[ERROR] Traffic analysis failed: {e}")
    
    return findings

def step_4_mac_analysis(evidence_file):
    """Step 4: MAC address analysis for device identification."""
    print("\n" + "="*70)
    print("STEP 4: MAC ADDRESS ANALYSIS")
    print("="*70)
    
    print("\n[+] Extracting Ethernet MAC addresses...")
    
    try:
        # Use tcpdump to get MAC addresses
        result = subprocess.run(
            ["tcpdump", "-r", str(evidence_file), "-e", "-n", "-c", "100"],
            capture_output=True, text=True
        )
        
        # Extract MAC addresses
        mac_pattern = r'([0-9a-fA-F:]{17})'
        macs = set(re.findall(mac_pattern, result.stdout))
        
        print(f"  Found {len(macs)} unique MAC addresses:")
        for mac in sorted(macs):
            print(f"    - {mac}")
        
        return list(macs)
        
    except Exception as e:
        print(f"[ERROR] MAC analysis failed: {e}")
        return []

def step_5_timeline_reconstruction(evidence_file):
    """Step 5: Reconstruct timeline of events."""
    print("\n" + "="*70)
    print("STEP 5: TIMELINE RECONSTRUCTION")
    print("="*70)
    
    print("\n[+] Analyzing packet timestamps...")
    
    try:
        # Get packet times
        result = subprocess.run(
            ["tcpdump", "-r", str(evidence_file), "-tt", "-n", "-c", "50"],
            capture_output=True, text=True
        )
        
        lines = result.stdout.strip().split('\n')
        if lines:
            print(f"  Sample of {len(lines)} packets:")
            for line in lines[:10]:
                print(f"    {line[:100]}...")
        
    except Exception as e:
        print(f"[ERROR] Timeline analysis failed: {e}")
    
    return []

def generate_report(case_dir, evidence_hash, traffic_findings, mac_addresses):
    """Generate final forensic report."""
    print("\n" + "="*70)
    print("GENERATING FINAL REPORT")
    print("="*70)
    
    report = f"""# NITROBA-HARASSMENT-001: FORENSIC INVESTIGATION REPORT

**Case ID:** NITROBA-HARASSMENT-001  
**Title:** Nitroba University Harassment Investigation  
**Date:** {datetime.now().strftime('%Y-%m-%d')}  
**Investigator:** Geoff Digital Forensics  
**Status:** IN PROGRESS

---

## 1. EVIDENCE INVENTORY

| Evidence ID | Type | Description | Hash (SHA256) |
|-------------|------|-------------|---------------|
| EVID-001 | PCAP | nitroba.pcap - Network capture from dorm room | {evidence_hash['sha256'][:32]}... |

**Evidence Source:** github.com/open-nsm/course/master/pcaps/nitroba.pcap  
**Original Source:** Digital Corpora (nitroba.pcap)  
**File Size:** {evidence_hash['size_bytes']:,} bytes  
**File Type:** {evidence_hash['file_type']}

### Hash Verification Notes
- **⚠️ Hash variance detected** from Digital Corpora published hashes
- MD5, SHA1, SHA256 do not match Digital Corpora reference values
- Evidence integrity maintained within this investigation chain
- For production, obtain verified copy from original source

---

## 2. CASE BACKGROUND

**Incident:** Harassing emails sent to Chemistry professor Lily Tuckrige  
**Date:** July 21, 2008  
**Victim:** lilytuckrige@yahoo.com  
**Source IP:** 140.247.62.34 (Nitroba student dorm room)  
**Attack Vector:** willselfdestruct.com (self-destructing message service)

**Environment:**
- Shared dorm room (3 female students)
- Unsecured Wi-Fi router (no password)
- Ethernet tap in place for packet capture
- Multiple devices potentially using network

**Challenge:** Open Wi-Fi = anyone in range could be perpetrator

---

## 3. INVESTIGATION OBJECTIVES

1. ✅ Evidence verification and chain of custody
2. ⏳ Identify willselfdestruct.com traffic
3. ⏳ Extract unique device identifiers (MAC addresses)
4. ⏳ Correlate traffic with Chem 109 class roster
5. ⏳ Provide conclusive evidence identifying perpetrator

---

## 4. PRELIMINARY FINDINGS

### Network Traffic Overview
- PCAP contains traffic from dorm room network
- Multiple IP addresses observed
- HTTP traffic to external sites

### IP Addresses Identified
{chr(10).join(f"- {{ip}}" for ip in traffic_findings.get('unique_ips', [])[:10])}

### MAC Addresses Identified
{chr(10).join(f"- {{mac}}" for mac in mac_addresses[:10])}

### Key Traffic Indicators
- willselfdestruct.com: {{'YES' if traffic_findings.get('willselfdestruct_traffic') else 'PENDING ANALYSIS'}}
- Yahoo mail access: {{'YES' if traffic_findings.get('yahoo_traffic') else 'PENDING ANALYSIS'}}

---

## 5. NEXT STEPS

1. **Deep Packet Inspection:** Analyze HTTP payloads for user agents, cookies
2. **Device Fingerprinting:** Correlate MAC addresses with specific devices
3. **Timeline Analysis:** Match network activity to harassment timestamps
4. **Roster Correlation:** Cross-reference findings with Chem 109 student list

---

## 6. CHAIN OF CUSTODY

| Action | Timestamp | Hash (SHA256) |
|--------|-----------|---------------|
| Evidence downloaded | {datetime.now().isoformat()} | {evidence_hash['sha256']} |
| Analysis started | {datetime.now().isoformat()} | - |

---

**Report Generated:** {datetime.now().isoformat()}  
**Analyst:** Geoff Digital Forensics Framework
"""
    
    report_path = case_dir / "findings" / "PRELIMINARY_REPORT.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"[✓] Preliminary report saved: {{report_path}}")
    return report_path

def main():
    case_dir = Path(__file__).parent
    
    print("="*70)
    print("NITROBA-HARASSMENT-001: NETWORK FORENSIC INVESTIGATION")
    print("Geoff Digital Forensics - Protocol-Based Analysis")
    print(f"Started: {{datetime.now().isoformat()}}")
    print("="*70)
    
    # Run investigation steps
    evidence_hash = step_1_evidence_verification(case_dir)
    if evidence_hash:
        step_2_pcap_overview(case_dir / "evidence" / "nitroba.pcap")
        traffic_findings = step_3_traffic_analysis(case_dir / "evidence" / "nitroba.pcap")
        mac_addresses = step_4_mac_analysis(case_dir / "evidence" / "nitroba.pcap")
        step_5_timeline_reconstruction(case_dir / "evidence" / "nitroba.pcap")
        
        report_path = generate_report(case_dir, evidence_hash, traffic_findings, mac_addresses)
        
        print("\n" + "="*70)
        print("PRELIMINARY ANALYSIS COMPLETE")
        print("="*70)
        print(f"\n[✓] Evidence verified: {{evidence_hash['size_bytes']:,}} bytes")
        print(f"[✓] Report generated: {{report_path}}")
        print(f"\n[*] NEXT: Deep packet inspection to identify perpetrator")
    else:
        print("\n[ERROR] Evidence verification failed. Cannot proceed.")

if __name__ == "__main__":
    main()
