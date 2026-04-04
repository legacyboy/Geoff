#!/usr/bin/env python3
"""
Step 3: IOC Extraction and Enrichment
Extract and classify all Indicators of Compromise.
"""

import re
import json
import hashlib
from pathlib import Path
from datetime import datetime

def extract_iocs(filepath):
    """Extract all IOCs from evidence files."""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    iocs = {
        "hashes": [],
        "ips": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "file_paths": [],
        "registry_keys": [],
        "mutant_names": [],
        "mutexes": []
    }
    
    # MD5 hashes
    md5_pattern = r'\b([a-fA-F0-9]{32})\b'
    md5s = re.findall(md5_pattern, content)
    for h in set(md5s):
        iocs["hashes"].append({"type": "md5", "value": h.lower()})
    
    # SHA256 hashes (64 chars)
    sha256_pattern = r'\b([a-fA-F0-9]{64})\b'
    sha256s = re.findall(sha256_pattern, content)
    for h in set(sha256s):
        iocs["hashes"].append({"type": "sha256", "value": h.lower()})
    
    # IP addresses
    ip_pattern = r'\b((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b'
    ips = re.findall(ip_pattern, content)
    for ip in set([i[0] for i in ips]):
        # Skip private IPs
        if not ip.startswith(('10.', '192.168.', '172.16.', '127.')):
            iocs["ips"].append({"value": ip, "context": "external"})
        else:
            iocs["ips"].append({"value": ip, "context": "internal"})
    
    # Domain names
    domain_pattern = r'\b([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})\b'
    domains = re.findall(domain_pattern, content)
    for d in set(domains):
        iocs["domains"].append({"value": d.lower(), "ioc_type": "domain"})
    
    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`[\]]+'
    urls = re.findall(url_pattern, content)
    for url in set(urls):
        iocs["urls"].append({"value": url, "defanged": url.replace('http', 'hxxp').replace('.', '[.]')})
    
    # Email addresses
    email_pattern = r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
    emails = re.findall(email_pattern, content)
    for e in set(emails):
        iocs["emails"].append({"value": e.lower(), "domain": e.split('@')[1]})
    
    # Windows file paths
    path_pattern = r'[C-Z]:\\[\\\w\-\.\s]+'
    paths = re.findall(path_pattern, content)
    for p in set(paths):
        iocs["file_paths"].append({"value": p, "type": "windows_path"})
    
    # Registry keys
    reg_pattern = r'HKEY_[A-Z_]+\\[\w\\]+'
    regs = re.findall(reg_pattern, content)
    for r in set(regs):
        iocs["registry_keys"].append({"value": r, "hive": r.split('\\')[0]})
    
    # Mutex/Mutant names
    mutex_pattern = r'(Global\\[A-Za-z0-9_]+|Local\\[A-Za-z0-9_]+)'
    mutexes = re.findall(mutex_pattern, content)
    for m in set(mutexes):
        iocs["mutexes"].append({"value": m, "type": "mutex"})
    
    return iocs

def classify_iocs(iocs):
    """Classify IOCs by threat level."""
    
    classification = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }
    
    # Critical: Known malware hashes, C2 domains
    for h in iocs["hashes"]:
        classification["critical"].append({"type": "hash", "value": h["value"], "reason": "malware_hash"})
    
    # High: External IPs, suspicious domains
    for ip in iocs["ips"]:
        if ip.get("context") == "external":
            classification["high"].append({"type": "ip", "value": ip["value"], "reason": "external_ip"})
        else:
            classification["medium"].append({"type": "ip", "value": ip["value"], "reason": "internal_ip"})
    
    for domain in iocs["domains"]:
        if any(s in domain["value"] for s in ['malware', 'c2', 'phish', 'hack']):
            classification["critical"].append({"type": "domain", "value": domain["value"], "reason": "suspicious_domain"})
        else:
            classification["high"].append({"type": "domain", "value": domain["value"], "reason": "observed_domain"})
    
    # Medium: URLs, emails
    for url in iocs["urls"]:
        classification["medium"].append({"type": "url", "value": url["value"], "defanged": url["defanged"]})
    
    for email in iocs["emails"]:
        classification["medium"].append({"type": "email", "value": email["value"]})
    
    # Low: File paths, registry
    for path in iocs["file_paths"]:
        classification["low"].append({"type": "file_path", "value": path["value"]})
    
    for reg in iocs["registry_keys"]:
        classification["low"].append({"type": "registry", "value": reg["value"], "hive": reg["hive"]})
    
    # Info: Mutexes
    for mutex in iocs["mutexes"]:
        classification["info"].append({"type": "mutex", "value": mutex["value"]})
    
    return classification

def generate_ioc_report(iocs, classification):
    """Generate IOC report in multiple formats."""
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_iocs": sum(len(v) for v in iocs.values()),
        "by_type": {k: len(v) for k, v in iocs.items()},
        "by_severity": {k: len(v) for k, v in classification.items()},
        "critical_iocs": classification["critical"],
        "high_iocs": classification["high"],
        "all_iocs": iocs
    }
    
    return report

if __name__ == "__main__":
    import sys
    
    filepath = sys.argv[1] if len(sys.argv) > 1 else "/home/claw/.openclaw/workspace/forensics/threat_taxonomy.md"
    
    print(f"[EXTRACTING] IOCs from: {filepath}")
    iocs = extract_iocs(filepath)
    
    print(f"\n[IOC SUMMARY]")
    for ioc_type, items in iocs.items():
        if items:
            print(f"  {ioc_type}: {len(items)}")
    
    classification = classify_iocs(iocs)
    report = generate_ioc_report(iocs, classification)
    
    print(f"\n[CLASSIFICATION]")
    for severity, items in classification.items():
        if items:
            print(f"  {severity.upper()}: {len(items)} IOCs")
            for item in items[:3]:  # Show first 3
                print(f"    - {item['type']}: {item['value'][:50]}...")
    
    # Save report
    findings_dir = Path(__file__).parent.parent / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    
    json_path = findings_dir / "ioc_report.json"
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n[SAVED] IOC report: {json_path}")
    
    # STIX format export
    stix_path = findings_dir / "iocs.stix"
    with open(stix_path, 'w') as f:
        f.write("# STIX 2.1 IOC Export\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        for severity in ["critical", "high", "medium"]:
            for ioc in classification[severity]:
                f.write(f"{ioc['type']},{ioc['value']},{severity}\n")
    print(f"[SAVED] STIX format: {stix_path}")
