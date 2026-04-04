#!/usr/bin/env python3
"""
Step 2: Threat Taxonomy Analysis
Extract TTPs, threat actors, and indicators from threat taxonomy data.
"""

import re
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def parse_threat_taxonomy(filepath):
    """Parse threat taxonomy markdown file and extract structured data."""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    analysis = {
        "actors": [],
        "ttps": [],
        "tools": [],
        "indicators": [],
        "mitre_mappings": [],
        "extracted_at": datetime.now().isoformat()
    }
    
    # Extract MITRE ATT&CK references
    mitre_pattern = r'(T\d{4}(\.\d{3})?)'
    mitre_refs = re.findall(mitre_pattern, content)
    analysis["mitre_mappings"] = list(set([m[0] for m in mitre_refs]))
    
    # Extract potential tool names (capitalized words in technical contexts)
    tool_patterns = [
        r'([A-Z][a-z]+(?:[A-Z][a-z]+)+)',  # CamelCase tools
        r'\b([a-z]+\.exe)\b',  # Windows executables
        r'\b(Shadow[\w\s]+)\b',  # Shadow-related tools
        r'\b(LockBit[\w\s]*)\b',  # Ransomware families
        r'\b(Cobalt[\w\s]+)\b',  # C2 frameworks
    ]
    
    tools_found = set()
    for pattern in tool_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            if len(match) > 3:
                tools_found.add(match)
    
    analysis["tools"] = sorted(tools_found)
    
    # Extract tactics (common cyber threat verbs)
    tactic_keywords = [
        'persistence', 'execution', 'privilege escalation', 'defense evasion',
        'credential access', 'discovery', 'lateral movement', 'collection',
        'exfiltration', 'command and control', 'initial access'
    ]
    
    content_lower = content.lower()
    for tactic in tactic_keywords:
        if tactic in content_lower:
            analysis["ttps"].append(tactic)
    
    # Extract potential IOCs (IPs, domains, hashes)
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ips = re.findall(ip_pattern, content)
    analysis["indicators"].extend([{"type": "ip", "value": ip} for ip in set(ips)])
    
    # Domain patterns
    domain_pattern = r'\b([a-zA-Z0-9-]+\.(?:com|net|org|io|xyz|top|info))\b'
    domains = re.findall(domain_pattern, content)
    analysis["indicators"].extend([{"type": "domain", "value": d} for d in set(domains)])
    
    return analysis

def generate_threat_timeline(analysis):
    """Generate a timeline of threat activities based on TTPs."""
    
    timeline = []
    kill_chain = [
        ("initial access", "Reconnaissance & Initial Access"),
        ("execution", "Execution"),
        ("persistence", "Persistence"),
        ("privilege escalation", "Privilege Escalation"),
        ("defense evasion", "Defense Evasion"),
        ("credential access", "Credential Access"),
        ("discovery", "Discovery"),
        ("lateral movement", "Lateral Movement"),
        ("collection", "Collection"),
        ("command and control", "Command & Control"),
        ("exfiltration", "Exfiltration")
    ]
    
    for tactic, phase in kill_chain:
        if tactic in analysis["ttps"]:
            timeline.append({
                "phase": phase,
                "tactic": tactic,
                "tools": [t for t in analysis["tools"] if len(t) < 15][:3],
                "mitre_techniques": [m for m in analysis["mitre_mappings"] if m.startswith("T")][:2]
            })
    
    return timeline

if __name__ == "__main__":
    import sys
    
    filepath = sys.argv[1] if len(sys.argv) > 1 else "/home/claw/.openclaw/workspace/forensics/threat_taxonomy.md"
    
    print(f"[ANALYZING] Threat taxonomy: {filepath}")
    analysis = parse_threat_taxonomy(filepath)
    
    print(f"\n[RESULTS]")
    print(f"  Tools identified: {len(analysis['tools'])}")
    print(f"  TTPs found: {len(analysis['ttps'])}")
    print(f"  MITRE mappings: {len(analysis['mitre_mappings'])}")
    print(f"  Indicators: {len(analysis['indicators'])}")
    
    timeline = generate_threat_timeline(analysis)
    print(f"\n[THREAT TIMELINE]")
    for i, event in enumerate(timeline, 1):
        print(f"  {i}. {event['phase']}")
    
    # Save analysis
    output_path = Path(__file__).parent.parent / "findings" / "threat_analysis.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump({
            "analysis": analysis,
            "timeline": timeline,
            "generated_at": datetime.now().isoformat()
        }, f, indent=2)
    
    print(f"\n[SAVED] Analysis written to: {output_path}")
