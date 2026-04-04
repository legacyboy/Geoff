#!/usr/bin/env python3
"""
Step 1: Evidence Collection and Verification
"""

import hashlib
import json
from pathlib import Path
from datetime import datetime

def calculate_hashes(filepath):
    """Calculate MD5, SHA1, SHA256 hashes of evidence file."""
    hashes = {}
    filepath = Path(filepath)
    
    if not filepath.exists():
        return {"error": f"File not found: {filepath}"}
    
    # Calculate hashes
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    
    hashes = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "file_size": filepath.stat().st_size,
        "file_path": str(filepath),
        "timestamp": datetime.now().isoformat()
    }
    
    return hashes

def collect_evidence(manifest_path):
    """Collect and verify all evidence items."""
    with open(manifest_path) as f:
        manifest = json.load(f)
    
    results = {
        "case_id": manifest["case_id"],
        "collection_time": datetime.now().isoformat(),
        "evidence_verified": []
    }
    
    for item in manifest["evidence_items"]:
        print(f"\n[COLLECTING] {item['id']}: {item['description']}")
        
        if Path(item["path"]).exists():
            hashes = calculate_hashes(item["path"])
            results["evidence_verified"].append({
                "id": item["id"],
                "type": item["type"],
                "hashes": hashes,
                "status": "verified"
            })
            print(f"  ✓ Verified - Size: {hashes['file_size']} bytes")
            print(f"  ✓ SHA256: {hashes['sha256'][:16]}...")
        else:
            results["evidence_verified"].append({
                "id": item["id"],
                "type": item["type"],
                "status": "missing",
                "path": item["path"]
            })
            print(f"  ✗ File not found")
    
    return results

if __name__ == "__main__":
    import sys
    manifest = sys.argv[1] if len(sys.argv) > 1 else "../evidence/evidence_manifest.json"
    results = collect_evidence(manifest)
    print(json.dumps(results, indent=2))
