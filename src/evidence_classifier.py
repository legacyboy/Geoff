#!/usr/bin/env python3
"""
AI-Based Evidence Classifier — Uses file headers, LLM reasoning, and Critic validation
to classify forensic evidence beyond simple filename matching.

Usage:
    from evidence_classifier import AIEvidenceClassifier
    classifier = AIEvidenceClassifier(orchestrator, call_llm_func)
    inventory = classifier.classify_evidence(evidence_path)
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


class AIEvidenceClassifier:
    """
    Multi-stage evidence classifier:
    1. Fast pass: File extension matching (existing)
    2. Header analysis: python-magic / file command for type detection
    3. LLM reasoning: Forensicate file purpose, OS, and evidence type
    4. Critic validation: Verify classification correctness
    """

    def __init__(self, orchestrator, call_llm_func):
        """
        Args:
            orchestrator: ExtendedOrchestrator for running tools
            call_llm_func: Function to call LLM (e.g., call_llm)
        """
        self.orchestrator = orchestrator
        self.call_llm = call_llm_func
        self.classifications_log = []

    def classify_evidence(self, evidence_path: Path) -> dict:
        """
        Main entry point. Returns enhanced inventory with AI-classified evidence.
        """
        # Stage 1: Fast pass (extension-based)
        inventory = self._fast_classify(evidence_path)
        
        # Stage 2: Header analysis for ambiguous files
        self._header_classify(inventory)
        
        # Stage 3: LLM reasoning for remaining ambiguous files
        self._llm_classify(inventory)
        
        # Stage 4: Critic validation
        self._critic_validate(inventory)
        
        return inventory

    # ------------------------------------------------------------------
    # Stage 1: Fast Classification (extension-based, existing)
    # ------------------------------------------------------------------
    def _fast_classify(self, evidence_path: Path) -> dict:
        """Quick classification by filename extension and name."""
        inventory = {
            "disk_images": [],
            "memory_dumps": [],
            "pcaps": [],
            "evtx_logs": [],
            "syslogs": [],
            "registry_hives": [],
            "mobile_backups": [],
            "other_files": [],
            "ai_classified": [],  # NEW: track AI-classified files
            "total_size_bytes": 0,
            "file_hashes": {},
            "classification_confidence": {},  # path -> confidence score
        }
        
        disk_ext = {'.e01', '.ee01', '.e02', '.e03', '.e04', '.dd', '.raw', '.img', '.001', '.002', '.aff', '.aff4', '.ex01', '.vmdk', '.vhd', '.vdi'}
        mem_ext  = {'.vmem', '.mem', '.dmp', '.core', '.lin', '.vmss', '.vmsn'}
        pcap_ext = {'.pcap', '.pcapng', '.cap'}
        registry_names = {'ntuser.dat', 'system', 'software', 'security', 'sam', 'amcache.hve',
                          'usrclass.dat', 'default', 'system.sav', 'software.sav'}
        mobile_indicators = {'info.plist', 'manifest.db', 'manifest.plist'}
        syslog_names = {'syslog', 'auth.log', 'kern.log', 'messages', 'secure', 'auth.log.1', 'daemon.log'}
        
        for item in evidence_path.rglob('*'):
            if not item.is_file():
                continue
            
            try:
                size = item.stat().st_size
                inventory["total_size_bytes"] += size
            except OSError:
                pass
            
            ext = item.suffix.lower()
            name_lower = item.name.lower()
            
            # Known types
            if ext in disk_ext:
                inventory["disk_images"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.9  # High confidence
            elif ext in mem_ext:
                inventory["memory_dumps"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.9
            elif ext in pcap_ext:
                inventory["pcaps"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.9
            elif ext == '.evtx':
                inventory["evtx_logs"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.9
            elif name_lower in registry_names:
                inventory["registry_hives"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.95
            elif name_lower in syslog_names or name_lower.startswith('syslog'):
                inventory["syslogs"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.85
            elif name_lower in mobile_indicators:
                inventory["mobile_backups"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.9
            else:
                # Ambiguous — needs further analysis
                inventory["other_files"].append(str(item))
                inventory["classification_confidence"][str(item)] = 0.3  # Low confidence
        
        return inventory

    # ------------------------------------------------------------------
    # Stage 2: Header Analysis (python-magic / file command)
    # ------------------------------------------------------------------
    def _header_classify(self, inventory: dict):
        """Use file headers to classify ambiguous files."""
        other_files = inventory["other_files"][:20]  # Process first 20 to avoid overload
        
        for fpath in other_files:
            try:
                header_info = self._get_file_header_info(fpath)
                
                if header_info:
                    # Move from other_files to proper category
                    new_type = self._map_header_to_type(header_info)
                    if new_type and new_type != "other_files":
                        inventory["other_files"].remove(fpath)
                        inventory[new_type].append(fpath)
                        inventory["classification_confidence"][fpath] = 0.7
                        inventory["ai_classified"].append({
                            "path": fpath,
                            "method": "header_analysis",
                            "evidence_type": new_type,
                            "header": header_info[:200],
                            "confidence": 0.7,
                        })
                        self.classifications_log.append({
                            "file": fpath,
                            "method": "header_analysis",
                            "type": new_type,
                            "header": header_info[:200],
                        })
            except Exception as e:
                self._log("header_error", f"Failed to analyze {fpath}: {e}")

    def _get_file_header_info(self, fpath: str) -> Optional[str]:
        """Get file type from header using file command or python-magic."""
        # Try file command first
        try:
            result = subprocess.run(
                ['file', '-b', fpath],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip()
        except:
            pass
        
        # Fallback to python-magic
        try:
            import magic
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(fpath)
            
            file_type = magic.Magic()
            description = file_type.from_file(fpath)
            
            return f"{description} (MIME: {mime_type})"
        except ImportError:
            pass
        
        return None

    def _map_header_to_type(self, header_info: str) -> Optional[str]:
        """Map file header description to evidence type."""
        header_lower = header_info.lower()
        
        # Disk images
        if any(kw in header_lower for kw in ['ewf', 'expert witness', 'encase', 'raw data', 'disk image']):
            return "disk_images"
        
        # Memory dumps
        if any(kw in header_lower for kw in ['vmware', 'virtualbox', 'memory dump', 'crash dump', 'pagefile']):
            return "memory_dumps"
        
        # PCAP
        if any(kw in header_lower for kw in ['pcap', 'tcpdump', 'packet capture', 'libpcap']):
            return "pcaps"
        
        # EVTX
        if any(kw in header_lower for kw in ['evtx', 'windows event log']):
            return "evtx_logs"
        
        # Registry
        if any(kw in header_lower for kw in ['windows nt registry', 'registry file']):
            return "registry_hives"
        
        # Archives (could be mobile backup)
        if any(kw in header_lower for kw in ['zip archive', 'tar archive', 'ios backup', 'itunes backup']):
            return "mobile_backups"
        
        # Logs
        if any(kw in header_lower for kw in ['ascii text', 'utf-8 text', 'syslog']):
            # Could be log file — need more analysis
            return None  # Let LLM decide
        
        return None

    # ------------------------------------------------------------------
    # Stage 3: LLM Reasoning (for remaining ambiguous files)
    # ------------------------------------------------------------------
    def _llm_classify(self, inventory: dict):
        """Use LLM to classify remaining ambiguous files."""
        other_files = inventory["other_files"]
        
        # Batch files for efficiency (up to 5 per call)
        batch_size = 5
        for i in range(0, len(other_files), batch_size):
            batch = other_files[i:i + batch_size]
            
            # Gather file info
            file_info = []
            for fpath in batch:
                try:
                    stat = os.stat(fpath)
                    header = self._get_file_header_info(fpath) or "Unknown"
                    file_info.append({
                        "path": fpath,
                        "filename": Path(fpath).name,
                        "size_bytes": stat.st_size,
                        "header": header[:200],
                    })
                except Exception as e:
                    file_info.append({
                        "path": fpath,
                        "filename": Path(fpath).name,
                        "error": str(e),
                    })
            
            # Call LLM for classification
            try:
                classification = self._call_llm_classifier(file_info)
                
                for result in classification:
                    fpath = result.get("path")
                    new_type = result.get("evidence_type", "other_files")
                    confidence = result.get("confidence", 0.5)
                    reasoning = result.get("reasoning", "")
                    
                    if fpath and new_type != "other_files" and fpath in inventory["other_files"]:
                        inventory["other_files"].remove(fpath)
                        inventory[new_type].append(fpath)
                        inventory["classification_confidence"][fpath] = confidence
                        inventory["ai_classified"].append({
                            "path": fpath,
                            "method": "llm_reasoning",
                            "evidence_type": new_type,
                            "confidence": confidence,
                            "reasoning": reasoning,
                        })
                        self.classifications_log.append({
                            "file": fpath,
                            "method": "llm_reasoning",
                            "type": new_type,
                            "confidence": confidence,
                            "reasoning": reasoning,
                        })
            except Exception as e:
                self._log("llm_classify_error", f"Batch classification failed: {e}")

    def _call_llm_classifier(self, file_info: List[dict]) -> List[dict]:
        """Call LLM to classify files based on headers and names."""
        prompt = f"""You are a forensic evidence classifier. Analyze these files and classify them.

For each file, determine:
1. EVIDENCE_TYPE: One of [disk_images, memory_dumps, pcaps, evtx_logs, syslogs, registry_hives, mobile_backups, other_files]
2. CONFIDENCE: 0.0-1.0
3. REASONING: Brief explanation (1 sentence)
4. OS_HINT: If detectable (windows, linux, macos, ios, android, unknown)

Files to classify:
{json.dumps(file_info, indent=2, default=str)}

Respond ONLY with a JSON array. Example:
[
  {{
    "path": "/path/to/file",
    "evidence_type": "disk_images",
    "confidence": 0.85,
    "reasoning": "EWF header indicates EnCase disk image",
    "os_hint": "windows"
  }}
]
"""
        
        try:
            response = self.call_llm("forensic_classifier", prompt, temperature=0.1)
            
            # Extract JSON from response
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            
            return []
        except Exception as e:
            self._log("llm_error", f"LLM classification failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Stage 4: Critic Validation
    # ------------------------------------------------------------------
    def _critic_validate(self, inventory: dict):
        """Have Critic review classifications and flag issues."""
        ai_classified = inventory.get("ai_classified", [])
        
        if not ai_classified:
            return
        
        # Build validation prompt
        prompt = f"""You are a forensic evidence validation critic. Review these AI classifications.

For each classification, verify:
1. Is the evidence_type correct given the file header?
2. Is the confidence appropriate?
3. Are there any obvious mistakes?

Classifications to review:
{json.dumps(ai_classified[:10], indent=2, default=str)}

Respond with a JSON array of corrections. Use empty array if all correct:
[
  {{
    "path": "/path/to/file",
    "issue": "wrong_type",
    "corrected_type": "memory_dumps",
    "reasoning": "VMware header indicates memory dump, not disk image"
  }}
]
"""
        
        try:
            response = self.call_llm("critic_validator", prompt, temperature=0.1)
            
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                corrections = json.loads(json_match.group(0))
                
                for correction in corrections:
                    fpath = correction.get("path")
                    issue = correction.get("issue")
                    corrected_type = correction.get("corrected_type")
                    
                    if fpath and corrected_type and issue:
                        # Apply correction
                        for category in ["disk_images", "memory_dumps", "pcaps", "evtx_logs",
                                         "syslogs", "registry_hives", "mobile_backups", "other_files"]:
                            if fpath in inventory.get(category, []):
                                inventory[category].remove(fpath)
                                break
                        
                        inventory[corrected_type].append(fpath)
                        inventory["classification_confidence"][fpath] = 0.6  # Reduced after correction
                        
                        # Update ai_classified record
                        for record in inventory["ai_classified"]:
                            if record["path"] == fpath:
                                record["method"] = record.get("method", "") + "+critic_corrected"
                                record["evidence_type"] = corrected_type
                                record["critic_reasoning"] = correction.get("reasoning", "")
                                break
                        
                        self.classifications_log.append({
                            "file": fpath,
                            "method": "critic_correction",
                            "type": corrected_type,
                            "issue": issue,
                            "reasoning": correction.get("reasoning", ""),
                        })
        
        except Exception as e:
            self._log("critic_error", f"Critic validation failed: {e}")

    def _log(self, event: str, message: str):
        """Log classification events."""
        self.classifications_log.append({
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "message": message,
        })

    def get_classification_log(self) -> List[dict]:
        """Return the full classification audit trail."""
        return self.classifications_log


# ------------------------------------------------------------------
# Integration helper
# ------------------------------------------------------------------

def classify_with_ai(evidence_path: Path, orchestrator, call_llm_func) -> dict:
    """Convenience function for AI-based evidence classification."""
    classifier = AIEvidenceClassifier(orchestrator, call_llm_func)
    return classifier.classify_evidence(evidence_path)
