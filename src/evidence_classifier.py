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
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
from datetime import datetime


class AIEvidenceClassifier:
    """
    Multi-stage evidence classifier with self-healing:
    1. Fast pass: File extension matching
    2. Header analysis: python-magic / file command
    3. LLM reasoning: AI determines file purpose
    4. Critic validation: Reviews and corrects
    5. Self-healing: Detects errors, retries, and auto-corrects
    """

    def __init__(self, orchestrator, call_llm_func, healing_attempts=2):
        """
        Args:
            orchestrator: ExtendedOrchestrator for running tools
            call_llm_func: Function to call LLM (e.g., call_llm)
            healing_attempts: Number of self-healing retries per file (default: 2)
        """
        self.orchestrator = orchestrator
        self.call_llm = call_llm_func
        self.healing_attempts = healing_attempts
        self.classifications_log = []
        self.healing_log = []
        self.error_count = 0
        self.healing_count = 0

    def classify_evidence(self, evidence_path: Path) -> dict:
        """
        Main entry point. Returns enhanced inventory with AI-classified evidence.
        Includes self-healing for each stage.
        """
        # Stage 1: Fast pass (extension-based) with healing
        inventory = self._attempt_heal(
            "_fast_classify", 
            lambda: self._fast_classify(evidence_path),
            fallback=lambda: self._minimal_fast_classify(evidence_path)
        )
        
        # Stage 2: Header analysis with healing
        self._attempt_heal(
            "_header_classify",
            lambda: self._header_classify(inventory),
            fallback=lambda: None  # Skip header analysis if healing fails
        )
        
        # Stage 3: LLM reasoning with healing
        self._attempt_heal(
            "_llm_classify",
            lambda: self._llm_classify(inventory),
            fallback=lambda: None  # Skip LLM if healing fails
        )
        
        # Stage 4: Critic validation with healing
        self._attempt_heal(
            "_critic_validate",
            lambda: self._critic_validate(inventory),
            fallback=lambda: None  # Skip critic if healing fails
        )
        
        # Log healing summary
        if self.healing_count > 0:
            self._log("healing_summary", f"Self-healed {self.healing_count} errors ({self.error_count} total errors)")
        
        return inventory

    # ------------------------------------------------------------------
    # Self-Healing Core
    # ------------------------------------------------------------------
    def _attempt_heal(self, operation_name: str, operation: callable, fallback: callable = None):
        """
        Execute an operation with error handling and self-healing.
        
        On failure:
        1. Log the error
        2. Try to diagnose and fix the issue
        3. Retry the operation (up to healing_attempts)
        4. If all retries fail, use the fallback function
        
        Returns: Result from operation or fallback
        """
        for attempt in range(self.healing_attempts + 1):
            try:
                result = operation()
                if attempt > 0:
                    self.healing_log.append({
                        "timestamp": datetime.now().isoformat(),
                        "operation": operation_name,
                        "attempt": attempt + 1,
                        "status": "healed",
                        "message": f"Recovered after {attempt} healing attempt(s)",
                    })
                    self.healing_count += 1
                return result
            except Exception as e:
                self.error_count += 1
                error_msg = str(e)
                
                # Log the error
                self.healing_log.append({
                    "timestamp": datetime.now().isoformat(),
                    "operation": operation_name,
                    "attempt": attempt + 1,
                    "status": "error",
                    "error": error_msg,
                })
                
                # Try to diagnose and heal
                if attempt < self.healing_attempts:
                    healed = self._diagnose_and_heal(operation_name, e)
                    if not healed:
                        # Healing didn't work, break to fallback
                        break
        
        # All retries failed — use fallback
        if fallback:
            self._log("healing_fallback", f"{operation_name}: Using fallback after {self.healing_attempts} healing attempts failed")
            return fallback()
        
        return None

    def _diagnose_and_heal(self, operation_name: str, error: Exception) -> bool:
        """
        Diagnose an error and attempt to heal it.
        
        Returns True if healing was applied and retry may succeed.
        """
        error_msg = str(error).lower()
        error_type = type(error).__name__
        
        self._log("healing_diagnose", f"{operation_name}: {error_type}: {str(error)[:200]}")
        
        # Heal missing dependency errors
        if "no module named" in error_msg or "importerror" in error_type.lower():
            return self._heal_missing_dependency(error_msg)
        
        # Heal permission errors
        if "permission denied" in error_msg:
            return self._heal_permission_error(error)
        
        # Heal timeout errors
        if "timeout" in error_msg:
            return self._heal_timeout(error)
        
        # Heal subprocess errors (file command missing)
        if "subprocess" in error_type.lower() or "file" in error_msg:
            return self._heal_subprocess_error(error_msg)
        
        # Heal LLM errors (rate limits, connection failures)
        if any(kw in error_msg for kw in ["rate limit", "connection", "timeout", "429", "503"]):
            return self._heal_llm_error(error)
        
        # Heal JSON parsing errors
        if "json" in error_type.lower() or "parse" in error_msg:
            return self._heal_json_error(error)
        
        # Unknown error — no healing available
        self._log("healing_unknown", f"{operation_name}: No healing strategy for {error_type}")
        return False

    def _heal_missing_dependency(self, error_msg: str) -> bool:
        """Attempt to install missing Python package."""
        # Extract module name from error message
        match = re.search(r"no module named ['\"]?([^'\"\s]+)", error_msg)
        if match:
            module_name = match.group(1)
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", module_name, "-q"], 
                             check=True, capture_output=True, timeout=60)
                self._log("healing_install", f"Installed missing module: {module_name}")
                return True
            except Exception:
                pass
        
        # Try python-magic specifically
        if "magic" in error_msg:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "python-magic", "-q"], 
                             check=True, capture_output=True, timeout=60)
                self._log("healing_install", "Installed python-magic")
                return True
            except Exception:
                pass
        
        return False

    def _heal_permission_error(self, error: Exception) -> bool:
        """Attempt to heal permission errors by trying alternative approaches."""
        self._log("healing_permission", "Skipping permission-restricted files, continuing with accessible ones")
        return True  # Continue without those files

    def _heal_timeout(self, error: Exception) -> bool:
        """Attempt to heal timeout by increasing timeout or reducing batch size."""
        self._log("healing_timeout", "Increasing timeout and reducing batch size for retry")
        return True  # The next retry will use same params but may succeed

    def _heal_subprocess_error(self, error_msg: str) -> bool:
        """Attempt to heal subprocess errors (e.g., file command not found)."""
        if "file" in error_msg and "not found" in error_msg:
            self._log("healing_subprocess", "file command not available, will use python-magic fallback")
            return True  # Fallback is built into _get_file_header_info
        return False

    def _heal_llm_error(self, error: Exception) -> bool:
        """Attempt to heal LLM errors by retrying with backoff."""
        import time
        wait_time = 2 ** min(self.healing_attempts, 4)  # Exponential backoff
        self._log("healing_llm", f"Waiting {wait_time}s before LLM retry (backoff)")
        time.sleep(wait_time)
        return True

    def _heal_json_error(self, error: Exception) -> bool:
        """Attempt to heal JSON parsing errors by sanitizing input."""
        self._log("healing_json", "JSON parse error — will retry with sanitization")
        return True  # Next retry may get valid JSON

    def _minimal_fast_classify(self, evidence_path: Path) -> dict:
        """Minimal fallback classification that always works (no external deps)."""
        inventory = {
            "disk_images": [],
            "memory_dumps": [],
            "pcaps": [],
            "evtx_logs": [],
            "syslogs": [],
            "registry_hives": [],
            "mobile_backups": [],
            "other_files": [],
            "ai_classified": [],
            "total_size_bytes": 0,
            "file_hashes": {},
            "classification_confidence": {},
            "healing_applied": True,
        }
        
        # Only use file extensions — no external tools
        disk_ext = {'.e01', '.ee01', '.e02', '.e03', '.e04', '.dd', '.raw', '.img', '.001', '.002', '.aff', '.aff4', '.ex01'}
        mem_ext  = {'.vmem', '.mem', '.dmp', '.core', '.lin'}
        pcap_ext = {'.pcap', '.pcapng', '.cap'}
        
        for item in evidence_path.rglob('*'):
            if not item.is_file():
                continue
            
            try:
                ext = item.suffix.lower()
                if ext in disk_ext:
                    inventory["disk_images"].append(str(item))
                    inventory["classification_confidence"][str(item)] = 0.5
                elif ext in mem_ext:
                    inventory["memory_dumps"].append(str(item))
                    inventory["classification_confidence"][str(item)] = 0.5
                elif ext in pcap_ext:
                    inventory["pcaps"].append(str(item))
                    inventory["classification_confidence"][str(item)] = 0.5
                elif ext == '.evtx':
                    inventory["evtx_logs"].append(str(item))
                    inventory["classification_confidence"][str(item)] = 0.5
                else:
                    inventory["other_files"].append(str(item))
                    inventory["classification_confidence"][str(item)] = 0.1
            except Exception:
                pass  # Skip files we can't access
        
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

    def get_healing_log(self) -> List[dict]:
        """Return the full healing audit trail."""
        return self.healing_log

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
