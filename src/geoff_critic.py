#!/usr/bin/env python3
"""
Geoff Critic - Validation Agent for DFIR Analysis
Reviews Geoff's tool outputs and conclusions for hallucinations and quality
"""

import json
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace/geoff-private/src')
import requests

class GeoffCritic:
    """
    Critic agent that validates Geoff's forensic analysis
    - Detects hallucinations in tool output interpretation
    - Validates that conclusions match actual tool results
    - Checks for false positives in IOC extraction
    - Ensures quality standards before git commit
    """
    
    def __init__(self, ollama_url: str = "http://localhost:11434", 
                 model: str = "qwen3-coder-next:cloud"):
        self.ollama_url = ollama_url
        self.model = model
        self.validation_log = []
        
        # Quality thresholds
        self.min_confidence = 0.7
        self.max_speculation = 0.3
    
    def _call_critic_llm(self, prompt: str) -> str:
        """Call LLM for validation review"""
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3}  # Lower temp for consistency
                },
                timeout=60
            )
            if response.status_code == 200:
                return response.json().get('response', '')
        except Exception as e:
            print(f"[CRITIC] LLM Error: {e}")
        return ""
    
    def validate_tool_output(self, tool_name: str, tool_params: Dict, 
                            raw_output: str, geoff_analysis: str) -> Dict[str, Any]:
        """
        Validate that Geoff's analysis matches actual tool output
        Returns validation result with confidence score
        """
        
        validation_prompt = f"""You are a forensic validation expert. Review the following:

TOOL EXECUTED: {tool_name}
PARAMETERS: {json.dumps(tool_params, indent=2)}

RAW TOOL OUTPUT:
{raw_output[:2000]}  # First 2000 chars

GEOFF'S ANALYSIS:
{geoff_analysis}

TASK: Validate Geoff's analysis against the raw tool output.

Check for:
1. HALLUCINATIONS: Did Geoff claim something not in the raw output?
2. FALSE POSITIVES: Did Geoff flag benign items as suspicious?
3. OMISSIONS: Did Geoff miss critical findings in the raw output?
4. CONFIDENCE: Is Geoff's confidence level appropriate for the evidence?

RESPOND IN JSON FORMAT:
{{
    "valid": true/false,
    "confidence_score": 0.0-1.0,
    "hallucinations_found": ["list any fabricated claims"],
    "false_positives": ["list benign items flagged incorrectly"],
    "missed_findings": ["list critical items Geoff missed"],
    "recommendations": ["suggested corrections or additions"],
    "validation_notes": "brief explanation"
}}

Be strict. If Geoff claims something not explicitly in the raw output, mark it as hallucination."""

        critic_response = self._call_critic_llm(validation_prompt)
        
        # Parse JSON response
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', critic_response, re.DOTALL)
            if json_match:
                validation_result = json.loads(json_match.group())
            else:
                validation_result = json.loads(critic_response)
        except:
            # Fallback if JSON parsing fails
            validation_result = {
                "valid": "true" in critic_response.lower(),
                "confidence_score": 0.5,
                "hallucinations_found": [],
                "false_positives": [],
                "missed_findings": [],
                "recommendations": ["Manual review required - JSON parse failed"],
                "validation_notes": critic_response[:500]
            }
        
        # Add metadata
        validation_result.update({
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
            "raw_output_length": len(raw_output),
            "analysis_length": len(geoff_analysis)
        })
        
        return validation_result
    
    def validate_timeline(self, events: List[Dict], geoff_conclusions: str) -> Dict[str, Any]:
        """Validate timeline consistency"""
        
        # Check for temporal impossibilities
        issues = []
        event_times = [e.get('timestamp') for e in events if e.get('timestamp')]
        
        # Sort and check for out-of-order events claimed by Geoff
        sorted_times = sorted(event_times)
        
        validation_prompt = f"""Validate timeline analysis:

EVENTS: {len(events)} timeline entries
TIME RANGE: {sorted_times[0] if sorted_times else 'N/A'} to {sorted_times[-1] if sorted_times else 'N/A'}

GEOFF'S CONCLUSIONS:
{geoff_conclusions}

Check for:
1. Temporal impossibilities (effects before causes)
2. Unsubstantiated claims about event sequences
3. Missing context for key events

JSON response with validation results."""

        critic_response = self._call_critic_llm(validation_prompt)
        
        return {
            "validation_type": "timeline",
            "event_count": len(events),
            "time_range": f"{sorted_times[0]} to {sorted_times[-1]}" if len(sorted_times) >= 2 else "N/A",
            "issues_detected": issues,
            "critic_review": critic_response[:1000],
            "timestamp": datetime.now().isoformat()
        }
    
    def validate_ioc_extraction(self, iocs: Dict[str, List], 
                               source_text: str) -> Dict[str, Any]:
        """Validate extracted IOCs are actually present in source"""
        
        false_positives = []
        validated_iocs = {}
        
        for ioc_type, ioc_list in iocs.items():
            validated_iocs[ioc_type] = []
            for ioc in ioc_list:
                if ioc in source_text:
                    validated_iocs[ioc_type].append(ioc)
                else:
                    false_positives.append({
                        "type": ioc_type,
                        "value": ioc,
                        "reason": "Not found in source text"
                    })
        
        return {
            "validation_type": "iocs",
            "original_ioc_count": sum(len(v) for v in iocs.values()),
            "validated_ioc_count": sum(len(v) for v in validated_iocs.values()),
            "false_positives": false_positives,
            "false_positive_count": len(false_positives),
            "validated_iocs": validated_iocs,
            "timestamp": datetime.now().isoformat()
        }
    
    def validate_sleuthkit_output(self, tool: str, output: str, 
                                  geoff_interpretation: str) -> Dict[str, Any]:
        """Specialized validation for SleuthKit outputs"""
        
        # Check for common misinterpretations
        issues = []
        
        # Validate file count claims
        file_count_match = re.search(r'(\d+)\s+files?', geoff_interpretation, re.IGNORECASE)
        if file_count_match:
            claimed_count = int(file_count_match.group(1))
            # Count actual files in output
            actual_files = len([line for line in output.split('\n') 
                              if line.strip() and not line.startswith('+')])
            if abs(claimed_count - actual_files) > (actual_files * 0.1):  # 10% tolerance
                issues.append(f"File count mismatch: Geoff claimed {claimed_count}, found ~{actual_files}")
        
        # Validate deleted file claims
        if "deleted" in geoff_interpretation.lower():
            deleted_in_output = "*" in output or "(del)" in output.lower()
            if not deleted_in_output:
                issues.append("Claimed deleted files but none marked in output")
        
        return {
            "tool": tool,
            "issues": issues,
            "validated": len(issues) == 0,
            "timestamp": datetime.now().isoformat()
        }
    
    def commit_validation(self, investigation_id: str, validation_result: Dict,
                         base_path: str = "/home/claw/.openclaw/workspace/geoff-private"):
        """Commit validation result to git for reproducibility"""
        
        # Create validation file
        validation_dir = Path(base_path) / "validations"
        validation_dir.mkdir(exist_ok=True)
        
        validation_file = validation_dir / f"{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(validation_file, 'w') as f:
            json.dump(validation_result, f, indent=2)
        
        # Git commit
        try:
            subprocess.run(['git', 'config', 'user.email'], cwd=base_path, 
                         capture_output=True, check=True)
        except:
            subprocess.run(['git', 'config', 'user.email', 'critic@geoff.local'], 
                         cwd=base_path, capture_output=True)
            subprocess.run(['git', 'config', 'user.name', 'Geoff Critic'], 
                         cwd=base_path, capture_output=True)
        
        try:
            subprocess.run(['git', 'add', str(validation_file)], 
                         cwd=base_path, check=True, capture_output=True)
            
            valid_str = "VALID" if validation_result.get('valid', False) else "NEEDS_REVIEW"
            commit_msg = f"[CRITIC-{valid_str}] {investigation_id}: {validation_result.get('validation_notes', 'Review complete')[:50]}"
            
            subprocess.run(['git', 'commit', '-m', commit_msg], 
                         cwd=base_path, capture_output=True)
            
            print(f"[CRITIC] Committed validation: {validation_file.name}")
            return True
        except Exception as e:
            print(f"[CRITIC] Git error: {e}")
            return False
    
    def get_validation_summary(self, investigation_id: str,
                              base_path: str = "/home/claw/.openclaw/workspace/geoff-private") -> Dict:
        """Get summary of all validations for an investigation"""
        
        validation_dir = Path(base_path) / "validations"
        if not validation_dir.exists():
            return {"validations": [], "total": 0, "passed": 0, "failed": 0}
        
        validations = []
        passed = 0
        failed = 0
        
        for val_file in sorted(validation_dir.glob(f"{investigation_id}_*.json")):
            try:
                with open(val_file) as f:
                    val = json.load(f)
                    validations.append(val)
                    if val.get('valid', False):
                        passed += 1
                    else:
                        failed += 1
            except:
                pass
        
        return {
            "investigation_id": investigation_id,
            "validations": validations,
            "total": len(validations),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / len(validations) if validations else 0
        }


class ValidationPipeline:
    """
    Pipeline that wraps Geoff's operations with Critic validation
    """
    
    def __init__(self, geoff_orchestrator, critic: Optional[GeoffCritic] = None):
        self.orchestrator = geoff_orchestrator
        self.critic = critic or GeoffCritic()
        self.investigation_id = None
    
    def start_investigation(self, case_name: str) -> str:
        """Start new investigation with validation tracking"""
        self.investigation_id = f"{case_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return self.investigation_id
    
    def execute_and_validate(self, step: Dict[str, Any], geoff_analysis: str = "") -> Dict[str, Any]:
        """
        Execute tool step, then validate results
        """
        module = step.get('module')
        function = step.get('function')
        params = step.get('params', {})
        
        # Execute tool
        print(f"[PIPELINE] Executing {module}.{function}...")
        tool_result = self.orchestrator.run_playbook_step(
            self.investigation_id or "unknown", step
        )
        
        # Get raw output
        raw_output = tool_result.get('stdout', '') or json.dumps(tool_result)
        
        # If Geoff provided analysis, validate it
        if geoff_analysis:
            print(f"[PIPELINE] Validating analysis...")
            validation = self.critic.validate_tool_output(
                f"{module}.{function}",
                params,
                raw_output,
                geoff_analysis
            )
            
            # Commit validation
            self.critic.commit_validation(
                self.investigation_id or "unknown",
                validation
            )
            
            # Add validation to result
            tool_result['critic_validation'] = validation
            tool_result['critic_approved'] = validation.get('valid', False)
        
        return tool_result
    
    def get_reproducibility_package(self) -> Dict:
        """Generate package for another investigator to reproduce"""
        if not self.investigation_id:
            return {"error": "No active investigation"}
        
        summary = self.critic.get_validation_summary(self.investigation_id)
        
        return {
            "investigation_id": self.investigation_id,
            "reproducibility": {
                "all_steps_validated": summary['failed'] == 0,
                "validation_pass_rate": summary['pass_rate'],
                "validation_count": summary['total']
            },
            "validation_summary": summary,
            "reproduction_instructions": [
                "1. Clone this git repository",
                "2. Checkout commit with investigation ID",
                "3. Review validations/ directory for step-by-step validation",
                "4. Run same tool commands as logged",
                "5. Compare results against critic validations"
            ]
        }


# For direct testing
if __name__ == "__main__":
    critic = GeoffCritic()
    
    # Test validation
    test_output = """
    r/r 1234:    /Users/admin/Desktop/evidence.doc
    r/r 1235:    /Users/admin/Desktop/normal.txt
    d/d 1236:    /Users/admin/Documents
    """
    
    test_analysis = "Found 3 files including evidence.doc and 2 deleted files."
    
    result = critic.validate_tool_output(
        "sleuthkit.fls",
        {"partition": "/dev/sda1"},
        test_output,
        test_analysis
    )
    
    print("Validation Result:")
    print(json.dumps(result, indent=2))
    
    # Should detect: claimed 2 deleted files but only 1 deleted marker
