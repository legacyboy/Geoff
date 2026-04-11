#!/usr/bin/env python3
"""
Geoff Forensicator - Tool Execution Agent
Receives instructions from Manager, executes forensic tools, returns results
Uses qwen2.5-coder:32b for code/tool understanding
"""

import json
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
import sys

# Forensicator Model Configuration
# Local: qwen2.5-coder:32b | Cloud: qwen2.5-coder (via API)
FORENSICATOR_MODEL = os.environ.get('GEOFF_FORENSICATOR_MODEL', "qwen2.5-coder:32b")

def call_forensicator_llm(prompt: str, ollama_url: str = "http://localhost:11434") -> str:
    """Call Forensicator LLM for tool understanding"""
    try:
        response = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": FORENSICATOR_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1}  # Low temp for precision
            },
            timeout=120
        )
        if response.status_code == 200:
            return response.json().get('response', '')
    except Exception as e:
        print(f"[FORENSICATOR] LLM Error: {e}")
    return ""

class ForensicatorAgent:
    """
    Forensicator agent that executes forensic tools
    - Receives high-level instructions from Manager
    - Translates to specific tool commands
    - Executes via subprocess
    - Returns structured results
    - Self-validates output before returning
    """
    
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        self.execution_log = []
        
    def execute_task(self, instruction: str, evidence_path: str = None) -> Dict[str, Any]:
        """
        Execute a forensic task based on Manager instruction
        Returns structured results with validation
        """
        result = {
            "instruction": instruction,
            "evidence": evidence_path,
            "timestamp": datetime.now().isoformat(),
            "commands_executed": [],
            "raw_outputs": [],
            "validated_output": None,
            "errors": [],
            "confidence": 0.0
        }
        
        # Step 1: Parse instruction into tool commands
        tool_plan = self._parse_instruction(instruction, evidence_path)
        
        # Step 2: Execute each command with validation
        for cmd_info in tool_plan:
            cmd_result = self._execute_command(cmd_info)
            result["commands_executed"].append(cmd_info)
            result["raw_outputs"].append(cmd_result)
            
            if cmd_result.get("error"):
                result["errors"].append(cmd_result["error"])
        
        # Step 3: Self-validate outputs (double-check)
        validated = self._validate_outputs(result["raw_outputs"], instruction)
        result["validated_output"] = validated
        result["confidence"] = validated.get("confidence", 0.0)
        
        # Step 4: Log execution
        self.execution_log.append(result)
        
        return result
    
    def _parse_instruction(self, instruction: str, evidence_path: str) -> List[Dict]:
        """Parse natural language instruction into tool commands"""
        prompt = f"""
You are a forensic tool expert. Parse this instruction into specific commands.

Instruction: "{instruction}"
Evidence path: {evidence_path or "N/A"}

Available tools:
- mmls: Show partition table
- fsstat: Show filesystem info
- fls: List files (use -r for recursive)
- icat: Extract file content
- strings: Extract strings (-a -n 8)
- yara: Scan with YARA rules
- vol.py: Volatility memory analysis

Respond ONLY in JSON format:
{{
    "commands": [
        {{"tool": "mmls", "args": ["evidence.E01"], "reason": "Show partitions"}},
        {{"tool": "fsstat", "args": ["-o", "2048", "evidence.E01"], "reason": "NTFS info"}}
    ],
    "expected_output": "What we expect to find"
}}
"""
        
        try:
            response = call_forensicator_llm(prompt, self.ollama_url)
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group())
                return plan.get("commands", [])
        except Exception as e:
            print(f"[FORENSICATOR] Parse error: {e}")
        
        # Fallback: simple keyword matching
        return self._fallback_parse(instruction, evidence_path)
    
    def _fallback_parse(self, instruction: str, evidence_path: str) -> List[Dict]:
        """Simple keyword-based command parsing fallback"""
        commands = []
        
        if evidence_path:
            if "partition" in instruction.lower():
                commands.append({"tool": "mmls", "args": [evidence_path], "reason": "Show partition table"})
            
            if "filesystem" in instruction.lower() or "fsstat" in instruction.lower():
                commands.append({"tool": "fsstat", "args": [evidence_path], "reason": "Show filesystem info"})
            
            if "list" in instruction.lower() or "files" in instruction.lower():
                commands.append({"tool": "fls", "args": ["-r", evidence_path], "reason": "List files recursively"})
            
            if "strings" in instruction.lower():
                commands.append({"tool": "strings", "args": ["-a", "-n", "8", evidence_path], "reason": "Extract strings"})
            
            if "memory" in instruction.lower() or "volatility" in instruction.lower():
                commands.append({"tool": "vol.py", "args": ["-f", evidence_path, "windows.pslist.PsList"], "reason": "List memory processes"})
            
            if "yara" in instruction.lower() or "scan" in instruction.lower():
                commands.append({"tool": "yara", "args": ["/usr/share/yara/rules/index.yar", evidence_path], "reason": "YARA malware scan"})
        
        return commands
    
    def _execute_command(self, cmd_info: Dict) -> Dict:
        """Execute a single tool command with error handling"""
        tool = cmd_info.get("tool", "")
        args = cmd_info.get("args", [])
        reason = cmd_info.get("reason", "")
        
        result = {
            "tool": tool,
            "args": args,
            "reason": reason,
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error": None,
            "execution_time_ms": 0
        }
        
        try:
            start_time = datetime.now()
            
            # Build command
            full_cmd = [tool] + args
            
            # Execute with timeout
            process = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds() * 1000
            
            result["stdout"] = process.stdout
            result["stderr"] = process.stderr
            result["returncode"] = process.returncode
            result["execution_time_ms"] = execution_time
            
            if process.returncode != 0:
                result["error"] = f"Tool returned non-zero exit code: {process.returncode}"
                
        except subprocess.TimeoutExpired:
            result["error"] = "Command timed out after 300 seconds"
        except FileNotFoundError:
            result["error"] = f"Tool '{tool}' not found in PATH"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _validate_outputs(self, outputs: List[Dict], original_instruction: str) -> Dict:
        """
        Double-check outputs against expected results
        Self-validation before returning to Manager
        """
        validation = {
            "is_valid": True,
            "confidence": 1.0,
            "issues": [],
            "summary": ""
        }
        
        # Check for execution errors
        errors = [out for out in outputs if out.get("error")]
        if errors:
            validation["is_valid"] = False
            validation["confidence"] = 0.3
            validation["issues"].append(f"{len(errors)} commands failed")
        
        # Check for empty outputs
        empty_outputs = [out for out in outputs if not out.get("stdout") and out.get("returncode") == 0]
        if empty_outputs:
            validation["issues"].append(f"{len(empty_outputs)} commands returned empty output")
            validation["confidence"] *= 0.8
        
        # Generate summary
        if outputs:
            summary_parts = []
            for out in outputs:
                tool = out.get("tool", "unknown")
                if out.get("error"):
                    summary_parts.append(f"{tool}: ERROR - {out['error']}")
                else:
                    stdout_preview = out.get("stdout", "")[:200].replace("\n", " ")
                    summary_parts.append(f"{tool}: Success ({len(out.get('stdout', ''))} chars)")
            validation["summary"] = " | ".join(summary_parts)
        
        return validation
    
    def get_execution_history(self) -> List[Dict]:
        """Return execution log for audit trail"""
        return self.execution_log

# Global forensicator instance
forensicator = ForensicatorAgent()

if __name__ == "__main__":
    # Test mode
    print("Geoff Forensicator Agent")
    print(f"Model: {FORENSICATOR_MODEL}")
    print("Ready to execute forensic tasks")
