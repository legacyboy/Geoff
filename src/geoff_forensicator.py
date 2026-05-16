#!/usr/bin/env python3
"""
Geoff Forensicator - Tool Execution Agent
Receives instructions from Manager, executes forensic tools, returns raw results.
Uses qwen2.5-coder:32b for code/tool understanding.

Design: Execute tools, return results. No self-validation — that's the Critic's job.
"""

import json
import subprocess
import re
import os
from datetime import datetime
from typing import Dict, List, Any
import requests
import time

# Forensicator Model Configuration
# Set GEOFF_FORENSICATOR_MODEL to override, or GEOFF_PROFILE=cloud|local
# Defaults to the active profile from profiles.json
FORENSICATOR_MODEL = os.environ.get('GEOFF_FORENSICATOR_MODEL', "qwen3-coder-next:cloud")

OLLAMA_URL_DEFAULT = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
OLLAMA_API_KEY = os.environ.get('OLLAMA_API_KEY', '')

def _ollama_base_url():
    if OLLAMA_API_KEY:
        return 'https://ollama.com/api'
    return OLLAMA_URL_DEFAULT

def _ollama_headers():
    h = {'Content-Type': 'application/json'}
    if OLLAMA_API_KEY:
        h['Authorization'] = f'Bearer {OLLAMA_API_KEY}'
    return h


def call_forensicator_llm(prompt: str, ollama_url: str = None) -> str:
    """Call Forensicator LLM for tool understanding

    Returns the LLM response, or None on connection failure (after retries).
    The caller should treat None as "LLM unavailable" and mark the step
    needs_review rather than producing a finding with error text.
    """
    url = ollama_url or _ollama_base_url()
    _MAX_RETRY_TIME = 1800  # 30 minutes total retry window
    _BACKOFF_TIMES = [30, 60, 120, 240, 300]  # seconds, last value repeats
    _max_retries = 99  # effectively unlimited within time window
    _error_patterns = (
        "Having trouble connecting to Ollama",
        "Check OLLAMA_URL",
        "[ERROR] Ollama returned",
    )
    _start = time.time()

    for attempt in range(_max_retries):
        elapsed = time.time() - _start
        if elapsed > _MAX_RETRY_TIME:
            print(f"[FORENSICATOR] LLM retry timeout after {elapsed:.0f}s/{_MAX_RETRY_TIME}s")
            return None

        try:
            response = requests.post(
                f"{url}/generate",
                headers=_ollama_headers(),
                json={
                    "model": FORENSICATOR_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1}
                },
                timeout=300  # 5 min — cloud models can be slow
            )
            if response.status_code == 200:
                result_text = response.json().get('response', '')
                # Reject error messages that leaked into the response
                if any(pat in result_text for pat in _error_patterns):
                    wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                    remaining = _MAX_RETRY_TIME - elapsed
                    actual_wait = min(wait, remaining)
                    if actual_wait <= 0:
                        return None
                    print(f"[FORENSICATOR] Ollama error in response, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                    time.sleep(actual_wait)
                    continue
                return result_text
            else:
                wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait, remaining)
                if actual_wait <= 0:
                    return None
                print(f"[FORENSICATOR] Ollama HTTP {response.status_code}, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                time.sleep(actual_wait)
                continue
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
            remaining = _MAX_RETRY_TIME - elapsed
            actual_wait = min(wait, remaining)
            if actual_wait <= 0:
                return None
            print(f"[FORENSICATOR] LLM {type(e).__name__} retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
            time.sleep(actual_wait)
            continue
        except Exception as e:
            print(f"[FORENSICATOR] LLM Error (attempt {attempt+1}): {e}")
            wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
            remaining = _MAX_RETRY_TIME - elapsed
            actual_wait = min(wait, remaining)
            if actual_wait <= 0:
                return None
            time.sleep(actual_wait)
            continue
    return None  # All retries exceeded (should not normally reach here)

class ForensicatorAgent:
    """
    Forensicator agent that executes forensic tools.
    - Receives high-level instructions from Manager
    - Translates to specific tool commands via LLM
    - Executes via subprocess
    - Returns raw results (no self-validation)
    """

    ALLOWED_TOOLS = frozenset({
        'mmls', 'fsstat', 'fls', 'icat', 'istat', 'ils', 'blkls', 'jcat',
        'vol.py', 'volatility3',
        'strings', 'floss',
        'regripper', 'rip.pl',
        'log2timeline.py', 'psort.py', 'pinfo.py',
        'tshark', 'tcpflow',
        'die', 'exiftool', 'peframe', 'ssdeep', 'hashdeep', 'upx',
        'pdfid', 'pdf-parser', 'oledump', 'oledump.py', 'js-beautify',
        'radare2', 'r2',
        'clamscan', 'clamdscan',
        'cat', 'file', 'xxd', 'hexdump',
    })

    def __init__(self, ollama_url: str = None):
        self.ollama_url = ollama_url or OLLAMA_URL_DEFAULT
        self.execution_log = []

    def execute_task(self, instruction: str, evidence_path: str = None) -> Dict[str, Any]:
        """
        Execute a forensic task based on Manager instruction.
        Parse instruction -> execute commands -> return raw results.
        """
        result = {
            "instruction": instruction,
            "evidence": evidence_path,
            "timestamp": datetime.now().isoformat(),
            "commands_executed": [],
            "raw_outputs": [],
            "errors": [],
        }

        # Step 1: Parse instruction into tool commands
        tool_plan = self._parse_instruction(instruction, evidence_path)

        # Step 2: Execute each command
        for cmd_info in tool_plan:
            cmd_result = self._execute_command(cmd_info)
            result["commands_executed"].append(cmd_info)
            result["raw_outputs"].append(cmd_result)

            if cmd_result.get("error"):
                result["errors"].append(cmd_result["error"])

        # Step 3: Log execution
        self.execution_log.append(result)

        return result

    def _parse_instruction(self, instruction: str, evidence_path: str) -> List[Dict]:
        """Parse natural language instruction into tool commands"""
        safe_instruction = instruction.replace("\n", " ").replace("\r", " ").replace('"', '\\"')[:500]
        safe_path = (evidence_path or "N/A").replace("\n", " ").replace("\r", " ")[:500]
        prompt = f"""
You are a forensic tool expert. Parse this instruction into specific commands.

Instruction: "{safe_instruction}"
Evidence path: {safe_path}

Available tools:
- mmls: Show partition table
- fsstat: Show filesystem info
- fls: List files (use -r for recursive)
- icat: Extract file content
- strings: Extract strings (-a -n 8)
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

        return commands

    def interpret_step_result(
        self,
        playbook_id: str,
        module: str,
        function: str,
        params: Dict,
        result: Dict,
        device_context: Dict = None,
    ) -> Dict[str, Any]:
        """
        Interpret a completed playbook step result.
        Called by find_evil() after each successful tool execution so the
        Forensicator LLM can assess threat significance and flag follow-ups.
        Non-blocking: returns a minimal dict if the LLM is unavailable.
        """
        ctx = device_context or {}
        result_summary = json.dumps(result, default=str)[:2000]

        prompt = f"""You are a forensic analyst reviewing a tool result. Be concise and precise.

INVESTIGATION CONTEXT:
- Playbook: {playbook_id}
- Device: {ctx.get('device_id', 'unknown')} (OS: {ctx.get('os_type', 'unknown')})
- Step: {module}.{function}
- Params: {json.dumps(params, default=str)[:400]}

TOOL RESULT (excerpt):
{result_summary}

Assess this result. Respond ONLY in valid JSON (no extra text):
{{
    "significance": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
    "threat_indicators": ["specific indicators, e.g. psexesvc.exe in prefetch, or empty list"],
    "follow_up_needed": false,
    "follow_up_reason": null,
    "analyst_note": "one concise sentence interpreting the finding"
}}"""

        try:
            response = call_forensicator_llm(prompt, self.ollama_url)
            if response is None:
                # LLM unavailable after retries — mark as needs_review, not as a finding
                return {
                    "significance": "UNKNOWN",
                    "threat_indicators": [],
                    "follow_up_needed": True,
                    "follow_up_reason": "Ollama timeout - forensicator LLM unavailable, manual review required",
                    "analyst_note": None,
                    "error": "ollama_timeout",
                    "needs_review": True,
                    "unverified_reason": "Ollama timeout - forensicator interpretation failed",
                    "timestamp": datetime.now().isoformat(),
                }
            m = re.search(r'\{.*\}', response, re.DOTALL)
            if m:
                parsed = json.loads(m.group())
                parsed["timestamp"] = datetime.now().isoformat()
                return parsed
        except Exception as e:
            print(f"[FORENSICATOR] Interpretation error for {module}.{function}: {e}")

        return {
            "significance": "UNKNOWN",
            "threat_indicators": [],
            "follow_up_needed": False,
            "follow_up_reason": None,
            "analyst_note": None,
            "error": "forensicator_unavailable",
            "timestamp": datetime.now().isoformat(),
        }

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

        if tool not in self.ALLOWED_TOOLS:
            result["error"] = f"Tool '{tool}' not in allowlist"
            return result

        try:
            start_time = datetime.now()

            full_cmd = [tool] + args

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

    def get_execution_history(self) -> List[Dict]:
        """Return execution log for audit trail"""
        return self.execution_log


# Global forensicator instance
forensicator = ForensicatorAgent()

if __name__ == "__main__":
    print("Geoff Forensicator Agent")
    print(f"Model: {FORENSICATOR_MODEL}")
    print("Ready to execute forensic tasks")