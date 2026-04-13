#!/usr/bin/env python3
"""
Geoff Critic - Sanity Check Agent for DFIR Analysis
Reviews Geoff's tool outputs and conclusions for obvious hallucinations.
Two checks: 1) Are claimed findings actually in the raw output? 2) Any obvious nonsense?
"""

import json
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import sys
import os

# Add src directory to path (works for both local and deployed)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import requests


class GeoffCritic:
    """
    Critic agent that sanity-checks Geoff's forensic analysis.
    - Checks for obvious hallucinations (claims not in raw output)
    - Validates IOC extraction against source text
    - Commits validation results to git for reproducibility
    """

    def __init__(self, ollama_url: str = None,
                 model: str = "qwen3-coder-next:cloud"):
        self.ollama_url = ollama_url or os.environ.get('OLLAMA_URL', 'http://localhost:11434')
        self.model = model
        self._api_key = os.environ.get('OLLAMA_API_KEY', '')
        self.validation_log = []

    def _ollama_headers(self):
        h = {'Content-Type': 'application/json'}
        if self._api_key:
            h['Authorization'] = f'Bearer {self._api_key}'
        return h

    def _call_critic_llm(self, prompt: str) -> str:
        """Call LLM for sanity check review"""
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                headers=self._ollama_headers(),
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.2}
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
        Sanity check: does the analysis claim something contradicted by or
        absent from the raw output? That's it.
        """
        sanity_prompt = f"""You are a sanity checker. Compare the raw tool output to the analysis.

TOOL: {tool_name}
RAW OUTPUT (excerpt):
{raw_output[:3000]}

ANALYSIS:
{geoff_analysis}

Answer ONLY these two questions:
1. Does the analysis claim something NOT present in the raw output? (hallucination)
2. Is there any obvious nonsense? (e.g. impossible values, contradictory claims)

Respond in JSON:
{{
    "hallucinations": ["list claims not in raw output, or empty list"],
    "nonsense": ["list obvious nonsense, or empty list"],
    "passes_sanity": true/false
}}"""

        critic_response = self._call_critic_llm(sanity_prompt)

        try:
            json_match = re.search(r'\{.*\}', critic_response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = json.loads(critic_response)
        except Exception:
            result = {
                "hallucinations": [],
                "nonsense": [],
                "passes_sanity": None,
                "parse_error": True,
                "raw_critic_response": critic_response[:500]
            }

        # Add metadata
        result.update({
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
            "raw_output_length": len(raw_output),
            "analysis_length": len(geoff_analysis),
        })

        return result

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

    def commit_validation(self, investigation_id: str, validation_result: Dict,
                         base_path: str = "/home/claw/.openclaw/workspace/geoff-private"):
        """Commit validation result to git for reproducibility"""

        validation_dir = Path(base_path) / "validations"
        validation_dir.mkdir(exist_ok=True)

        validation_file = validation_dir / f"{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(validation_file, 'w') as f:
            json.dump(validation_result, f, indent=2)

        # Git commit
        try:
            subprocess.run(['git', 'config', 'user.email'], cwd=base_path,
                         capture_output=True, check=True)
        except Exception:
            subprocess.run(['git', 'config', 'user.email', 'critic@geoff.local'],
                         cwd=base_path, capture_output=True)
            subprocess.run(['git', 'config', 'user.name', 'Geoff Critic'],
                         cwd=base_path, capture_output=True)

        try:
            subprocess.run(['git', 'add', str(validation_file)],
                         cwd=base_path, check=True, capture_output=True)

            passes = validation_result.get('passes_sanity', False)
            label = "PASS" if passes else "FAIL"
            commit_msg = f"[CRITIC-{label}] {investigation_id}: sanity check"

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
                    if val.get('passes_sanity', False):
                        passed += 1
                    else:
                        failed += 1
            except Exception:
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
    Pipeline that wraps Geoff's operations with a sanity check.
    Execute tool -> sanity check results. No double validation.
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
        Execute tool step, then sanity check results.
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

        # Sanity check the analysis if provided
        if geoff_analysis:
            print(f"[PIPELINE] Sanity checking analysis...")
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

            tool_result['critic_validation'] = validation
            tool_result['passes_sanity'] = validation.get('passes_sanity', False)

        return tool_result

    def get_reproducibility_package(self) -> Dict:
        """Generate package for another investigator to reproduce"""
        if not self.investigation_id:
            return {"error": "No active investigation"}

        summary = self.critic.get_validation_summary(self.investigation_id)

        return {
            "investigation_id": self.investigation_id,
            "reproducibility": {
                "all_steps_passed_sanity": summary['failed'] == 0,
                "sanity_check_pass_rate": summary['pass_rate'],
                "validation_count": summary['total']
            },
            "validation_summary": summary,
            "reproduction_instructions": [
                "1. Clone this git repository",
                "2. Checkout commit with investigation ID",
                "3. Review validations/ directory for step-by-step sanity checks",
                "4. Run same tool commands as logged",
                "5. Compare results against critic validations"
            ]
        }


# For direct testing
if __name__ == "__main__":
    critic = GeoffCritic()

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

    print("Sanity Check Result:")
    print(json.dumps(result, indent=2))