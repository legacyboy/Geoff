#!/usr/bin/env python3
import subprocess
from pathlib import Path

# Spawn the researcher agent as a subagent
def spawn_researcher(symbols, research_type='comprehensive', output_format='json'):
    script_path = Path(__file__).parent / 'researcher_agent.py'
    command = [str(script_path), '--symbols', symbols, '--type', research_type, '--output_format', output_format]
    result = subprocess.run(command, capture_output=True, text=True)
    return result

def main():
    symbols = input('Enter stock/crypto symbols (comma-separated): ')
    research_type = input('Research type [news/technical/sentiment/comprehensive]: ') or 'comprehensive'
    output_format = input('Output format [json/markdown/summary]: ') or 'json'
    result = spawn_researcher(symbols, research_type=research_type, output_format=output_format)
    print(result.stdout)

if __name__ == '__main__':
    main()