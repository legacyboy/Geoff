#!/usr/bin/env python3
"""
HTML Structure Analyzer for SANS HHC 2025 Terminal Page
Fetches and analyzes the terminal page HTML to find all input elements,
contenteditable divs, and their attributes.
"""

import urllib.request
import urllib.error
from html.parser import HTMLParser
from dataclasses import dataclass
from typing import List, Dict, Optional
import json


@dataclass
class Element:
    tag: str
    attrs: Dict[str, Optional[str]]
    has_contenteditable: bool = False


class HTMLAnalyzer(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inputs: List[Element] = []
        self.contenteditable_divs: List[Element] = []
        self._current_data = ""
        
    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = {k: v for k, v in attrs}
        
        # Check for input elements
        if tag == 'input':
            self.inputs.append(Element(tag=tag, attrs=attr_dict))
        
        # Check for contenteditable divs
        if tag == 'div':
            is_contenteditable = attr_dict.get('contenteditable') == 'true' or 'contenteditable' in attr_dict
            if is_contenteditable or attr_dict.get('contenteditable'):
                self.contenteditable_divs.append(Element(
                    tag=tag, 
                    attrs=attr_dict, 
                    has_contenteditable=True
                ))
    
    def print_results(self):
        print("=" * 80)
        print("SANS HHC 2025 Terminal Page HTML Analysis")
        print("=" * 80)
        
        print("\n" + "=" * 80)
        print(f"INPUT ELEMENTS FOUND: {len(self.inputs)}")
        print("=" * 80)
        for i, elem in enumerate(self.inputs, 1):
            print(f"\n[Input #{i}]")
            for attr, value in elem.attrs.items():
                print(f"  {attr}: {value if value else '(empty)'}")
        
        print("\n" + "=" * 80)
        print(f"CONTENTEDITABLE DIVS FOUND: {len(self.contenteditable_divs)}")
        print("=" * 80)
        for i, elem in enumerate(self.contenteditable_divs, 1):
            print(f"\n[Div #{i}]")
            for attr, value in elem.attrs.items():
                print(f"  {attr}: {value if value else '(empty)'}")
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total input elements: {len(self.inputs)}")
        print(f"Total contenteditable divs: {len(self.contenteditable_divs)}")


def fetch_and_analyze():
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4"
    
    print(f"Fetching URL: {url}")
    print("-" * 80)
    
    try:
        # Create request with headers to mimic a browser
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            html = response.read().decode('utf-8', errors='replace')
            
            # Save raw HTML to file for inspection
            with open('/home/claw/.openclaw/workspace/sans-challenge/page_dump.html', 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"Raw HTML saved to page_dump.html ({len(html)} bytes)")
            print(f"HTTP Status: {response.status}")
            print(f"Content-Type: {response.headers.get('Content-Type')}")
            print(f"Server Headers: {dict(response.headers)}")
            
            # Analyze HTML
            analyzer = HTMLAnalyzer()
            analyzer.feed(html)
            analyzer.print_results()
            
            # Additional analysis - look for terminal div and script src
            print("\n" + "=" * 80)
            print("ADDITIONAL ELEMENTS ANALYSIS")
            print("=" * 80)
            
            # Find all divs (not just contenteditable ones)
            import re
            div_pattern = re.compile(r'<div[^>]*>', re.IGNORECASE)
            divs = div_pattern.findall(html)
            print(f"\nAll div tags found: {len(divs)}")
            for i, div in enumerate(divs, 1):
                print(f"  [Div {i}] {div}")
            
            # Find all script tags
            script_pattern = re.compile(r'<script[^>]*>', re.IGNORECASE)
            scripts = script_pattern.findall(html)
            print(f"\nAll script tags found: {len(scripts)}")
            for i, script in enumerate(scripts, 1):
                print(f"  [Script {i}] {script}")
            
            # Find all input elements (comprehensive)
            input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
            inputs = input_pattern.findall(html)
            print(f"\nAll input tags found (regex): {len(inputs)}")
            for i, inp in enumerate(inputs, 1):
                print(f"  [Input {i}] {inp}")
            
            # Find all elements with id or class attributes
            id_pattern = re.compile(r'id="([^"]+)"', re.IGNORECASE)
            class_pattern = re.compile(r'class="([^"]+)"', re.IGNORECASE)
            
            ids = id_pattern.findall(html)
            classes = class_pattern.findall(html)
            
            print(f"\nElements with ID attribute: {len(ids)}")
            for id_val in ids:
                print(f"  - #{id_val}")
            
            print(f"\nElements with CLASS attribute: {len(classes)}")
            for class_val in classes:
                print(f"  - .{class_val}")
            
            # Save structured results to JSON
            results = {
                'url': url,
                'html_size': len(html),
                'http_status': response.status,
                'headers': dict(response.headers),
                'inputs': [
                    {'tag': e.tag, 'attrs': e.attrs} 
                    for e in analyzer.inputs
                ],
                'contenteditable_divs': [
                    {'tag': e.tag, 'attrs': e.attrs} 
                    for e in analyzer.contenteditable_divs
                ],
                'all_divs': divs,
                'all_scripts': scripts,
                'all_inputs': inputs,
                'all_ids': ids,
                'all_classes': classes
            }
            
            with open('/home/claw/.openclaw/workspace/sans-challenge/analysis_results.json', 'w') as f:
                json.dump(results, f, indent=2)
            print("\nStructured results saved to analysis_results.json")
            
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason}")
        print(f"Response body:\n{e.read().decode('utf-8', errors='replace')}")
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    fetch_and_analyze()
