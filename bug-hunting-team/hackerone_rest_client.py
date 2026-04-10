#!/usr/bin/env python3
"""
HackerOne Bug Bounty Integration - REST API Version
Personal API tokens work with REST API at api.hackerone.com
"""

import json
import os
import base64
import requests

# Config location
CONFIG_FILE = os.path.expanduser('~/.config/hackerone/config.json')

# Fallback to bug-hunting-team directory
if not os.path.exists(CONFIG_FILE):
    CONFIG_FILE = '/home/claw/.openclaw/workspace/bug-hunting-team/hackerone_config.json'

def load_config():
    """Load HackerOne API config"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return None

def save_config(config):
    """Save HackerOne API config"""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)

def setup_api_key():
    """Interactive setup for HackerOne API"""
    print("HackerOne API Setup")
    print("Get your API token from: https://hackerone.com/settings/api_token")
    print()
    
    username = input("HackerOne username: ").strip()
    api_token = input("API token: ").strip()
    
    config = {
        'username': username,
        'api_token': api_token,
        'endpoint': 'https://api.hackerone.com/v1'
    }
    
    save_config(config)
    print(f"Saved to {CONFIG_FILE}")
    return config

class HackerOneClient:
    """HackerOne REST API Client"""
    
    def __init__(self, config=None):
        if config is None:
            config = load_config()
        if config is None:
            raise ValueError("No config found. Run setup first.")
        
        self.username = config['username']
        self.api_token = config['api_token']
        self.endpoint = config.get('endpoint', 'https://api.hackerone.com/v1')
        
    def _auth(self):
        """Generate Basic Auth header"""
        credentials = f"{self.username}:{self.api_token}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
    
    def _request(self, method, path, **kwargs):
        """Make authenticated request to HackerOne API"""
        url = f"{self.endpoint}{path}"
        headers = {
            'Authorization': self._auth(),
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        response = requests.request(method, url, headers=headers, **kwargs)
        
        if response.status_code == 401:
            raise Exception("Authentication failed - check your API token")
        elif response.status_code == 403:
            raise Exception("Access forbidden - you may not have permission")
        elif response.status_code == 404:
            raise Exception(f"Not found: {path}")
        elif response.status_code >= 400:
            raise Exception(f"API error {response.status_code}: {response.text}")
        
        return response.json() if response.text else {}
    
    def get_me(self):
        """Get current user info"""
        return self._request('GET', '/me')
    
    def get_programs(self):
        """Get programs you have access to"""
        # Note: Personal API tokens have limited access to program data
        # You typically need to know the program handle
        return self._request('GET', '/programs')
    
    def get_program(self, handle):
        """Get specific program details"""
        return self._request('GET', f'/programs/{handle}')
    
    def get_scope(self, handle):
        """Get program scope/targets"""
        return self._request('GET', f'/programs/{handle}/structured_scopes')
    
    def get_reports(self, state=None):
        """Get your reports"""
        params = {}
        if state:
            params['filter[state]'] = state
        return self._request('GET', '/reports', params=params)
    
    def get_report(self, report_id):
        """Get specific report details"""
        return self._request('GET', f'/reports/{report_id}')
    
    def submit_report(self, program_handle, title, vulnerability_information, 
                      severity_rating='low', impact=None):
        """Submit a vulnerability report"""
        data = {
            'data': {
                'type': 'report',
                'attributes': {
                    'title': title,
                    'vulnerability_information': vulnerability_information,
                    'severity_rating': severity_rating
                }
            }
        }
        
        if impact:
            data['data']['attributes']['impact'] = impact
        
        return self._request('POST', f'/programs/{program_handle}/reports', json=data)

class VulnerabilityReporter:
    """Helper for formatting and submitting reports"""
    
    def __init__(self, client):
        self.client = client
    
    def format_chrome_vrp_report(self, bug_type, affected_component, 
                                  description, root_cause, poc, impact):
        """Format report for Chrome VRP"""
        
        report = f"""## Bug Type
{bug_type}

## Affected Component
{affected_component}

## Description
{description}

## Root Cause Analysis
{root_cause}

## Proof of Concept
```javascript
{poc}
```

## Impact
{impact}

## Suggested Fix
[To be discussed with Chrome security team]

## References
- Chromium source code analysis
- Related CVEs or previous bugs
"""
        return report
    
    def submit_to_chrome(self, title, report_body, severity='high'):
        """Submit to Google Chrome VRP"""
        # Chrome VRP handle is "chrome"
        try:
            result = self.client.submit_report(
                program_handle='google',
                title=title,
                vulnerability_information=report_body,
                severity_rating=severity
            )
            return result
        except Exception as e:
            print(f"Chrome submission failed: {e}")
            print("Note: Chrome VRP may require special access or use a different submission method")
            return None
    
    def submit_to_mozilla(self, title, report_body, severity='high'):
        """Submit to Mozilla"""
        try:
            result = self.client.submit_report(
                program_handle='mozilla',
                title=title,
                vulnerability_information=report_body,
                severity_rating=severity
            )
            return result
        except Exception as e:
            print(f"Mozilla submission failed: {e}")
            return None

def list_bug_bounty_programs():
    """List popular bug bounty programs to target"""
    programs = [
        {"handle": "google", "name": "Google VRP", "scope": "All Google products", "bounties": "Up to $151,515"},
        {"handle": "chrome", "name": "Chrome VRP", "scope": "Chrome browser, V8, PDF", "bounties": "Up to $250,000"},
        {"handle": "mozilla", "name": "Mozilla", "scope": "Firefox, Thunderbird", "bounties": "Up to $10,000"},
        {"handle": "internet", "name": "Internet Bug Bounty", "scope": "Core internet infrastructure", "bounties": "Varies"},
        {"handle": "nodejs", "name": "Node.js", "scope": "Node.js runtime", "bounties": "Up to $2,500"},
    ]
    return programs

# CLI interface
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("HackerOne Bug Bounty Client")
        print()
        print("Usage: python3 hackerone_rest_client.py <command>")
        print()
        print("Setup:")
        print("  setup                    - Configure API credentials")
        print()
        print("Information:")
        print("  me                       - Show your profile")
        print("  programs                 - List programs you have access to")
        print("  scope <handle>            - Get program scope")
        print("  reports [state]          - List your reports")
        print()
        print("Targets (for fabht/claude):")
        print("  targets                  - Show popular bug bounty programs")
        print()
        print("Submit (after finding bugs):")
        print("  submit <handle> <file>  - Submit report from file")
        print()
        print("Examples:")
        print("  python3 hackerone_rest_client.py setup")
        print("  python3 hackerone_rest_client.py targets")
        print("  python3 hackerone_rest_client.py scope google")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == 'setup':
        setup_api_key()
    
    elif cmd == 'targets':
        print("Popular Bug Bounty Programs:\n")
        for p in list_bug_bounty_programs():
            print(f"  {p['handle']}")
            print(f"    Name:    {p['name']}")
            print(f"    Scope:   {p['scope']}")
            print(f"    Rewards: {p['bounties']}")
            print()
        print("\nFor Chrome VRP, check: https://bughunters.google.com/")
    
    elif cmd == 'me':
        try:
            client = HackerOneClient()
            me = client.get_me()
            data = me.get('data', {}).get('attributes', {})
            print(f"Username: {data.get('username')}")
            print(f"Name: {data.get('name')}")
            print(f"Email: {data.get('email')}")
            print(f"Reputation: {data.get('reputation', 'N/A')}")
        except Exception as e:
            print(f"Error: {e}")
    
    elif cmd == 'programs':
        try:
            client = HackerOneClient()
            result = client.get_programs()
            programs = result.get('data', [])
            print(f"Found {len(programs)} programs:\n")
            for p in programs:
                attrs = p.get('attributes', {})
                print(f"  {attrs.get('handle')}")
                print(f"    Name: {attrs.get('name')}")
                print(f"    URL: {attrs.get('url')}")
                print()
        except Exception as e:
            print(f"Error: {e}")
    
    elif cmd == 'scope' and len(sys.argv) > 2:
        try:
            client = HackerOneClient()
            result = client.get_scope(sys.argv[2])
            scopes = result.get('data', [])
            print(f"Scope for {sys.argv[2]}:\n")
            for s in scopes:
                attrs = s.get('attributes', {})
                bounty = "💰" if attrs.get('eligible_for_bounty') else ""
                print(f"  [{attrs.get('asset_type')}] {attrs.get('asset_identifier')} {bounty}")
        except Exception as e:
            print(f"Error: {e}")
    
    elif cmd == 'reports':
        try:
            client = HackerOneClient()
            state = sys.argv[2] if len(sys.argv) > 2 else None
            result = client.get_reports(state=state)
            reports = result.get('data', [])
            print(f"Found {len(reports)} reports:\n")
            for r in reports:
                attrs = r.get('attributes', {})
                print(f"  #{r.get('id')}: {attrs.get('title')}")
                print(f"    State: {attrs.get('state')}")
                print()
        except Exception as e:
            print(f"Error: {e}")
    
    else:
        print(f"Unknown command: {cmd}")
