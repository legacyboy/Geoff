#!/usr/bin/env python3
"""
HackerOne Bug Bounty Integration
Fetch programs, submit reports, track bounties
"""

import json
import os
import requests

# Config location
CONFIG_FILE = os.path.expanduser('~/.config/hackerone/config.json')

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
    print("Get your API key from: https://hackerone.com/settings/api")
    print()
    
    username = input("HackerOne username: ").strip()
    api_key = input("API key (starts with xxxxxxxx-xxxx-xxxx): ").strip()
    
    config = {
        'username': username,
        'api_key': api_key,
        'endpoint': 'https://hackerone.com/graphql'
    }
    
    save_config(config)
    print(f"Saved to {CONFIG_FILE}")
    return config

class HackerOneClient:
    def __init__(self, config=None):
        if config is None:
            config = load_config()
        if config is None:
            raise ValueError("No config found. Run setup_api_key() first.")
        
        self.username = config['username']
        self.api_key = config['api_key']
        self.endpoint = config.get('endpoint', 'https://hackerone.com/graphql')
        
    def graphql_query(self, query, variables=None):
        """Execute GraphQL query against HackerOne API"""
        # HackerOne uses Basic auth with username as identifier
        import base64
        credentials = base64.b64encode(f"{self.username}:{self.api_key}".encode()).decode()
        headers = {
            'Authorization': f'Basic {credentials}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        response = requests.post(
            self.endpoint,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code != 200:
            raise Exception(f"API error: {response.status_code} - {response.text}")
        
        return response.json()
    
    def get_programs(self):
        """Get programs you have access to"""
        query = '''
        query {
            me {
                programs(first: 100) {
                    edges {
                        node {
                            id
                            handle
                            name
                            url
                            submission_state
                            offers_bounties
                            currency
                        }
                    }
                }
            }
        }
        '''
        result = self.graphql_query(query)
        return result.get('data', {}).get('me', {}).get('programs', {}).get('edges', [])
    
    def get_program_scope(self, handle):
        """Get scope/targets for a specific program"""
        query = f'''
        query {{
            team(handle: "{handle}") {{
                id
                handle
                name
                submission_state
                structured_scopes(first: 100) {{
                    edges {{
                        node {{
                            id
                            asset_type
                            asset_identifier
                            eligible_for_bounty
                            eligible_for_submission
                        }}
                    }}
                }}
            }}
        }}
        '''
        return self.graphql_query(query)
    
    def submit_report(self, program_handle, title, description, severity='low', impact=''):
        """Submit a vulnerability report"""
        # Note: This is a simplified version
        # Real submission requires more fields and markdown formatting
        
        mutation = '''
        mutation CreateReport($input: CreateReportInput!) {
            createReport(input: $input) {
                report {
                    id
                    databaseId
                    url
                    title
                    state
                }
                errors {
                    message
                    field
                }
            }
        }
        '''
        
        variables = {
            'input': {
                'team_handle': program_handle,
                'title': title,
                'vulnerability_information': description,
                'severity_rating': severity,
                'impact': impact
            }
        }
        
        return self.graphql_query(mutation, variables)
    
    def get_my_reports(self, state=None):
        """Get your submitted reports"""
        query = '''
        query {
            me {
                reports(first: 100) {
                    edges {
                        node {
                            id
                            databaseId
                            title
                            state
                            substate
                            created_at
                            team {
                                handle
                                name
                            }
                            bounties {
                                amount
                                currency
                            }
                        }
                    }
                }
            }
        }
        '''
        result = self.graphql_query(query)
        return result.get('data', {}).get('me', {}).get('reports', {}).get('edges', [])

class VulnerabilityReporter:
    """Helper class to format and submit vulnerability reports"""
    
    def __init__(self, client):
        self.client = client
    
    def format_vulnerability_report(self, title, vuln_type, affected_urls, description, 
                                       steps_to_reproduce, impact, poc_code=''):
        """Format a professional vulnerability report"""
        
        report = f"""# {title}

## Summary
{vuln_type} vulnerability discovered in the affected system.

## Affected Targets
{affected_urls}

## Description
{description}

## Steps to Reproduce
{steps_to_reproduce}

## Impact
{impact}

## Proof of Concept
"""
        if poc_code:
            report += f"```\n{poc_code}\n```\n"
        
        report += """
## Remediation
[To be added after discussion with security team]

## References
- [Relevant CVE or security advisory]
- [Research paper or blog post]
"""
        return report
    
    def submit_to_chrome_vrp(self, title, description, severity):
        """Submit to Google Chrome VRP via HackerOne"""
        # Chrome VRP is handle: "chrome"
        return self.client.submit_report(
            program_handle='chrome',
            title=title,
            description=description,
            severity=severity
        )
    
    def submit_to_mozilla(self, title, description, severity):
        """Submit to Mozilla via HackerOne"""
        # Mozilla is handle: "mozilla"
        return self.client.submit_report(
            program_handle='mozilla',
            title=title,
            description=description,
            severity=severity
        )

# CLI interface
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 hackerone_client.py <command>")
        print()
        print("Commands:")
        print("  setup       - Configure API credentials")
        print("  programs    - List available programs")
        print("  scope <handle> - Get program scope/targets")
        print("  reports     - List your reports")
        print()
        print("For bug hunting workflow:")
        print("  1. Run setup to save credentials")
        print("  2. Run programs to see what you can hack")
        print("  3. Use fabht/claude to find bugs")
        print("  4. Submit via API")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == 'setup':
        setup_api_key()
    
    elif cmd == 'programs':
        client = HackerOneClient()
        programs = client.get_programs()
        print(f"Found {len(programs)} programs:\n")
        for p in programs:
            node = p['node']
            bounty = "💰" if node.get('offers_bounties') else ""
            print(f"  {node['handle']} - {node['name']} {bounty}")
            print(f"    State: {node['submission_state']}")
            print(f"    URL: {node['url']}")
            print()
    
    elif cmd == 'scope' and len(sys.argv) > 2:
        client = HackerOneClient()
        result = client.get_program_scope(sys.argv[2])
        team = result.get('data', {}).get('team', {})
        print(f"Program: {team.get('name')}")
        print(f"Handle: {team.get('handle')}")
        print(f"Submission: {team.get('submission_state')}")
        print()
        print("Scope:")
        scopes = team.get('structured_scopes', {}).get('edges', [])
        for s in scopes:
            node = s['node']
            bounty = "💰 bounty" if node.get('eligible_for_bounty') else ""
            print(f"  [{node['asset_type']}] {node['asset_identifier']} {bounty}")
    
    elif cmd == 'reports':
        client = HackerOneClient()
        reports = client.get_my_reports()
        print(f"Found {len(reports)} reports:\n")
        for r in reports:
            node = r['node']
            bounty = f" - ${node['bounties'][0]['amount']}" if node.get('bounties') else ""
            print(f"  #{node['databaseId']}: {node['title']}")
            print(f"    State: {node['state']} ({node['substate']}){bounty}")
            print(f"    Program: {node['team']['handle']}")
            print()
    
    else:
        print(f"Unknown command: {cmd}")
