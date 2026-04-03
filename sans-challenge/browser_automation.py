#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - Browser Automation
Uses pyppeteer to solve termOrientation challenge
"""

import asyncio
from pyppeteer import launch
import sys

async def solve_term_orientation():
    """Solve termOrientation via real browser automation"""
    
    print("="*60)
    print("SANS Holiday Hack Challenge 2025 - Browser Automation")
    print("Solving: termOrientation")
    print("="*60 + "\n")
    
    # Terminal URL
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=64f0bad9-9940-40d4-aead-4065d3575189&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    print("[*] Launching headless browser...")
    
    try:
        browser = await launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        
        page = await browser.newPage()
        
        # Set viewport
        await page.setViewport({'width': 1280, 'height': 800})
        
        print(f"[*] Navigating to challenge...")
        await page.goto(url, {'waitUntil': 'networkidle2', 'timeout': 30000})
        
        print("[+] Page loaded")
        
        # Wait for terminal to initialize
        print("[*] Waiting for terminal to load...")
        await asyncio.sleep(5)
        
        # Try to find the challenge input field
        print("[*] Looking for challenge input field...")
        
        # The challenge has an input field in the upper pane
        # Try multiple selectors
        selectors = [
            'input[type="text"]',
            'input',
            '[contenteditable]',
            '.xterm-helper-textarea',
            'textarea',
        ]
        
        input_field = None
        for selector in selectors:
            try:
                element = await page.querySelector(selector)
                if element:
                    print(f"[+] Found input element: {selector}")
                    input_field = element
                    break
            except:
                continue
        
        if input_field:
            print("[*] Typing 'answer'...")
            await input_field.type('answer')
            await asyncio.sleep(1)
            
            print("[*] Pressing Enter...")
            await page.keyboard.press('Enter')
            await asyncio.sleep(3)
            
            # Check for success message
            print("[*] Checking for success...")
            content = await page.content()
            
            if 'congratulations' in content.lower() or 'correct' in content.lower() or 'complete' in content.lower():
                print("[✓] CHALLENGE SOLVED!")
            else:
                print("[!] Success not detected in page content")
                # Take screenshot for debugging
                await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_result.png'})
                print("[*] Screenshot saved")
        else:
            print("[!] Could not find input field")
            # Try alternative: focus on page and type
            print("[*] Trying alternative: focus and type...")
            await page.focus('body')
            await page.keyboard.type('answer')
            await asyncio.sleep(1)
            await page.keyboard.press('Enter')
            await asyncio.sleep(3)
            
            content = await page.content()
            if 'congratulations' in content.lower():
                print("[✓] CHALLENGE SOLVED!")
            else:
                print("[!] Still no success")
                await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_debug.png'})
        
        await browser.close()
        print("[+] Browser closed")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    asyncio.run(solve_term_orientation())
