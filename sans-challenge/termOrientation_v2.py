#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - TermOrientation Challenge Solver V2
Handles multiple input fields and waits for completion confirmation
"""

import asyncio
from pyppeteer import launch
import sys

async def solve_term_orientation():
    """Solve termOrientation properly - handle multiple input areas"""
    
    print("="*60)
    print("SANS HHC 2025 - TermOrientation Solver V2")
    print("="*60 + "\n")
    
    # Updated URL with new session ID
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    print("[*] Launching browser...")
    
    try:
        browser = await launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        
        page = await browser.newPage()
        await page.setViewport({'width': 1280, 'height': 800})
        
        print(f"[*] Navigating to challenge...")
        await page.goto(url, {'waitUntil': 'networkidle2', 'timeout': 30000})
        
        print("[+] Page loaded")
        
        # Wait for terminal to fully initialize
        print("[*] Waiting for terminal initialization (10 seconds)...")
        await asyncio.sleep(10)
        
        # Take initial screenshot to see the layout
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_initial.png'})
        print("[*] Initial screenshot saved")
        
        # Try to find ALL input elements (there may be multiple)
        print("[*] Searching for all input elements...")
        
        input_elements = await page.querySelectorAll('input, textarea, [contenteditable], .xterm-helper-textarea')
        print(f"[+] Found {len(input_elements)} input elements")
        
        # Try each input element
        for i, element in enumerate(input_elements):
            try:
                print(f"\n[*] Trying input element {i+1}/{len(input_elements)}...")
                
                # Focus the element
                await element.focus()
                await asyncio.sleep(1)
                
                # Clear any existing content
                await element.evaluate('el => el.value = ""')
                await asyncio.sleep(0.5)
                
                # Type answer
                print(f"  [*] Typing 'answer'...")
                await element.type('answer')
                await asyncio.sleep(1)
                
                # Try pressing Enter
                print(f"  [*] Pressing Enter...")
                await page.keyboard.press('Enter')
                await asyncio.sleep(3)
                
                # Check for completion
                content = await page.content()
                if any(word in content.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge', 'award']):
                    print(f"  [✓] SUCCESS with element {i+1}!")
                    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_success.png'})
                    break
                else:
                    print(f"  [!] No success yet with element {i+1}")
                    
            except Exception as e:
                print(f"  [!] Error with element {i+1}: {e}")
                continue
        
        # Alternative: Try clicking on specific coordinates where input might be
        print("\n[*] Trying coordinate-based approach...")
        
        # The challenge might have a custom input area
        # Try clicking at top-center of the page (where "Enter answer here" usually is)
        await page.mouse.click(640, 100)  # Top center area
        await asyncio.sleep(1)
        await page.keyboard.type('answer')
        await asyncio.sleep(1)
        await page.keyboard.press('Enter')
        await asyncio.sleep(3)
        
        # Check again for success
        content = await page.content()
        if any(word in content.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge', 'award']):
            print("[✓] SUCCESS with coordinate approach!")
        else:
            print("[!] Still no success confirmation")
        
        # Final screenshot
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_final.png'})
        print("[*] Final screenshot saved")
        
        # Check page for any completion indicators
        print("\n[*] Checking for completion indicators...")
        
        # Look for badge/award elements
        badges = await page.querySelectorAll('.badge, .award, .completed, .success, [class*="complete"], [class*="success"]')
        print(f"[+] Found {len(badges)} potential completion elements")
        
        # Get all text content
        text_content = await page.evaluate('() => document.body.innerText')
        
        if 'congratulations' in text_content.lower():
            print("[✓] 'Congratulations' found in page text!")
        if 'completed' in text_content.lower():
            print("[✓] 'Completed' found in page text!")
        if 'success' in text_content.lower():
            print("[✓] 'Success' found in page text!")
        
        await browser.close()
        print("\n[+] Browser closed")
        
        print("\n" + "="*60)
        print("Challenge attempt completed")
        print("Check screenshots in sans-challenge/ folder")
        print("="*60)
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    asyncio.run(solve_term_orientation())
